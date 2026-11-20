package sleepable

import (
	"bytes"
	"cmp"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"path"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/util/exhttp"
	"go.mau.fi/util/pblite"
	"google.golang.org/protobuf/proto"

	"go.mau.fi/mautrix-gmessages/pkg/libgm"
	"go.mau.fi/mautrix-gmessages/pkg/libgm/gmproto"
)

// fakeGoogle stands in for both Google's Messages servers and the paired phone. It is the
// HTTP transport of the libgm client under test, so every request is answered in process and
// nothing ever reaches the network. It never calls testing.T, since libgm goroutines can
// still make requests after a test has returned.
type fakeGoogle struct {
	// session is the fixture pairing; the fake phone uses its keys to encrypt responses.
	session *libgm.AuthData
	// newToken is handed out by RegisterRefresh.
	newToken []byte

	mu           sync.Mutex
	convs        []*gmproto.Conversation
	messages     map[string][]*gmproto.Message // oldest first
	actions      []gmproto.ActionType
	fetchedConvs []string
	sent         []*gmproto.SendMessageRequest
	unexpected   []string
	refreshes    int
	stream       chan []byte
	// subscribed is closed when the client first asks the phone for updates, by which time
	// libgm's long polling loop is blocked reading the stream.
	subscribed chan struct{}

	failRefresh bool // RegisterRefresh answers 401
	failListen  bool // ReceiveMessages answers 401
	neverActive bool // the phone never activates the session
}

const rotatedCookie = "rotated-fixture-psidts"

func newFakeGoogle(session *libgm.AuthData) *fakeGoogle {
	return &fakeGoogle{
		session:    session,
		newToken:   []byte("fixture-refreshed-tachyon-token"),
		messages:   make(map[string][]*gmproto.Message),
		subscribed: make(chan struct{}),
	}
}

func (f *fakeGoogle) httpSettings() exhttp.ClientSettings {
	settings := exhttp.SensibleClientSettings
	settings.TransportOverride = func(exhttp.ClientSettings) http.RoundTripper { return f }
	return settings
}

func (f *fakeGoogle) addConversation(id, name string, participants ...*gmproto.Participant) *gmproto.Conversation {
	f.mu.Lock()
	defer f.mu.Unlock()
	conv := &gmproto.Conversation{
		ConversationID:    id,
		Name:              name,
		DefaultOutgoingID: "self-" + id,
		Participants:      participants,
		SimCard: &gmproto.SIMCard{SIMData: &gmproto.SIMData{
			SIMPayload: &gmproto.SIMPayload{Two: 2, SIMNumber: 1},
		}},
	}
	f.convs = append(f.convs, conv)
	return conv
}

func (f *fakeGoogle) addMessage(convID, msgID, participantID string, ts int64, text string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.messages[convID] = append(f.messages[convID], &gmproto.Message{
		MessageID:      msgID,
		ConversationID: convID,
		Timestamp:      ts,
		ParticipantID:  participantID,
		MessageStatus:  &gmproto.MessageStatus{Status: gmproto.MessageStatusType_INCOMING_COMPLETE},
		MessageInfo: []*gmproto.MessageInfo{{
			Data: &gmproto.MessageInfo_MessageContent{MessageContent: &gmproto.MessageContent{Content: text}},
		}},
	})
	for _, conv := range f.convs {
		if conv.ConversationID == convID {
			conv.LastMessageTimestamp = max(conv.LastMessageTimestamp, ts)
		}
	}
	// The phone lists conversations by recent activity.
	slices.SortFunc(f.convs, func(a, b *gmproto.Conversation) int {
		return cmp.Compare(b.LastMessageTimestamp, a.LastMessageTimestamp)
	})
}

func (f *fakeGoogle) set(fn func(f *fakeGoogle)) {
	f.mu.Lock()
	fn(f)
	f.mu.Unlock()
}

func (f *fakeGoogle) get(fn func(f *fakeGoogle)) {
	f.mu.Lock()
	fn(f)
	f.mu.Unlock()
}

func (f *fakeGoogle) recordUnexpected(format string, args ...any) {
	f.mu.Lock()
	f.unexpected = append(f.unexpected, fmt.Sprintf(format, args...))
	f.mu.Unlock()
}

func (f *fakeGoogle) RoundTrip(req *http.Request) (*http.Response, error) {
	switch req.URL.Host {
	case "instantmessaging-pa.clients6.google.com", "instantmessaging-pa.googleapis.com":
	default:
		f.recordUnexpected("request to %s", req.URL.Redacted())
		return nil, fmt.Errorf("fake google: refusing request to %s", req.URL.Host)
	}
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		_ = req.Body.Close()
	}
	if cookie, err := req.Cookie("SAPISID"); err != nil || cookie.Value != f.session.Cookies["SAPISID"] {
		f.recordUnexpected("%s without the saved Google cookies", path.Base(req.URL.Path))
		return respond(req, http.StatusUnauthorized, nil), nil
	}
	switch path.Base(req.URL.Path) {
	case "RegisterRefresh":
		return f.registerRefresh(req, body), nil
	case "ReceiveMessages":
		return f.receiveMessages(req), nil
	case "SendMessage":
		return f.sendMessage(req, body), nil
	case "AckMessages":
		return respond(req, http.StatusOK, &gmproto.OutgoingRPCResponse{}), nil
	default:
		// Pairing endpoints land here too: a wake must never pair again.
		f.recordUnexpected("request to %s", req.URL.Path)
		return respond(req, http.StatusNotFound, nil), nil
	}
}

func respond(req *http.Request, status int, msg proto.Message) *http.Response {
	var body []byte
	if msg != nil {
		body, _ = pblite.Marshal(msg)
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": {libgm.ContentTypePBLite}},
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    req,
	}
}

func (f *fakeGoogle) registerRefresh(req *http.Request, body []byte) *http.Response {
	var refresh gmproto.RegisterRefreshRequest
	if err := pblite.Unmarshal(body, &refresh); err != nil {
		f.recordUnexpected("undecodable RegisterRefresh: %v", err)
		return respond(req, http.StatusBadRequest, nil)
	}
	pub, err := f.session.RefreshKey.GetPublicKey()
	signed := sha256.Sum256(fmt.Appendf(nil, "%s:%d", refresh.GetMessageAuth().GetRequestID(), refresh.GetUnixTimestamp()))
	if err != nil || !ecdsa.VerifyASN1(pub, signed[:], refresh.GetSignature()) ||
		refresh.GetCurrBrowserDevice().GetSourceID() != f.session.Browser.GetSourceID() {
		f.recordUnexpected("RegisterRefresh not signed with the saved refresh key")
		return respond(req, http.StatusUnauthorized, nil)
	}
	f.mu.Lock()
	f.refreshes++
	fail := f.failRefresh
	f.mu.Unlock()
	if fail {
		return respond(req, http.StatusUnauthorized, nil)
	}
	resp := respond(req, http.StatusOK, &gmproto.RegisterRefreshResponse{
		TokenData: &gmproto.TokenData{TachyonAuthToken: f.newToken, TTL: (24 * time.Hour).Microseconds()},
	})
	resp.Header.Add("Set-Cookie", "__Secure-1PSIDTS="+rotatedCookie+"; Path=/; Secure")
	return resp
}

// receiveMessages opens a long polling stream. Every payload is a separate write to a pipe,
// so libgm reads them one at a time just like from Google's chunked responses.
func (f *fakeGoogle) receiveMessages(req *http.Request) *http.Response {
	f.mu.Lock()
	fail := f.failListen
	stream := make(chan []byte, 64)
	f.stream = stream
	f.mu.Unlock()
	if fail {
		return respond(req, http.StatusUnauthorized, nil)
	}
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		if _, err := pw.Write([]byte("[[")); err != nil {
			return
		}
		for {
			select {
			case data := <-stream:
				if _, err := pw.Write(data); err != nil {
					return
				}
			case <-req.Context().Done():
				return
			}
		}
	}()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {libgm.ContentTypePBLite}},
		Body:       pr,
		Request:    req,
	}
}

func (f *fakeGoogle) sendMessage(req *http.Request, body []byte) *http.Response {
	var outgoing gmproto.OutgoingRPCMessage
	var data gmproto.OutgoingRPCData
	if err := pblite.Unmarshal(body, &outgoing); err != nil {
		f.recordUnexpected("undecodable SendMessage: %v", err)
		return respond(req, http.StatusBadRequest, nil)
	} else if err = proto.Unmarshal(outgoing.GetData().GetMessageData(), &data); err != nil {
		f.recordUnexpected("undecodable SendMessage data: %v", err)
		return respond(req, http.StatusBadRequest, nil)
	}
	var plain []byte
	if data.EncryptedProtoData != nil {
		var err error
		if plain, err = f.session.RequestCrypto.Decrypt(data.EncryptedProtoData); err != nil {
			f.recordUnexpected("%s not encrypted with the saved request keys", data.Action)
			return respond(req, http.StatusBadRequest, nil)
		}
	}
	f.mu.Lock()
	f.actions = append(f.actions, data.Action)
	neverActive := f.neverActive
	f.mu.Unlock()

	var resp proto.Message
	switch data.Action {
	case gmproto.ActionType_GET_UPDATES:
		f.mu.Lock()
		select {
		case <-f.subscribed:
		default:
			close(f.subscribed)
		}
		f.mu.Unlock()
		if !neverActive {
			f.push(uuid.NewString(), data.Action, &gmproto.UpdateEvents{
				Event: &gmproto.UpdateEvents_UserAlertEvent{UserAlertEvent: &gmproto.UserAlertEvent{
					AlertType: gmproto.AlertType_BROWSER_ACTIVE,
				}},
			})
		}
	case gmproto.ActionType_LIST_CONVERSATIONS:
		f.mu.Lock()
		resp = &gmproto.ListConversationsResponse{Conversations: f.convs}
		f.mu.Unlock()
	case gmproto.ActionType_LIST_MESSAGES:
		var list gmproto.ListMessagesRequest
		_ = proto.Unmarshal(plain, &list)
		resp = f.listMessages(&list)
	case gmproto.ActionType_GET_CONVERSATION:
		var get gmproto.GetConversationRequest
		_ = proto.Unmarshal(plain, &get)
		f.mu.Lock()
		idx := slices.IndexFunc(f.convs, func(c *gmproto.Conversation) bool { return c.ConversationID == get.ConversationID })
		getResp := &gmproto.GetConversationResponse{}
		if idx >= 0 {
			getResp.Conversation = f.convs[idx]
		}
		f.mu.Unlock()
		resp = getResp
	case gmproto.ActionType_SEND_MESSAGE:
		var send gmproto.SendMessageRequest
		_ = proto.Unmarshal(plain, &send)
		f.mu.Lock()
		f.sent = append(f.sent, &send)
		f.mu.Unlock()
		resp = &gmproto.SendMessageResponse{Status: gmproto.SendMessageResponse_SUCCESS}
	case gmproto.ActionType_IS_BUGLE_DEFAULT:
		resp = &gmproto.IsBugleDefaultResponse{Success: true}
	case gmproto.ActionType_NOTIFY_DITTO_ACTIVITY:
		resp = &gmproto.NotifyDittoActivityResponse{}
	}
	if resp != nil {
		f.push(data.RequestID, data.Action, resp)
	}
	return respond(req, http.StatusOK, &gmproto.OutgoingRPCResponse{})
}

// listMessages pages through a conversation newest first, like the phone does.
func (f *fakeGoogle) listMessages(req *gmproto.ListMessagesRequest) *gmproto.ListMessagesResponse {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetchedConvs = append(f.fetchedConvs, req.ConversationID)
	msgs := f.messages[req.ConversationID]
	end := len(msgs)
	if req.Cursor != nil {
		end = slices.IndexFunc(msgs, func(m *gmproto.Message) bool { return m.MessageID == req.Cursor.LastItemID })
	}
	start := max(0, end-int(req.Count))
	page := slices.Clone(msgs[start:end])
	slices.Reverse(page)
	resp := &gmproto.ListMessagesResponse{Messages: page, TotalMessages: int64(len(msgs))}
	if start > 0 {
		resp.Cursor = &gmproto.Cursor{LastItemID: msgs[start].MessageID, LastItemTimestamp: msgs[start].Timestamp}
	}
	return resp
}

// push delivers an encrypted payload from the phone over the open long polling stream.
func (f *fakeGoogle) push(requestID string, action gmproto.ActionType, msg proto.Message) {
	plain, _ := proto.Marshal(msg)
	encrypted, _ := f.session.RequestCrypto.Encrypt(plain)
	messageData, _ := proto.Marshal(&gmproto.RPCMessageData{
		SessionID:     requestID,
		Action:        action,
		EncryptedData: encrypted,
	})
	payload, _ := pblite.Marshal(&gmproto.LongPollingPayload{Data: &gmproto.IncomingRPCMessage{
		ResponseID:  uuid.NewString(),
		BugleRoute:  gmproto.BugleRoute_DataEvent,
		MessageData: messageData,
	}})
	f.mu.Lock()
	stream := f.stream
	f.mu.Unlock()
	select {
	case stream <- append([]byte(","), payload...):
	default:
		f.recordUnexpected("long polling stream full or closed, dropped %s", action)
	}
}
