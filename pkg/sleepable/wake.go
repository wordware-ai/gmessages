package sleepable

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exhttp"

	"go.mau.fi/mautrix-gmessages/pkg/libgm"
	"go.mau.fi/mautrix-gmessages/pkg/libgm/events"
	"go.mau.fi/mautrix-gmessages/pkg/libgm/gmproto"
	"go.mau.fi/mautrix-gmessages/pkg/libgm/util"
)

const (
	defaultReadyTimeout     = 45 * time.Second
	conversationsPerWake    = 50
	messagesPerPage         = 50
	maxPagesPerConversation = 10
)

var (
	// ErrInterrupted is returned when the context is cancelled (for example by SIGTERM) before
	// the drain finishes. The session was flushed to disk and the cursor was left unchanged.
	ErrInterrupted = errors.New("wake interrupted before the drain finished")
	// ErrReadOnly is the reason a queued reply is refused when sending isn't enabled.
	ErrReadOnly = errors.New("sending is disabled, the client runs read-only unless sending is explicitly allowed")
)

// Options configures a wake.
type Options struct {
	// AllowSend lets the wake send one queued reply. Without it the client is read-only and
	// queued replies stay in the outbox.
	AllowSend bool
	// HTTPSettings configures libgm's HTTP clients.
	HTTPSettings exhttp.ClientSettings
	// ReadyTimeout bounds the wait for the phone to accept this session.
	ReadyTimeout time.Duration
	Logger       zerolog.Logger
}

// Result summarizes a wake.
type Result struct {
	Drained         int          `json:"drained"`
	LastSeq         int64        `json:"last_seq"`
	CursorTimestamp int64        `json:"cursor_timestamp_us"`
	Interrupted     bool         `json:"interrupted,omitempty"`
	Reply           *ReplyResult `json:"reply,omitempty"`
}

const (
	ReplySent    = "sent"
	ReplyRefused = "refused"
	ReplyFailed  = "failed"
)

// ReplyResult is the outcome for the queued reply a wake looked at. A sent reply moves to
// sent/; a failed one moves to failed/ and is never retried automatically; a refused one
// stays queued.
type ReplyResult struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Wake reconnects with the saved session, drains the messages newer than the saved cursor
// into the inbox, sends at most one queued reply if allowed, and saves the new cursor and
// session.
//
// If the wake fails, nothing in the state directory is changed. If ctx is cancelled before
// the drain completes, the session (which may hold a refreshed token or rotated cookies) is
// saved, the cursor is not moved, and ErrInterrupted is returned.
func Wake(ctx context.Context, store *Store, opts Options) (*Result, error) {
	st, err := store.Load()
	if err != nil {
		return nil, err
	}
	if opts.ReadyTimeout <= 0 {
		opts.ReadyTimeout = defaultReadyTimeout
	}
	log := opts.Logger
	wakeCtx, fail := context.WithCancelCause(ctx)
	defer fail(nil)
	w := &waker{log: &log, ready: make(chan struct{}), fail: fail}

	cli := libgm.NewClient(st.Session, nil, log, opts.HTTPSettings)
	cli.SetEventHandler(w.handleEvent)
	// Disconnect is what stops long polling. Cancelling its context as well would only make
	// libgm report a spurious listen error and retry until then.
	if err = cli.Connect(context.WithoutCancel(wakeCtx)); err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	batch, err := w.drain(wakeCtx, cli, st.Cursor, opts.ReadyTimeout)
	if err != nil {
		cli.Disconnect()
		if ctx.Err() == nil {
			return nil, err
		}
		if err = store.Save(st); err != nil {
			return nil, fmt.Errorf("failed to save session after interruption: %w", err)
		}
		log.Info().Msg("Wake interrupted, saved session and kept the previous cursor")
		return &Result{Interrupted: true, LastSeq: st.LastSeq, CursorTimestamp: st.Cursor.Timestamp}, ErrInterrupted
	}
	res := &Result{Reply: w.sendQueuedReply(wakeCtx, cli, store.dir, opts.AllowSend)}
	cli.Disconnect()

	added, err := appendInbox(store.dir, st, batch)
	if err != nil {
		return nil, err
	}
	for _, msg := range batch {
		st.Cursor = st.Cursor.advance(msg)
	}
	if err = store.Save(st); err != nil {
		return nil, err
	}
	res.Drained = len(added)
	res.LastSeq = st.LastSeq
	res.CursorTimestamp = st.Cursor.Timestamp
	log.Info().
		Int("drained", res.Drained).
		Int64("last_seq", res.LastSeq).
		Int64("cursor_timestamp_us", res.CursorTimestamp).
		Msg("Wake finished")
	return res, nil
}

type waker struct {
	log       *zerolog.Logger
	ready     chan struct{}
	readyOnce sync.Once
	fail      context.CancelCauseFunc
}

// handleEvent runs synchronously on libgm's long polling goroutine, so it only signals.
func (w *waker) handleEvent(rawEvt any) {
	switch evt := rawEvt.(type) {
	case *gmproto.UserAlertEvent:
		if evt.GetAlertType() == gmproto.AlertType_BROWSER_ACTIVE {
			w.readyOnce.Do(func() { close(w.ready) })
		}
	case *events.ListenFatalError:
		w.fail(fmt.Errorf("long polling failed: %w", evt.Error))
	case *events.GaiaLoggedOut:
		w.fail(errors.New("the Google account was signed out of Messages, pair again"))
	case *gmproto.RevokePairData:
		w.fail(errors.New("the phone revoked this pairing, pair again"))
	}
}

// drain waits for the phone to accept the session, then fetches every message newer than the
// cursor from the conversations that changed since then.
func (w *waker) drain(ctx context.Context, cli *libgm.Client, cursor Cursor, readyTimeout time.Duration) ([]Message, error) {
	timer := time.NewTimer(readyTimeout)
	defer timer.Stop()
	select {
	case <-w.ready:
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-timer.C:
		return nil, fmt.Errorf("the phone didn't activate the session within %s", readyTimeout)
	}
	resp, err := cli.ListConversations(ctx, &gmproto.ListConversationsRequest{
		Count:  conversationsPerWake,
		Folder: gmproto.ListConversationsRequest_INBOX,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list conversations: %w", wrapCause(ctx, err))
	}
	convs := resp.GetConversations()
	if len(convs) == conversationsPerWake && convs[len(convs)-1].GetLastMessageTimestamp() > cursor.Timestamp {
		w.log.Warn().Msg("Every listed conversation has new messages, conversations past the first page are not drained")
	}
	var batch []Message
	for _, conv := range convs {
		if conv.GetLastMessageTimestamp() < cursor.Timestamp {
			continue
		}
		msgs, err := w.fetchConversation(ctx, cli, conv, cursor)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch messages: %w", wrapCause(ctx, err))
		}
		batch = append(batch, msgs...)
	}
	slices.SortFunc(batch, func(a, b Message) int {
		return cmp.Or(cmp.Compare(a.Timestamp, b.Timestamp), strings.Compare(a.ID, b.ID))
	})
	return slices.CompactFunc(batch, func(a, b Message) bool { return a.ID == b.ID }), nil
}

func (w *waker) fetchConversation(ctx context.Context, cli *libgm.Client, conv *gmproto.Conversation, cursor Cursor) ([]Message, error) {
	var out []Message
	var page *gmproto.Cursor
	for range maxPagesPerConversation {
		resp, err := cli.FetchMessages(ctx, conv.GetConversationID(), messagesPerPage, page)
		if err != nil {
			return nil, err
		}
		reachedCursor := false
		for _, msg := range resp.GetMessages() {
			if cursor.covers(msg) {
				reachedCursor = true
				continue
			}
			out = append(out, newMessage(conv, msg))
		}
		if reachedCursor || len(resp.GetMessages()) == 0 || resp.GetCursor() == nil {
			return out, nil
		}
		page = resp.GetCursor()
	}
	w.log.Warn().
		Int("max_messages", maxPagesPerConversation*messagesPerPage).
		Msg("Conversation has more new messages than one wake drains, older ones are skipped")
	return out, nil
}

func newMessage(conv *gmproto.Conversation, msg *gmproto.Message) Message {
	status := msg.GetMessageStatus().GetStatus()
	out := Message{
		ID:               msg.GetMessageID(),
		ConversationID:   conv.GetConversationID(),
		ConversationName: conv.GetName(),
		Timestamp:        msg.GetTimestamp(),
		Status:           status.String(),
		// Statuses 1-99 are outgoing and 100-199 incoming, the same split the bridge uses.
		FromMe:   (status >= 1 && status < 100) || msg.GetSenderParticipant().GetIsMe(),
		SenderID: msg.GetParticipantID(),
	}
	sender := msg.GetSenderParticipant()
	if sender == nil {
		for _, participant := range conv.GetParticipants() {
			if participant.GetID().GetParticipantID() == out.SenderID {
				sender = participant
				break
			}
		}
	}
	out.SenderName = sender.GetFullName()
	out.SenderNumber = sender.GetFormattedNumber()
	var texts []string
	for _, info := range msg.GetMessageInfo() {
		if content := info.GetMessageContent().GetContent(); content != "" {
			texts = append(texts, content)
		}
		if info.GetMediaContent() != nil {
			out.HasMedia = true
		}
	}
	out.Text = strings.Join(texts, "\n")
	return out
}

// sendQueuedReply looks at the oldest queued reply and sends it if sending is allowed. The
// reply is moved to failed/ before the request goes out and only promoted to sent/ once the
// phone accepts it, so a crash mid-send can't lead to it being sent twice.
func (w *waker) sendQueuedReply(ctx context.Context, cli *libgm.Client, dir string, allowSend bool) *ReplyResult {
	id, reply, err := nextReply(dir)
	if id == "" && err == nil {
		return nil
	}
	if err != nil {
		w.log.Err(err).Str("reply_id", id).Msg("Failed to read queued reply")
		if id != "" && moveReply(dir, id, outboxDirName, failedDirName) != nil {
			return &ReplyResult{ID: id, Status: ReplyFailed, Error: "unreadable reply could not be moved out of the outbox"}
		}
		return &ReplyResult{ID: id, Status: ReplyFailed, Error: err.Error()}
	}
	if !allowSend {
		w.log.Warn().Str("reply_id", id).Msg("Not sending queued reply, sending is disabled")
		return &ReplyResult{ID: id, Status: ReplyRefused, Error: ErrReadOnly.Error()}
	}
	if err = moveReply(dir, id, outboxDirName, failedDirName); err != nil {
		return &ReplyResult{ID: id, Status: ReplyFailed, Error: fmt.Sprintf("failed to claim reply: %v", err)}
	}
	if err = sendReply(ctx, cli, reply); err != nil {
		err = wrapCause(ctx, err)
		w.log.Err(err).Str("reply_id", id).Msg("Failed to send queued reply")
		return &ReplyResult{ID: id, Status: ReplyFailed, Error: err.Error()}
	}
	if err = moveReply(dir, id, failedDirName, sentDirName); err != nil {
		w.log.Err(err).Str("reply_id", id).Msg("Reply was sent but couldn't be moved to sent/")
	}
	w.log.Info().Str("reply_id", id).Msg("Sent queued reply")
	return &ReplyResult{ID: id, Status: ReplySent}
}

func sendReply(ctx context.Context, cli *libgm.Client, reply *Reply) error {
	conv, err := cli.GetConversation(ctx, reply.ConversationID)
	if err != nil {
		return fmt.Errorf("failed to get conversation: %w", err)
	}
	tmpID := util.GenerateTmpID()
	resp, err := cli.SendMessage(ctx, &gmproto.SendMessageRequest{
		ConversationID: reply.ConversationID,
		MessagePayload: &gmproto.MessagePayload{
			TmpID:          tmpID,
			ConversationID: reply.ConversationID,
			ParticipantID:  conv.GetDefaultOutgoingID(),
			TmpID2:         tmpID,
			MessageInfo: []*gmproto.MessageInfo{{
				Data: &gmproto.MessageInfo_MessageContent{MessageContent: &gmproto.MessageContent{Content: reply.Text}},
			}},
		},
		SIMPayload: conv.GetSimCard().GetSIMData().GetSIMPayload(),
		TmpID:      tmpID,
	})
	if err != nil {
		return err
	} else if resp.GetStatus() != gmproto.SendMessageResponse_SUCCESS {
		return fmt.Errorf("phone rejected the reply with status %s", resp.GetStatus())
	}
	return nil
}

// wrapCause swaps a plain context cancellation error for the reason the wake was cancelled,
// such as a fatal long polling error.
func wrapCause(ctx context.Context, err error) error {
	if cause := context.Cause(ctx); cause != nil && errors.Is(err, context.Canceled) {
		return cause
	}
	return err
}
