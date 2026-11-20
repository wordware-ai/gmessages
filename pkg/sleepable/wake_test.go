package sleepable

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.mau.fi/mautrix-gmessages/pkg/libgm"
	"go.mau.fi/mautrix-gmessages/pkg/libgm/gmproto"
	"go.mau.fi/mautrix-gmessages/pkg/libgm/util"
)

// cursor0 is where the fixture state's cursor starts.
var cursor0 = time.Date(2026, time.November, 1, 12, 0, 0, 0, time.UTC).UnixMicro()

var alice = &gmproto.Participant{
	ID:              &gmproto.SmallInfo{Type: gmproto.IdentifierType_PHONE, Number: "+15550100", ParticipantID: "p-alice"},
	FullName:        "Alice Example",
	FormattedNumber: "(555) 555-0100",
	IsVisible:       true,
}

// fixtureSession is a paired Google account session made of fake identities and freshly
// generated keys. Its tachyon token has expired, so a wake has to refresh it.
func fixtureSession() *libgm.AuthData {
	session := libgm.NewAuthData()
	session.Browser = &gmproto.Device{UserID: 1, SourceID: "fixture-browser", Network: util.GoogleNetwork}
	session.Mobile = &gmproto.Device{UserID: 2, SourceID: "fixture-phone", Network: util.GoogleNetwork}
	session.TachyonAuthToken = []byte("fixture-expired-tachyon-token")
	session.TachyonExpiry = time.Now().Add(-time.Hour)
	session.TachyonTTL = (24 * time.Hour).Microseconds()
	session.SessionID = uuid.New()
	session.DestRegID = uuid.New()
	session.Cookies = map[string]string{
		"SAPISID":          "fixture-sapisid-secret",
		"SID":              "fixture-sid-secret",
		"__Secure-1PSIDTS": "fixture-psidts-secret",
	}
	return session
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type testEnv struct {
	dir     string
	key     []byte
	session *libgm.AuthData
	google  *fakeGoogle
	logs    *syncBuffer
}

func newTestEnv(t *testing.T) *testEnv {
	root := t.TempDir()
	keyPath := filepath.Join(root, "state.key")
	require.NoError(t, os.WriteFile(keyPath, randomBytes(32), 0o600))
	env := &testEnv{dir: filepath.Join(root, "state"), session: fixtureSession(), logs: &syncBuffer{}}
	var err error
	env.key, err = LoadKey(keyPath, env.dir)
	require.NoError(t, err)
	env.google = newFakeGoogle(env.session)
	store, err := Open(env.dir, env.key)
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.Save(&State{Session: env.session, Cursor: Cursor{Timestamp: cursor0}}))
	t.Cleanup(func() {
		env.google.get(func(f *fakeGoogle) {
			assert.Empty(t, f.unexpected, "unexpected requests to the fake Google server")
		})
		env.assertNoSecrets(t, env.logs.String(), "logs")
	})
	return env
}

func (e *testEnv) options(allowSend bool) Options {
	return Options{
		AllowSend:    allowSend,
		HTTPSettings: e.google.httpSettings(),
		ReadyTimeout: 15 * time.Second,
		Logger:       zerolog.New(e.logs).Level(zerolog.DebugLevel),
	}
}

func (e *testEnv) wakeErr(ctx context.Context, t *testing.T, allowSend bool) (*Result, error) {
	store, err := Open(e.dir, e.key)
	require.NoError(t, err)
	defer store.Close()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return Wake(ctx, store, e.options(allowSend))
}

func (e *testEnv) wake(t *testing.T, allowSend bool) *Result {
	res, err := e.wakeErr(context.Background(), t, allowSend)
	require.NoError(t, err)
	return res
}

func (e *testEnv) load(t *testing.T) *State {
	store, err := Open(e.dir, e.key)
	require.NoError(t, err)
	defer store.Close()
	st, err := store.Load()
	require.NoError(t, err)
	return st
}

func (e *testEnv) stateBytes(t *testing.T) []byte {
	data, err := os.ReadFile(filepath.Join(e.dir, stateFileName))
	require.NoError(t, err)
	return data
}

// assertNoSecrets checks that none of the fixture's credentials appear in text, in any of
// the encodings a log line or error could plausibly use.
func (e *testEnv) assertNoSecrets(t *testing.T, text, where string) {
	secrets := [][]byte{
		e.session.TachyonAuthToken, e.google.newToken, []byte(rotatedCookie),
		e.session.RequestCrypto.AESKey, e.session.RequestCrypto.HMACKey, e.session.RefreshKey.D,
	}
	for _, value := range e.session.Cookies {
		secrets = append(secrets, []byte(value))
	}
	for _, secret := range secrets {
		for _, encoded := range []string{
			string(secret), base64.StdEncoding.EncodeToString(secret),
			base64.RawURLEncoding.EncodeToString(secret), hex.EncodeToString(secret),
		} {
			assert.NotContains(t, text, encoded, "secret leaked into %s", where)
		}
	}
}

func randomBytes(n int) []byte {
	data := make([]byte, n)
	_, _ = rand.Read(data)
	return data
}

func messageIDs(msgs []Message) (ids []string) {
	for _, msg := range msgs {
		ids = append(ids, msg.ID)
	}
	return
}

func TestWakeDrainsSinceCursorAndAdvances(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)
	env.google.addConversation("conv-a", "Alice", alice)
	env.google.addConversation("conv-b", "Bob")
	env.google.addMessage("conv-a", "a-old", "p-alice", cursor0-10, "before the cursor")
	env.google.addMessage("conv-b", "b-old", "p-bob", cursor0-5, "also before the cursor")
	env.google.addMessage("conv-a", "a-1", "p-alice", cursor0+5, "hello")
	env.google.addMessage("conv-a", "a-2", "p-alice", cursor0+7, "are you there?")

	res := env.wake(t, false)
	assert.Equal(t, &Result{Drained: 2, LastSeq: 2, CursorTimestamp: cursor0 + 7}, res)
	inbox, err := ReadInbox(env.dir, 0)
	require.NoError(t, err)
	assert.Equal(t, []Message{{
		Seq: 1, ID: "a-1", ConversationID: "conv-a", ConversationName: "Alice", Timestamp: cursor0 + 5,
		Status: "INCOMING_COMPLETE", SenderID: "p-alice", SenderName: "Alice Example",
		SenderNumber: "(555) 555-0100", Text: "hello",
	}, {
		Seq: 2, ID: "a-2", ConversationID: "conv-a", ConversationName: "Alice", Timestamp: cursor0 + 7,
		Status: "INCOMING_COMPLETE", SenderID: "p-alice", SenderName: "Alice Example",
		SenderNumber: "(555) 555-0100", Text: "are you there?",
	}}, inbox)

	st := env.load(t)
	assert.Equal(t, Cursor{Timestamp: cursor0 + 7, MessageIDs: []string{"a-2"}}, st.Cursor)
	// The wake resumed the saved pairing: same identities and keys, only the expired token was
	// refreshed and the cookie Google rotated was kept.
	assert.Equal(t, env.session.Browser.GetSourceID(), st.Session.Browser.GetSourceID())
	assert.Equal(t, env.session.Mobile.GetSourceID(), st.Session.Mobile.GetSourceID())
	assert.Equal(t, env.session.RequestCrypto, st.Session.RequestCrypto)
	assert.Equal(t, env.session.RefreshKey, st.Session.RefreshKey)
	assert.Equal(t, env.google.newToken, st.Session.TachyonAuthToken)
	assert.Equal(t, rotatedCookie, st.Session.Cookies["__Secure-1PSIDTS"])
	assert.Equal(t, env.session.Cookies["SAPISID"], st.Session.Cookies["SAPISID"])
	env.google.get(func(f *fakeGoogle) {
		assert.Equal(t, 1, f.refreshes)
		// conv-b had nothing past the cursor, so it wasn't fetched at all.
		assert.Equal(t, []string{"conv-a"}, f.fetchedConvs)
	})

	// The next wake only drains what arrived since, numbered after the previous batch.
	env.google.addMessage("conv-b", "b-1", "p-bob", cursor0+9, "new in b")
	res = env.wake(t, false)
	assert.Equal(t, &Result{Drained: 1, LastSeq: 3, CursorTimestamp: cursor0 + 9}, res)
	inbox, err = ReadInbox(env.dir, 2)
	require.NoError(t, err)
	assert.Equal(t, []string{"b-1"}, messageIDs(inbox))
	assert.Equal(t, int64(3), inbox[0].Seq)
	env.google.get(func(f *fakeGoogle) {
		assert.Equal(t, 1, f.refreshes, "a still valid token shouldn't be refreshed")
		assert.NotContains(t, f.actions, gmproto.ActionType_SEND_MESSAGE)
	})
}

func TestFailedWakeLeavesStateIntact(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		breakServer func(f *fakeGoogle)
		wantErr     string
	}{
		"token refresh rejected": {
			breakServer: func(f *fakeGoogle) { f.failRefresh = true },
			wantErr:     "failed to refresh auth token: unexpected http 401",
		},
		// The token is refreshed in memory before long polling fails, which must not reach disk.
		"long polling rejected": {
			breakServer: func(f *fakeGoogle) { f.failListen = true },
			wantErr:     "long polling failed: http 401 while polling",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			env := newTestEnv(t)
			env.google.addConversation("conv-a", "Alice", alice)
			env.google.addMessage("conv-a", "a-1", "p-alice", cursor0+5, "hello")
			env.google.addMessage("conv-a", "a-2", "p-alice", cursor0+7, "are you there?")
			env.google.set(tc.breakServer)
			before := env.stateBytes(t)

			res, err := env.wakeErr(context.Background(), t, true)
			require.ErrorContains(t, err, tc.wantErr)
			assert.Nil(t, res)
			env.assertNoSecrets(t, err.Error(), "the error")
			assert.Equal(t, before, env.stateBytes(t), "a failed wake rewrote the state file")
			assert.NoFileExists(t, filepath.Join(env.dir, inboxFileName))

			// The untouched state still works once the server recovers.
			env.google.set(func(f *fakeGoogle) { f.failRefresh, f.failListen = false, false })
			assert.Equal(t, 2, env.wake(t, false).Drained)
		})
	}
}

func TestReadOnlyRefusesSend(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)
	conv := env.google.addConversation("conv-a", "Alice", alice)
	env.google.addMessage("conv-a", "a-1", "p-alice", cursor0+5, "can you call me?")
	id, err := QueueReply(env.dir, Reply{ConversationID: "conv-a", Text: "calling in 5"})
	require.NoError(t, err)

	res := env.wake(t, false)
	assert.Equal(t, &ReplyResult{ID: id, Status: ReplyRefused, Error: ErrReadOnly.Error()}, res.Reply)
	assert.Equal(t, 1, res.Drained, "a refused reply doesn't stop the drain")
	assert.FileExists(t, filepath.Join(env.dir, outboxDirName, id+".json"))
	env.google.get(func(f *fakeGoogle) {
		assert.NotContains(t, f.actions, gmproto.ActionType_SEND_MESSAGE)
		assert.Empty(t, f.sent)
	})

	// With sending explicitly allowed, the next wake sends it.
	res = env.wake(t, true)
	assert.Equal(t, &ReplyResult{ID: id, Status: ReplySent}, res.Reply)
	assert.Equal(t, 0, res.Drained)
	assert.NoFileExists(t, filepath.Join(env.dir, outboxDirName, id+".json"))
	assert.FileExists(t, filepath.Join(env.dir, sentDirName, id+".json"))
	env.google.get(func(f *fakeGoogle) {
		require.Len(t, f.sent, 1)
		assert.Equal(t, "conv-a", f.sent[0].GetConversationID())
		assert.Equal(t, conv.DefaultOutgoingID, f.sent[0].GetMessagePayload().GetParticipantID())
		assert.Equal(t, "calling in 5", f.sent[0].GetMessagePayload().GetMessageInfo()[0].GetMessageContent().GetContent())
		assert.Equal(t, int32(1), f.sent[0].GetSIMPayload().GetSIMNumber())
	})

	// The outbox is empty now, so a third wake has nothing to send.
	assert.Nil(t, env.wake(t, true).Reply)
}

func TestSIGTERMFlushesSession(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)
	env.google.addConversation("conv-a", "Alice", alice)
	env.google.addMessage("conv-a", "a-1", "p-alice", cursor0+5, "hello")
	// The phone never activates the session, so the wake is still waiting for it when SIGTERM
	// lands right after the client asked for updates.
	env.google.set(func(f *fakeGoogle) { f.neverActive = true })

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	go func() {
		<-env.google.subscribed
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
	}()
	res, err := env.wakeErr(ctx, t, false)
	require.ErrorIs(t, err, ErrInterrupted)
	assert.Equal(t, &Result{Interrupted: true, CursorTimestamp: cursor0}, res)

	st := env.load(t)
	assert.Equal(t, Cursor{Timestamp: cursor0}, st.Cursor, "an interrupted drain must not move the cursor")
	assert.Equal(t, env.google.newToken, st.Session.TachyonAuthToken, "the refreshed token wasn't flushed")
	assert.Equal(t, rotatedCookie, st.Session.Cookies["__Secure-1PSIDTS"])
	inbox, err := ReadInbox(env.dir, 0)
	require.NoError(t, err)
	assert.Empty(t, inbox)
}
