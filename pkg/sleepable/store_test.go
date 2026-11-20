package sleepable

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStateIsEncryptedAtRest(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)
	sealed := env.stateBytes(t)
	env.assertNoSecrets(t, string(sealed), "the state file")
	for _, field := range []string{"cookies", "SAPISID", "tachyon", "request_crypto", "fixture-browser"} {
		assert.NotContains(t, string(sealed), field)
	}
	info, err := os.Stat(filepath.Join(env.dir, stateFileName))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	info, err = os.Stat(env.dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())

	st := env.load(t)
	assert.Equal(t, env.session.Cookies, st.Session.Cookies)
	assert.Equal(t, env.session.RequestCrypto, st.Session.RequestCrypto)

	otherKey := randomBytes(32)
	store, err := Open(env.dir, otherKey)
	require.NoError(t, err)
	_, err = store.Load()
	assert.ErrorIs(t, err, ErrWrongKey)
	require.NoError(t, store.Close())

	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 1
	require.NoError(t, os.WriteFile(filepath.Join(env.dir, stateFileName), tampered, 0o600))
	store, err = Open(env.dir, env.key)
	require.NoError(t, err)
	defer store.Close()
	_, err = store.Load()
	assert.ErrorIs(t, err, ErrWrongKey)
}

func TestLoadKeyRejectsUnsafeKeyFiles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	require.NoError(t, os.Mkdir(stateDir, 0o700))
	write := func(name string, data []byte, mode os.FileMode) string {
		path := filepath.Join(root, name)
		require.NoError(t, os.WriteFile(path, data, mode))
		require.NoError(t, os.Chmod(path, mode))
		return path
	}

	good := write("good.key", randomBytes(32), 0o400)
	key, err := LoadKey(good, stateDir)
	require.NoError(t, err)
	assert.Len(t, key, 32)

	_, err = LoadKey(write("shared.key", randomBytes(32), 0o644), stateDir)
	assert.ErrorContains(t, err, "accessible by group or others")
	_, err = LoadKey(write("short.key", randomBytes(16), 0o600), stateDir)
	assert.ErrorContains(t, err, "at least 32 bytes")
	_, err = LoadKey(write("state/inside.key", randomBytes(32), 0o600), stateDir)
	assert.ErrorContains(t, err, "inside the state directory")
}

func TestOpenLocksStateDirectory(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t)
	store, err := Open(env.dir, env.key)
	require.NoError(t, err)
	_, err = Open(env.dir, env.key)
	assert.ErrorIs(t, err, ErrLocked)
	require.NoError(t, store.Close())
	store, err = Open(env.dir, env.key)
	require.NoError(t, err)
	require.NoError(t, store.Close())
}

// A wake that wrote the inbox but died before saving its state must not hand out the same
// sequence numbers or messages again.
func TestInboxKeepsLinesFromUnsavedWake(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	saved := &State{}
	crashed := *saved
	_, err := appendInbox(dir, &crashed, []Message{{ID: "a-1", Timestamp: 5}, {ID: "a-2", Timestamp: 7}})
	require.NoError(t, err)
	// It also left half a line behind.
	f, err := os.OpenFile(filepath.Join(dir, inboxFileName), os.O_APPEND|os.O_WRONLY, 0)
	require.NoError(t, err)
	_, err = f.WriteString(`{"seq":3,"id":"a-`)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	retry := *saved
	added, err := appendInbox(dir, &retry, []Message{{ID: "a-1", Timestamp: 5}, {ID: "b-1", Timestamp: 6}, {ID: "a-2", Timestamp: 7}})
	require.NoError(t, err)
	assert.Equal(t, []Message{{Seq: 3, ID: "b-1", Timestamp: 6}}, added)
	assert.Equal(t, int64(3), retry.LastSeq)

	msgs, err := ReadInbox(dir, 0)
	require.NoError(t, err)
	assert.Equal(t, []string{"a-1", "a-2", "b-1"}, messageIDs(msgs))
	msgs, err = ReadInbox(dir, 2)
	require.NoError(t, err)
	assert.Equal(t, []string{"b-1"}, messageIDs(msgs))
}
