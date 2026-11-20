// Package sleepable runs libgm as a client that is off most of the time: each wake reconnects
// with the saved pairing, drains new messages into a local inbox, optionally sends one queued
// reply, saves its cursor and exits.
package sleepable

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"go.mau.fi/mautrix-gmessages/pkg/libgm"
	"go.mau.fi/mautrix-gmessages/pkg/libgm/gmproto"
)

const (
	stateFileName = "state.enc"
	lockFileName  = "wake.lock"
	inboxFileName = "inbox.jsonl"
	outboxDirName = "outbox"
	sentDirName   = "sent"
	failedDirName = "failed"

	minKeyLength = 32
	keyInfo      = "gmessages-sleep state v1"
)

// stateMagic prefixes the state file and is authenticated as additional data, so a file from
// a different format version fails to decrypt instead of being misread.
var stateMagic = []byte("GMSLEEP1")

var (
	ErrNoState  = errors.New("no saved session in the state directory, import one first")
	ErrWrongKey = errors.New("cannot decrypt the state file: wrong key or corrupted file")
	ErrLocked   = errors.New("another wake is already running on this state directory")
)

// State is everything a wake needs to resume without pairing again. It only ever touches disk
// encrypted.
type State struct {
	// Session holds the pairing keys, the paired phone and browser identities, the tachyon
	// token and the Google account cookies.
	Session *libgm.AuthData `json:"session"`
	// Cursor marks the newest message already written to the inbox.
	Cursor Cursor `json:"cursor"`
	// LastSeq is the sequence number of the last inbox line and InboxSize the inbox length
	// that this state committed, which lets a wake recognise lines written by a wake that
	// stopped before saving.
	LastSeq   int64 `json:"last_seq"`
	InboxSize int64 `json:"inbox_size"`
}

// Cursor is the newest message timestamp that has been drained, with the IDs of the messages
// at exactly that timestamp so that a message sharing it isn't skipped.
type Cursor struct {
	Timestamp  int64    `json:"timestamp_us"`
	MessageIDs []string `json:"message_ids,omitempty"`
}

func (c Cursor) covers(msg *gmproto.Message) bool {
	return msg.GetTimestamp() < c.Timestamp ||
		(msg.GetTimestamp() == c.Timestamp && slices.Contains(c.MessageIDs, msg.GetMessageID()))
}

func (c Cursor) advance(msg Message) Cursor {
	switch {
	case msg.Timestamp > c.Timestamp:
		return Cursor{Timestamp: msg.Timestamp, MessageIDs: []string{msg.ID}}
	case msg.Timestamp == c.Timestamp && !slices.Contains(c.MessageIDs, msg.ID):
		c.MessageIDs = append(slices.Clone(c.MessageIDs), msg.ID)
	}
	return c
}

// LoadKey reads the state encryption key from a file that has to live outside the state
// directory and be accessible only by its owner. The file holds at least 32 bytes of random
// data (for example from `head -c 32 /dev/urandom`), which is stretched into the AES-256 key
// with HKDF-SHA256.
func LoadKey(keyPath, stateDir string) ([]byte, error) {
	realKey, err := filepath.EvalSymlinks(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve key file: %w", err)
	}
	realDir, err := filepath.EvalSymlinks(stateDir)
	if errors.Is(err, fs.ErrNotExist) {
		realDir, err = filepath.Abs(stateDir)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to resolve state directory: %w", err)
	}
	if rel, err := filepath.Rel(realDir, realKey); err == nil && filepath.IsLocal(rel) {
		return nil, fmt.Errorf("key file %s is inside the state directory, keep it somewhere else", keyPath)
	}
	info, err := os.Stat(realKey)
	if err != nil {
		return nil, fmt.Errorf("failed to stat key file: %w", err)
	} else if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("key file %s is accessible by group or others (mode %#o), restrict it to 0600 or 0400", keyPath, perm)
	}
	raw, err := os.ReadFile(realKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	defer clear(raw)
	if len(raw) < minKeyLength {
		return nil, fmt.Errorf("key file %s must contain at least %d bytes of random data", keyPath, minKeyLength)
	}
	return hkdf.Key(sha256.New, raw, nil, keyInfo, 32)
}

// Store is an exclusively locked state directory.
type Store struct {
	dir  string
	aead cipher.AEAD
	lock *os.File
}

// Open locks the state directory, creating it with mode 0700 if needed. Only one Store can
// hold a directory at a time, so a timer that fires while the previous wake is still running
// can't send the same reply twice.
func Open(dir string, key []byte) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create state directory: %w", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to stat state directory: %w", err)
	} else if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("state directory %s is accessible by group or others (mode %#o), restrict it to 0700", dir, perm)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("invalid state key: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, lockFileName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file: %w", err)
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("failed to lock state directory: %w", err)
	}
	return &Store{dir: dir, aead: aead, lock: lock}, nil
}

// Close releases the directory lock.
func (s *Store) Close() error {
	return s.lock.Close()
}

func (s *Store) path(name string) string {
	return filepath.Join(s.dir, name)
}

// Load decrypts the saved state.
func (s *Store) Load() (*State, error) {
	sealed, err := os.ReadFile(s.path(stateFileName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoState
	} else if err != nil {
		return nil, fmt.Errorf("failed to read state file: %w", err)
	}
	headerLen := len(stateMagic) + s.aead.NonceSize()
	if len(sealed) < headerLen+s.aead.Overhead() || !bytes.HasPrefix(sealed, stateMagic) {
		return nil, ErrWrongKey
	}
	plain, err := s.aead.Open(nil, sealed[len(stateMagic):headerLen], sealed[headerLen:], stateMagic)
	if err != nil {
		return nil, ErrWrongKey
	}
	defer clear(plain)
	var st State
	// The decode error is replaced rather than wrapped so that no fragment of the decrypted
	// state can end up in an error message.
	if json.Unmarshal(plain, &st) != nil {
		return nil, errors.New("the decrypted state is not valid, restore it from a backup or import the session again")
	} else if st.Session == nil || st.Session.Browser == nil {
		return nil, errors.New("the saved state has no paired session")
	}
	return &st, nil
}

// Save encrypts the state with AES-256-GCM and atomically replaces the state file.
func (s *Store) Save(st *State) error {
	plain, err := json.Marshal(st)
	if err != nil {
		return errors.New("failed to serialize state")
	}
	defer clear(plain)
	nonce := make([]byte, s.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	sealed := append(slices.Concat(stateMagic, nonce), s.aead.Seal(nil, nonce, plain, stateMagic)...)
	return writeFileAtomic(s.path(stateFileName), sealed)
}

// writeFileAtomic writes data to a 0600 temporary file next to path, syncs it and renames it
// over path, so a crash leaves either the old file or the new one.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("failed to write %s: %w", filepath.Base(path), err)
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("failed to replace %s: %w", filepath.Base(path), err)
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
