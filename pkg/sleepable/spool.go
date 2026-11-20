package sleepable

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Message is one drained message, stored as a line of inbox.jsonl.
type Message struct {
	// Seq numbers inbox lines from 1 without gaps. Readers keep the last Seq they handled and
	// ask for the messages after it.
	Seq              int64  `json:"seq"`
	ID               string `json:"id"`
	ConversationID   string `json:"conversation_id"`
	ConversationName string `json:"conversation_name,omitempty"`
	Timestamp        int64  `json:"timestamp_us"`
	Status           string `json:"status"`
	FromMe           bool   `json:"from_me"`
	SenderID         string `json:"sender_id,omitempty"`
	SenderName       string `json:"sender_name,omitempty"`
	SenderNumber     string `json:"sender_number,omitempty"`
	Text             string `json:"text,omitempty"`
	HasMedia         bool   `json:"has_media,omitempty"`
}

// Reply is a queued outgoing text message, stored as one JSON file in outbox/.
type Reply struct {
	ConversationID string `json:"conversation_id"`
	Text           string `json:"text"`
}

// ReadInbox returns the messages with a sequence number above since, oldest first. It only
// reads files, so the consumer needs neither the key nor the lock.
func ReadInbox(dir string, since int64) ([]Message, error) {
	data, err := os.ReadFile(filepath.Join(dir, inboxFileName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	msgs, err := parseInbox(data)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(msgs, func(msg Message) bool { return msg.Seq <= since }), nil
}

// parseInbox decodes complete inbox lines; a trailing line without a newline is still being
// written (or was cut short by a crash) and is ignored.
func parseInbox(data []byte) ([]Message, error) {
	data = data[:bytes.LastIndexByte(data, '\n')+1]
	var msgs []Message
	for line := range bytes.Lines(data) {
		var msg Message
		if err := json.Unmarshal(line, &msg); err != nil {
			return nil, fmt.Errorf("inbox line after seq %d is not valid JSON: %w", lastSeq(msgs), err)
		}
		msgs = append(msgs, msg)
	}
	return msgs, nil
}

func lastSeq(msgs []Message) int64 {
	if len(msgs) == 0 {
		return 0
	}
	return msgs[len(msgs)-1].Seq
}

// appendInbox writes a drained batch to the inbox and updates the inbox bookkeeping in st.
// Lines past st.InboxSize were written by a wake that stopped before it saved its state:
// they were already delivered, so their IDs are dropped from the batch and their sequence
// numbers are kept.
func appendInbox(dir string, st *State, batch []Message) ([]Message, error) {
	f, err := os.OpenFile(filepath.Join(dir, inboxFileName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to open inbox: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()
	if size < st.InboxSize {
		// The consumer rotated the inbox away; numbering continues from LastSeq.
		st.InboxSize = 0
	}
	delivered := make(map[string]bool)
	if size > st.InboxSize {
		residue := make([]byte, size-st.InboxSize)
		if _, err = f.ReadAt(residue, st.InboxSize); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("failed to read inbox: %w", err)
		}
		msgs, err := parseInbox(residue)
		if err != nil {
			return nil, err
		}
		for _, msg := range msgs {
			delivered[msg.ID] = true
			st.LastSeq = max(st.LastSeq, msg.Seq)
		}
		size = st.InboxSize + int64(bytes.LastIndexByte(residue, '\n')+1)
		if err = f.Truncate(size); err != nil {
			return nil, fmt.Errorf("failed to drop partial inbox line: %w", err)
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	var added []Message
	for _, msg := range batch {
		if delivered[msg.ID] {
			continue
		}
		st.LastSeq++
		msg.Seq = st.LastSeq
		if err = enc.Encode(msg); err != nil {
			return nil, err
		}
		added = append(added, msg)
	}
	if _, err = f.WriteAt(buf.Bytes(), size); err != nil {
		return nil, fmt.Errorf("failed to write inbox: %w", err)
	} else if err = f.Sync(); err != nil {
		return nil, fmt.Errorf("failed to sync inbox: %w", err)
	}
	st.InboxSize = size + int64(buf.Len())
	return added, nil
}

// QueueReply adds a reply to the outbox and returns its ID. Wakes send queued replies oldest
// first, at most one per wake, and only when sending is enabled.
func QueueReply(dir string, reply Reply) (string, error) {
	if strings.TrimSpace(reply.ConversationID) == "" || strings.TrimSpace(reply.Text) == "" {
		return "", errors.New("a reply needs a conversation ID and text")
	}
	outbox := filepath.Join(dir, outboxDirName)
	if err := os.MkdirAll(outbox, 0o700); err != nil {
		return "", fmt.Errorf("failed to create outbox: %w", err)
	}
	data, err := json.Marshal(reply)
	if err != nil {
		return "", err
	}
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	id := fmt.Sprintf("%020d-%s", time.Now().UnixNano(), hex.EncodeToString(suffix))
	return id, writeFileAtomic(filepath.Join(outbox, id+".json"), data)
}

// nextReply returns the oldest queued reply, or an empty ID if the outbox is empty.
func nextReply(dir string) (string, *Reply, error) {
	entries, err := os.ReadDir(filepath.Join(dir, outboxDirName))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil, nil
	} else if err != nil {
		return "", nil, err
	}
	idx := slices.IndexFunc(entries, func(e fs.DirEntry) bool {
		return e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".json") && !strings.HasPrefix(e.Name(), ".")
	})
	if idx < 0 {
		return "", nil, nil
	}
	id := strings.TrimSuffix(entries[idx].Name(), ".json")
	data, err := os.ReadFile(filepath.Join(dir, outboxDirName, entries[idx].Name()))
	if err != nil {
		return id, nil, err
	}
	var reply Reply
	if err = json.Unmarshal(data, &reply); err != nil {
		return id, nil, fmt.Errorf("queued reply is not valid JSON: %w", err)
	} else if reply.ConversationID == "" || reply.Text == "" {
		return id, nil, errors.New("queued reply needs a conversation ID and text")
	}
	return id, &reply, nil
}

func moveReply(dir, id, from, to string) error {
	if err := os.MkdirAll(filepath.Join(dir, to), 0o700); err != nil {
		return err
	}
	name := id + ".json"
	if err := os.Rename(filepath.Join(dir, from, name), filepath.Join(dir, to, name)); err != nil {
		return err
	}
	return syncDir(filepath.Join(dir, to))
}
