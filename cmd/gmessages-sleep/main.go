// Command gmessages-sleep runs a Google Messages client that sleeps between wakes. Each
// "wake" reconnects with the encrypted saved session, drains new messages into inbox.jsonl,
// sends at most one queued reply (only with -allow-send), saves its cursor and exits, so it
// fits a cron job or a systemd timer.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exhttp"

	"go.mau.fi/mautrix-gmessages/pkg/libgm"
	"go.mau.fi/mautrix-gmessages/pkg/sleepable"
)

const usage = `Usage: gmessages-sleep <command> [flags]

Commands:
  import   read a paired libgm session (AuthData JSON) from stdin and encrypt it into the state directory
  wake     reconnect, drain new messages into inbox.jsonl, optionally send one queued reply, save, exit
  read     print inbox messages after a sequence number, one JSON object per line
  queue    queue a reply for the next wake that runs with -allow-send

Every command takes -dir (or $GMSLEEP_DIR). import and wake also take -key-file (or
$GMSLEEP_KEY_FILE), a file outside -dir with at least 32 random bytes and mode 0600 or 0400.
Run "gmessages-sleep <command> -h" for the flags of a command.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "import":
		err = runImport(args)
	case "wake":
		err = runWake(args)
	case "read":
		err = runRead(args)
	case "queue":
		err = runQueue(args)
	case "-h", "-help", "--help", "help":
		fmt.Fprint(os.Stdout, usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gmessages-sleep:", err)
		os.Exit(1)
	}
}

type commonFlags struct {
	dir     string
	keyFile string
}

func newFlagSet(name string, withKey bool) (*flag.FlagSet, *commonFlags) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	cf := &commonFlags{}
	fs.StringVar(&cf.dir, "dir", os.Getenv("GMSLEEP_DIR"), "state directory (mode 0700)")
	if withKey {
		fs.StringVar(&cf.keyFile, "key-file", os.Getenv("GMSLEEP_KEY_FILE"), "file holding the state encryption key")
	}
	return fs, cf
}

func (cf *commonFlags) openStore() (*sleepable.Store, error) {
	if cf.dir == "" || cf.keyFile == "" {
		return nil, errors.New("-dir and -key-file are required")
	}
	key, err := sleepable.LoadKey(cf.keyFile, cf.dir)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	return sleepable.Open(cf.dir, key)
}

func runImport(args []string) error {
	fs, cf := newFlagSet("import", true)
	force := fs.Bool("force", false, "replace an existing saved session")
	_ = fs.Parse(args)
	store, err := cf.openStore()
	if err != nil {
		return err
	}
	defer store.Close()
	if _, err = store.Load(); err == nil && !*force {
		return errors.New("the state directory already holds a session, pass -force to replace it")
	} else if err != nil && !errors.Is(err, sleepable.ErrNoState) && !*force {
		return fmt.Errorf("refusing to overwrite unreadable state without -force: %w", err)
	}
	var session libgm.AuthData
	// The decode error is not wrapped so that no part of the session can be echoed back.
	if json.NewDecoder(io.LimitReader(os.Stdin, 1<<20)).Decode(&session) != nil {
		return errors.New("stdin is not a libgm session JSON object")
	} else if session.Browser == nil || session.Mobile == nil || session.RequestCrypto == nil || session.RefreshKey == nil {
		return errors.New("the session is not paired (it has no browser, phone or keys), pair it first")
	}
	// Start draining from now rather than pulling the whole history on the first wake.
	err = store.Save(&sleepable.State{
		Session: &session,
		Cursor:  sleepable.Cursor{Timestamp: time.Now().UnixMicro()},
	})
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Session imported and encrypted. Delete the plaintext copy you imported it from.")
	return nil
}

func runWake(args []string) error {
	fs, cf := newFlagSet("wake", true)
	allowSend := fs.Bool("allow-send", false, "send the oldest queued reply (without it the client is read-only)")
	readyTimeout := fs.Duration("ready-timeout", 45*time.Second, "how long to wait for the phone to accept the session")
	logLevel := fs.String("log-level", "info", "log level: debug, info, warn or error")
	_ = fs.Parse(args)
	level, err := zerolog.ParseLevel(*logLevel)
	if err != nil || level < zerolog.DebugLevel {
		// Trace logs from libgm include raw response bodies, which can carry auth tokens.
		return fmt.Errorf("unsupported log level %q, use debug, info, warn or error", *logLevel)
	}
	log := zerolog.New(os.Stderr).Level(level).With().Timestamp().Logger()

	store, err := cf.openStore()
	if err != nil {
		return err
	}
	defer store.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	res, err := sleepable.Wake(ctx, store, sleepable.Options{
		AllowSend:    *allowSend,
		HTTPSettings: exhttp.SensibleClientSettings,
		ReadyTimeout: *readyTimeout,
		Logger:       log,
	})
	if err != nil && !errors.Is(err, sleepable.ErrInterrupted) {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(res)
}

func runRead(args []string) error {
	fs, cf := newFlagSet("read", false)
	since := fs.Int64("since", 0, "only print messages with a sequence number above this")
	_ = fs.Parse(args)
	if cf.dir == "" {
		return errors.New("-dir is required")
	}
	msgs, err := sleepable.ReadInbox(cf.dir, *since)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	for _, msg := range msgs {
		if err = enc.Encode(msg); err != nil {
			return err
		}
	}
	return nil
}

func runQueue(args []string) error {
	fs, cf := newFlagSet("queue", false)
	var reply sleepable.Reply
	fs.StringVar(&reply.ConversationID, "conversation", "", "conversation ID to reply in (from the inbox)")
	fs.StringVar(&reply.Text, "text", "", "reply text")
	_ = fs.Parse(args)
	if cf.dir == "" {
		return errors.New("-dir is required")
	}
	id, err := sleepable.QueueReply(cf.dir, reply)
	if err != nil {
		return err
	}
	fmt.Println(id)
	return nil
}
