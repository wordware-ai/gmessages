# gmessages-sleep

A Google Messages client that stays off between wakes. Each `wake` reconnects with the
saved pairing (no QR code, no new pairing), drains the messages that arrived since the
last saved cursor into `inbox.jsonl`, sends at most one queued reply when `-allow-send` is
given, saves the new cursor and session, and exits. Run it from cron or a systemd timer.

It drives `libgm` through its public API and never pairs: pair once with a tool that produces
a libgm session (`pkg/libgm/gmtest` or the bridge), then import it.

## Setup

```sh
(umask 077 && head -c 32 /dev/urandom > ~/.config/gmessages-sleep.key)
gmessages-sleep import -dir ~/.local/state/gmessages-sleep \
  -key-file ~/.config/gmessages-sleep.key < session.json
shred -u session.json
```

The key file must be outside the state directory and readable only by its owner (0600 or
0400), and the state directory must be 0700. `-dir` and `-key-file` can also come from
`$GMSLEEP_DIR` and `$GMSLEEP_KEY_FILE`. The first wake drains messages newer than the import.

## Wake cycle

```ini
# gmessages-sleep.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/gmessages-sleep wake -dir %S/gmessages-sleep -key-file %E/gmessages-sleep.key

# gmessages-sleep.timer
[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
```

`wake` prints a JSON summary such as `{"drained":2,"last_seq":42,"cursor_timestamp_us":...}`
and exits 0. It exits 1 when the wake failed, in which case nothing in the state directory
changed and the next wake retries from the same cursor. On SIGTERM or SIGINT it disconnects,
saves the session (which may hold a refreshed token or rotated cookies), keeps the old cursor,
prints `"interrupted":true` and exits 0. Only one wake can hold a state directory at a time.

## Reading and replying

```sh
gmessages-sleep read -dir DIR -since 41      # inbox lines with seq > 41, one JSON object each
gmessages-sleep queue -dir DIR -conversation CONVERSATION_ID -text "On my way"
gmessages-sleep wake -dir DIR -key-file KEY -allow-send
```

Neither `read` nor `queue` needs the key. Without `-allow-send` the client is read-only: a
queued reply is reported as `refused` and stays queued.

| Path          | Contents                                                                   |
|---------------|----------------------------------------------------------------------------|
| `state.enc`   | Session, pairing keys, Google cookies and cursor, AES-256-GCM encrypted     |
| `inbox.jsonl` | Drained messages, append-only, numbered by `seq` (plaintext, mode 0600)    |
| `outbox/`     | Queued replies, one JSON file each, sent oldest first, one per wake        |
| `sent/`       | Replies the phone accepted                                                 |
| `failed/`     | Replies that failed or whose outcome is unknown; they are never retried    |
