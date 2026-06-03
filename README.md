# Open-Pot

Custom SSH honeypot built for learning and lab use. It accepts SSH connections, logs credentials and commands, and provides a fake shell prompt. Use only on isolated networks you control.

## Quick start (Docker)

1. Build the image:
   ```
   docker build -t open-pot .
   ```
2. Run the honeypot:
   ```
   mkdir -p data
   docker run --rm -p 2222:2222 -v "$(pwd)/data:/data" open-pot
   ```
3. Connect from another VM:
   ```
   ssh -p 2222 attacker@192.168.56.10
   ```

Logs are written to `data/events.jsonl`.

## Configuration

Environment variables:

| Variable | Default | Description |
|---|---|---|
| HONEYPOT_LISTEN_HOST | 0.0.0.0 | Bind address |
| HONEYPOT_LISTEN_PORT | 2222 | SSH listen port |
| HONEYPOT_BANNER | Open-Pot SSH | SSH banner |
| HONEYPOT_PROMPT | attacker@open-pot:~$ | Fake shell prompt |
| HONEYPOT_LOG_PATH | /data/events.jsonl | Log file path |
| HONEY_LOG_ENDPOINT | (empty) | Optional HTTP endpoint to POST events |

## Safety

Run this only in an isolated lab environment. Do not store real data or credentials in the honeypot. If you need internet access for updates, use a second NAT NIC with strict outbound firewall rules.
