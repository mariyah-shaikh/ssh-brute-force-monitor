# SSH Brute-Force Monitor

A Python tool that watches the Linux systemd journal for failed SSH logins,
counts them per source IP in a sliding time window, and sends an email alert
when a threshold is exceeded.

## How it works
- Streams `journalctl -u ssh` in real time
- A regex extracts the username and source IP from "Failed password" events
- Keeps a 60-second sliding window of attempts per IP
- Alerts when one IP reaches 3 failures; 5-minute email cooldown per IP

## Requirements
- Linux with systemd and OpenSSH server (tested on Kali Linux)
- Python 3 (standard library only)
- Gmail account with an App Password

## Setup

Set your email details as environment variables (never put them in the code).

**Kali / zsh:**
```bash
export ALERT_SENDER="you@gmail.com"
export ALERT_RECIPIENT="you@gmail.com"
read -s "GMAIL_APP_PASSWORD?App password: "
export GMAIL_APP_PASSWORD
sudo -E python3 ssh_monitor.py
```

**bash:**
```bash
export ALERT_SENDER="you@gmail.com"
export ALERT_RECIPIENT="you@gmail.com"
read -s -p "App password: " GMAIL_APP_PASSWORD; export GMAIL_APP_PASSWORD
sudo -E python3 ssh_monitor.py
```

If the variables are not set, alerts are printed to the console instead of emailed.

## Testing
1. Start the monitor in one terminal.
2. In a second terminal run `ssh fakeuser@localhost` and enter 3 wrong passwords within 60 seconds.
3. The monitor prints the failed attempts and sends the alert email.

## Settings (top of `ssh_monitor.py`)
- `FAILED_THRESHOLD = 3` failed logins from one IP
- `WINDOW_SECONDS = 60` time window
- `ALERT_COOLDOWN = 300` seconds between emails for the same IP

## Limitations / future work
- Detection only; it does not block IPs (Fail2Ban does that)
- Monitors failed SSH logins only, not sudo/su privilege escalation
- Possible additions: Slack/Telegram alerts, IP blocking, more detection rules
