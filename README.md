# SSH Brute-Force Monitor

A Python tool that watches the Linux systemd journal for failed SSH logins,
counts them per source IP in a sliding time window, and sends an email alert
when a threshold is exceeded.

## How it works
- Streams `journalctl -u ssh` in real time
- Regex extracts username and source IP from "Failed password" events
- Keeps a 60-second sliding window of attempts per IP
- Alerts when one IP reaches 3 failures; 5-minute cooldown per IP

## Requirements
- Linux with systemd and OpenSSH server (tested on Kali Linux)
- Python 3 (standard library only)
- Gmail account with an App Password

## Setup
```bash
export ALERT_SENDER="you@gmail.com"
export ALERT_RECIPIENT="you@gmail.com"
read -s -p "App password: " GMAIL_APP_PASSWORD; export GMAIL_APP_PASSWORD
sudo -E python3 ssh_monitor.py
```
If these variables are not set, alerts are printed to the console.

## Testing
From another terminal: `ssh fakeuser@localhost` and enter 3 wrong passwords.

## Limitations / future work
- Detection only; does not block IPs (Fail2Ban does that)
- Monitors failed SSH logins only, not sudo/su privilege escalation
- Possible additions: Slack/Telegram alerts, privilege escalation rules
