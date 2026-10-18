#!/usr/bin/env python3
"""
SSH Brute-Force Monitor
Watches the systemd journal for failed SSH logins, counts them per source IP
inside a sliding time window, and sends an email alert when a threshold is hit.
"""

import os
import re
import smtplib
import subprocess
import time
from collections import defaultdict, deque
from email.mime.text import MIMEText

# ---------- Settings ----------
WINDOW_SECONDS = 60      # look-back window
FAILED_THRESHOLD = 3     # failed logins from ONE IP inside the window -> alert
ALERT_COOLDOWN = 300     # seconds before the same IP can trigger another alert

# ---------- Secrets come from environment variables, never from the code ----------
SENDER_EMAIL = os.environ.get("ALERT_SENDER")
RECIPIENT_EMAIL = os.environ.get("ALERT_RECIPIENT")
APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD")

# One match per failed attempt. Captures the username and the source IP.
FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\S+) port \d+"
)


def send_alert(ip, events):
    """Send an email (or print to console if email is not configured)."""
    subject = f"ALERT: {len(events)} failed SSH logins from {ip}"
    body = (
        f"{len(events)} failed SSH login attempts from {ip} "
        f"within {WINDOW_SECONDS} seconds.\n\nLog lines:\n\n" + "\n".join(events)
    )

    if not (SENDER_EMAIL and RECIPIENT_EMAIL and APP_PASSWORD):
        print("\n[ALERT - email not configured, printing instead]")
        print(subject)
        print(body + "\n")
        return

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECIPIENT_EMAIL

    try:
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=20) as server:
            server.starttls()
            server.login(SENDER_EMAIL, APP_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECIPIENT_EMAIL, msg.as_string())
        print(f"[+] Alert email sent for {ip}")
    except Exception as err:  # a mail failure must not kill the monitor
        print(f"[-] Could not send email: {err}")


def monitor():
    # -f follow live, -n 0 = skip old lines, only watch new ones
    cmd = ["journalctl", "-u", "ssh", "-f", "-n", "0", "--no-pager"]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1
    )

    attempts = defaultdict(deque)  # ip -> deque of (timestamp, log line)
    last_alert = {}                # ip -> time of last alert

    print(f"[*] Monitoring SSH logins... alert at {FAILED_THRESHOLD} failures "
          f"per IP within {WINDOW_SECONDS}s. Ctrl+C to stop.")

    try:
        for line in proc.stdout:
            match = FAILED_PATTERN.search(line)
            if not match:
                continue

            user, ip = match.groups()
            now = time.time()
            window = attempts[ip]
            window.append((now, line.strip()))

            # drop attempts older than the window
            while window and now - window[0][0] > WINDOW_SECONDS:
                window.popleft()

            print(f"[!] Failed login: user={user} ip={ip} "
                  f"({len(window)}/{FAILED_THRESHOLD})")

            cooled_down = now - last_alert.get(ip, 0) > ALERT_COOLDOWN
            if len(window) >= FAILED_THRESHOLD and cooled_down:
                send_alert(ip, [entry[1] for entry in window])
                last_alert[ip] = now
                window.clear()

    except KeyboardInterrupt:
        print("\n[+] Stopping monitor.")
    finally:
        proc.terminate()


if __name__ == "__main__":
    monitor()
