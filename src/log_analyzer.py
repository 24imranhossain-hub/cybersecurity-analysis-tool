#!/usr/bin/env python3
"""Security log analyzer.

Reads a Linux auth log (e.g. /var/log/auth.log) and reports:
  * failed SSH login attempts per source IP
  * possible brute-force attacks (IPs over the failure threshold)
  * successful logins and invalid usernames that were tried

Usage: python src/log_analyzer.py samples/sample_auth.log [--threshold 5]
"""
import argparse
import re
from collections import Counter

FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3})")
ACCEPTED = re.compile(r"Accepted \S+ for (\S+) from (\d{1,3}(?:\.\d{1,3}){3})")
INVALID_USER = re.compile(r"Invalid user (\S+) from")


def analyze(path):
    """Parse the log file and return counters for failed, accepted and invalid users."""
    failed_by_ip, accepted, invalid_users = Counter(), [], Counter()
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            if m := FAILED.search(line):
                failed_by_ip[m.group(2)] += 1
            elif m := ACCEPTED.search(line):
                accepted.append((m.group(1), m.group(2)))
            if m := INVALID_USER.search(line):
                invalid_users[m.group(1)] += 1
    return failed_by_ip, accepted, invalid_users


def main():
    parser = argparse.ArgumentParser(description="Analyze an auth log for suspicious logins.")
    parser.add_argument("logfile")
    parser.add_argument("--threshold", type=int, default=5,
                        help="failed attempts from one IP that count as brute force (default 5)")
    args = parser.parse_args()

    failed_by_ip, accepted, invalid_users = analyze(args.logfile)
    print("=== Security Log Analysis Report ===")
    print(f"Total failed logins: {sum(failed_by_ip.values())}")
    for ip, count in failed_by_ip.most_common():
        flag = "  <-- possible brute-force attack" if count >= args.threshold else ""
        print(f"  {ip:<16} {count} failed{flag}")
    print(f"Successful logins: {len(accepted)}")
    for user, ip in accepted:
        print(f"  {user} from {ip}")
    if invalid_users:
        print("Invalid usernames tried: " + ", ".join(sorted(invalid_users)))


if __name__ == "__main__":
    main()
