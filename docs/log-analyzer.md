# Log Analyzer

`src/log_analyzer.py` reviews a Linux authentication log and highlights activity a security analyst should investigate.

## What it detects
- **Failed SSH logins** grouped by source IP address
- **Possible brute-force attacks**: any IP with failed logins at or above the threshold
- **Successful logins** (user and source IP)
- **Invalid usernames** an attacker tried (e.g. `admin`, `test`)

## Usage
```bash
python src/log_analyzer.py samples/sample_auth.log
python src/log_analyzer.py /var/log/auth.log --threshold 10
```

| Option | Default | Meaning |
|---|---|---|
| `--threshold` | 5 | Failed attempts from one IP that count as brute force |

## Example output
```
=== Security Log Analysis Report ===
Total failed logins: 9
  203.0.113.45     6 failed  <-- possible brute-force attack
  198.51.100.7     2 failed
  10.0.0.15        1 failed
Successful logins: 3
  imran from 10.0.0.15
  imran from 10.0.0.15
  deploy from 10.0.0.20
Invalid usernames tried: admin, test
```

## Next steps for the analyst
Block or rate-limit flagged IPs (e.g. with fail2ban or a firewall rule) and check whether any successful login came from a flagged IP.
