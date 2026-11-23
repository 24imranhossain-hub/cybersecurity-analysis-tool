# Vulnerability Scanner

`src/vuln_scanner.py` audits a server configuration file (INI format) and reports insecure settings with a severity and a recommended fix.

## Checks

| Severity | Setting | Problem | Fix |
|---|---|---|---|
| HIGH | `[ssh] PermitRootLogin = yes` | Root can log in over SSH | Set to `no` |
| HIGH | `[services] telnet = enabled` | Clear-text passwords | Disable Telnet, use SSH |
| HIGH | `[files] shadow_permissions` not 600/640 | Password hashes readable | `chmod 640 /etc/shadow` |
| MEDIUM | `[ssh] PasswordAuthentication = yes` | Password guessing possible | Use SSH keys |
| MEDIUM | `[services] ftp = enabled` | Unencrypted file transfer | Use SFTP |
| MEDIUM | `[password_policy] min_length` < 12 | Weak passwords allowed | Minimum 12 characters |
| MEDIUM | `[password_policy] max_failed_attempts` > 5 | Brute force easier | Lock after 5 attempts |
| LOW | `[ssh] Port = 22` | Default port attracts scans | Consider another port |

## Usage
```bash
python src/vuln_scanner.py samples/server_config.ini
```
The exit code is 1 when any HIGH finding exists, so the scan can fail a CI pipeline.

## Example output (first findings)
```
=== Vulnerability Scan Report ===
Findings: 7
  [HIGH  ] [ssh] PermitRootLogin = yes
           Issue: Root can log in over SSH
           Fix:   Set PermitRootLogin to no
  [HIGH  ] [services] telnet = enabled
           Issue: Telnet sends passwords in clear text
           Fix:   Disable Telnet and use SSH
```

## Adding a new check
Add one tuple to the `CHECKS` list: `(section, key, check_function, severity, message, recommendation)`.
