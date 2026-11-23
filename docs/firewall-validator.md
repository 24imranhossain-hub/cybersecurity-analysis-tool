# Firewall Rule Validator

`src/firewall_validator.py` checks a firewall rule set **before** it is deployed, so mistakes are caught in review instead of in production.

## Input format
A CSV file with the columns `rule_id,action,protocol,source,destination,port`.

| Field | Allowed values |
|---|---|
| action | `allow`, `deny` |
| protocol | `tcp`, `udp`, `icmp`, `any` |
| source / destination | `any`, an IP address or a CIDR network (e.g. `10.0.0.0/24`) |
| port | `any` or 1-65535 |

## Checks
1. **Syntax**: invalid action, protocol, IP address or port.
2. **Duplicates**: the same rule appearing more than once.
3. **Risky rules**: `allow` from `any` source to SSH (22), Telnet (23), SMB (445), MySQL (3306) or RDP (3389).

## Usage
```bash
python src/firewall_validator.py samples/firewall_rules.csv
```

## Example output
```
=== Firewall Rule Validation Report ===
Errors:   3
  [ERROR] Rule 5: invalid action 'permit'
  [ERROR] Rule 6: invalid source address '10.0.0.300'
  [ERROR] Rule 7: invalid port '70000'
Warnings: 3
  [WARN]  Rule 2: allows ANY source to SSH (port 22)
  [WARN]  Rule 4: duplicate of rule 1
  [WARN]  Rule 8: allows ANY source to RDP (port 3389)
```
The script exits with code 1 when errors are found, so it can be used in a CI pipeline.
