# ise-endpoint-explain

[![ci](https://github.com/korpus91/ise-endpoint-explain/actions/workflows/ci.yml/badge.svg)](https://github.com/korpus91/ise-endpoint-explain/actions/workflows/ci.yml)

"Why did this laptop land in the wrong VLAN?" "Why does this printer keep failing?" One command answers it from Cisco ISE: the live session, then a timeline of recent authentications with the user, method, switch and port, authorization profile, SGT and matched rule, and for every failure the ISE reason with its likely cause in plain English.

```
Endpoint AA:BB:CC:00:11:22

Active session
  user           host/laptop01.example.com
  ip             192.0.2.55
  device / port  access-sw1 / GigabitEthernet1/0/14
  authz profile  Corp-Access
  sgt            Employees

Authentication history (3 records, newest first)
  2026-10-06 14:22:10.123    PASS  user=host/laptop01.example.com  method=dot1x/EAP-TLS  device=access-sw1 port=GigabitEthernet1/0/14
                              authz=Corp-Access  sgt=Employees  rule=Corp-EAP-TLS
  2026-10-06 08:01:12.411    FAIL  ...
                              reason: 12514 EAP-TLS failed SSL/TLS handshake because of an unknown CA in the client certificates chain
                              likely cause: ... Import the issuing CA into ISE trusted certificates for client auth.
```

## Safety

Read-only. Two GET calls against the ISE Monitoring (MnT) REST API:

```
GET /admin/API/mnt/Session/MACAddress/{mac}
GET /admin/API/mnt/AuthStatus/MACAddress/{mac}/{seconds}/{records}/All
```

Credentials come from `ISE_USERNAME` / `ISE_PASSWORD` or a prompt and are never written to disk. Use a dedicated read-only monitoring account.

## Install and use

```bash
pip install ise-endpoint-explain
ise-explain aa:bb:cc:00:11:22 --mnt ise-mnt.example.com --ca-bundle corp-ca.pem
ise-explain aabb.cc00.1122 --mnt 192.0.2.10 --insecure --seconds 432000    # lab only, 5-day window
ise-explain AA-BB-CC-00-11-22 --offline saved/                            # no ISE access needed
```

MAC addresses are accepted in any common format. The history window is capped at 432000 seconds (5 days), the MnT API limit. In large deployments point `--mnt` at the MnT node.

Offline mode reads `session.xml` and `authstatus.xml`, the raw output of the two calls above, so a client can collect them and send them without granting access.

Exit codes: `0` newest authentication passed, `1` newest failed or no records, `2` error.

## Failure hints

Common ISE failure codes (5400, 5411, 5440, 11036, 12321, 12514, 12935, 15039, 22040, 22056, 24408) are mapped to their usual cause. Unknown codes print the ISE reason text unchanged. Additions are welcome by pull request.

## Status

Tested offline against synthetic responses built from Cisco's documented MnT API formats. Unknown fields are kept, not dropped, so new ISE releases degrade gracefully. If a field name differs on your version, open an issue with a redacted sample.

## License

MIT. See LICENSE. Security reports: see SECURITY.md.