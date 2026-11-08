# Sample logs

## `auth.log` - Linux demo (included)

A **synthetic** OpenSSH log written for this project, so it can be committed and used by
anyone: `authwatch scan samples/auth.log`. All IPs come from the documentation-only ranges
of RFC 5737. It contains three scenarios plus normal traffic:

| Time (Oct 1) | What happens | Expected alert |
|---|---|---|
| 09:02–09:05 | alice logs in with a key; bob mistypes once, then logs in | none (normal) |
| 09:14–09:17 | 203.0.113.45 fails 15 times as `root`, then **gets in** | Brute-force + **Success after failures** |
| 09:40–09:52 | 198.51.100.23 tries 7 different accounts slowly | Password spraying |

The file also exercises the parser: rsyslog `message repeated N times`, `invalid user`,
the newer `sshd-session` tag, and noise lines (cron, sudo, pam) that must be ignored.
It is checked end-to-end by `tests/test_linux_parser.py`.

## Windows `.evtx` recordings (download yourself)

Put `.evtx` files in this folder to try authwatch on real attack recordings.
Any `.evtx` placed here is also picked up by the test suite (`tests/test_parser.py`)
to check that real files parse correctly.

### Where to get them

**EVTX-ATTACK-SAMPLES** - a public collection of Windows event logs recorded during real
attack techniques, organised by MITRE ATT&CK tactic:
<https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES>

Files used during development (real 4624/4625 events, ~68 KB each):

- `Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx`
- `Command and Control/DE_RDP_Tunneling_4624.evtx` - RDP logons from `127.0.0.1`, which led
  to the "keep loopback RDP" rule in `filters.py`

```bash
curl -L -o samples/DE_RDP_Tunneling_4624.evtx "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/Command%20and%20Control/DE_RDP_Tunneling_4624.evtx"
```

EVTX-ATTACK-SAMPLES is licensed under **GPL-3.0**, so the files are *not* committed here
(`samples/*.evtx` is in `.gitignore`). Download them locally to run the real-file tests.

## Your own logs

On a Windows machine **you administer**: Event Viewer → Windows Logs → Security →
*Save All Events As…* → `.evtx`. On Linux: `/var/log/auth.log` or `/var/log/secure`.
Do not commit logs from real company systems - they contain usernames, hostnames and
IP addresses.
