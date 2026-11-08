# authwatch

[![CI](https://github.com/faded14444/Authwatch-Log-Analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/faded14444/Authwatch-Log-Analyzer/actions/workflows/ci.yml)

**authwatch** reads raw authentication logs - **Windows Security logs (`.evtx`)** and
**Linux SSH logs (`auth.log` / `secure`)** - and detects attacks the way a SOC analyst would
triage them: brute-force, password spraying, and - most importantly - a successful logon
right after a run of failures.

Every alert is mapped to **MITRE ATT&CK**, has a severity, and explains itself in one sentence.

```
$ authwatch scan samples/auth.log
authwatch · 1 file · 27 logon events (27 analysed) · 2026-10-01 09:02:17 → 2026-10-01 09:51:54 UTC
┌──────────┬────────────────────────┬───────────────┬───────────────────────┬──────────┬────────────────────────────────┬──────────────┐
│ Severity │ Rule                   │ Source IP     │ Account(s)            │ Attempts │ Time (UTC)                     │ MITRE        │
├──────────┼────────────────────────┼───────────────┼───────────────────────┼──────────┼────────────────────────────────┼──────────────┤
│ CRITICAL │ Success after failures │ 203.0.113.45  │ root                  │       15 │ 2026-10-01 09:14:02 → 09:17:10 │ T1110, T1078 │
│ HIGH     │ Brute-force            │ 203.0.113.45  │ root                  │       15 │ 2026-10-01 09:14:02 → 09:16:30 │ T1110.001    │
│ HIGH     │ Password spraying      │ 198.51.100.23 │ admin, deploy +5 more │        8 │ 2026-10-01 09:40:05 → 09:51:54 │ T1110.003    │
└──────────┴────────────────────────┴───────────────┴───────────────────────┴──────────┴────────────────────────────────┴──────────────┘
Details
  1. CRITICAL Account 'root' logged on successfully from 203.0.113.45 after 15 failed attempts against this same account - verify this logon
  2. HIGH 15 failed logons for account 'root' from 203.0.113.45 within 2m 28s
  3. HIGH 8 failed logons against 7 different accounts from 198.51.100.23 within 11m 49s

Summary: 3 alert(s) - 1 critical, 2 high
```
<sub>Output for the synthetic demo log in <a href="samples/auth.log"><code>samples/auth.log</code></a> - run the command above to reproduce it. In a terminal, severities are colour-coded.</sub>

## Features

- **Windows:** parses native `.evtx` files directly - no manual export to CSV needed
- **Linux:** parses OpenSSH logs from Debian/Ubuntu (`auth.log`) and RHEL/Fedora (`secure`),
  including rotated `.gz` files, classic and RFC 3339 syslog timestamps
- Three detection rules mapped to MITRE ATT&CK, shared by both log sources
- Sliding time windows: one long attack produces **one** alert, not hundreds
- Noise filtering of local, loopback and machine-account logons (common false positives)
- Colour terminal report + **JSON output** ready for a SIEM, a script or `jq`
- Robust: a corrupted record, chunk or line is skipped and reported, not fatal
- Script-friendly exit codes: `0` no alerts, `1` alerts found, `2` error

## Installation

Requires Python 3.11+.

```bash
git clone https://github.com/faded14444/Authwatch-Log-Analyzer.git
cd Authwatch-Log-Analyzer
python -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
# try it on the bundled demo log
authwatch scan samples/auth.log

# Windows Security log
authwatch scan Security.evtx

# Linux: current and rotated logs at once
authwatch scan /var/log/auth.log /var/log/auth.log.1 /var/log/auth.log.2.gz

# a whole folder (searched recursively for *.evtx, auth.log*, secure*),
# only high+ alerts, save JSON
authwatch scan logs/ --min-severity high --output alerts.json

# tune thresholds for a noisier environment
authwatch scan Security.evtx --bf-threshold 20 --bf-window 10
```

Where to get a log:
- **Windows** (a machine you administer): Event Viewer → Windows Logs → Security →
  *Save All Events As…* (`.evtx`).
- **Linux:** `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/Fedora). On
  journald-only systems: `journalctl -u ssh -o short > auth.log`.

See [`samples/`](samples/README.md) for the demo log and public attack recordings.

## What counts as a logon

| Source | Failure | Success |
|---|---|---|
| Windows `.evtx` | event **4625** (an account failed to log on) | event **4624** (an account was successfully logged on) |
| Linux SSH | `Failed password for [invalid user] NAME from IP` | `Accepted <method> for NAME from IP` |

On Linux, other lines about the same attempt (`Invalid user …`, `pam_unix(sshd:auth):
authentication failure`, `Connection closed …`) are deliberately **ignored** - counting them
too would report each attempt two or three times. rsyslog's
`message repeated N times: [ … ]` is expanded, so collapsed lines are still counted.

## Detection rules

| Rule | Groups by | Fires when (default) | Severity | MITRE ATT&CK |
|---|---|---|---|---|
| **Brute-force** | source IP + account | ≥ 10 failures within 5 min | high | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Guessing |
| **Password spraying** | source IP | ≥ 5 *distinct accounts* failing within 30 min | high | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Password Spraying |
| **Success after failures** | source IP | a success preceded by ≥ 5 failures within 10 min | **critical** | [T1110](https://attack.mitre.org/techniques/T1110/) → [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts |

Account names are compared the way each OS does it: **case-insensitive on Windows**
(`ADMIN` = `admin`), **case-sensitive on Linux** (`Root` and `root` are different users).

### Why these thresholds?

Every threshold trades **sensitivity** (catching slow, careful attackers) against
**false positives** (users who mistype their password a few times). The defaults are a
starting point:

- **Brute-force 10 / 5 min.** A human who forgot their password rarely fails more than 3–5
  times before giving up or getting locked out. Ten failures in five minutes is machine speed.
- **Spraying 5 accounts / 30 min.** Sprayers deliberately go *slow and wide* to stay under
  the account-lockout policy, so this rule counts **distinct accounts** over a longer window
  instead of raw attempts. One host failing against five different accounts is very
  unusual for legitimate traffic.
- **Success after failures 5 / 10 min.** This is the alert that matters most: the attack may
  have worked. It is rated critical and should be verified with the account owner. The
  description says whether the successful account was itself under attack or was a
  different account (typical after a spray).

All thresholds can be changed from the command line (`authwatch scan --help`).

### Noise filtering

Before detection, authwatch drops events that are almost always benign:
no source IP (`-`), loopback addresses, machine accounts (`HOST$`) and `ANONYMOUS LOGON`.
All of these rules live in [`filters.py`](src/authwatch/filters.py).

**One deliberate exception:** RDP logons (logon type 10) from `127.0.0.1` are *kept*.
RDP from localhost is never normal - it is the fingerprint of RDP tunnelling (ngrok, plink,
chisel). A naive "drop all loopback" filter would make a brute-force attack through such a
tunnel completely invisible. This gap was found by testing against a real RDP-tunnelling
recording from EVTX-ATTACK-SAMPLES.

### Known limitations

- Classic syslog lines (`Oct  1 09:14:02 …`) have **no year and no timezone**. authwatch
  takes the year of the file's last modification (override with `--linux-year`), handles
  the December → January rollover, and treats the times as UTC. RFC 3339 timestamps
  (`2026-10-01T09:14:02+02:00`) carry both and are converted exactly.
- Distributed attacks from many IPs (one attempt per IP) are not correlated yet.
- Kerberos pre-auth failures (4771) and NTLM validation (4776) are not parsed yet.
- All times are reported in UTC.

## Architecture

```
 parsers/                  filters.py       detectors/                 reporters/
┌────────────────────┐    ┌───────────┐    ┌───────────────────────┐   ┌──────────┐
│ evtx_parser        │──▶ │  drop     │──▶ │ brute_force           │──▶│ console  │
│ linux_auth_parser  │    │  noise    │    │ password_spray        │   │ json     │
│  (→ AuthEvent)     │    └───────────┘    │ success_after_failures│   └──────────┘
└────────────────────┘                     └───────────────────────┘
```

Each parser converts its log format into a common `AuthEvent`
([`models.py`](src/authwatch/models.py)). Detectors only ever see `AuthEvent`s, so the
Linux parser was added as **one new parser file** plus a routing rule in
[`parsers/__init__.py`](src/authwatch/parsers/__init__.py) - the detection rules and
reports did not change.

## Development

```bash
pytest          # 100 tests: rules (incl. edge cases), both parsers, filters, reports, CLI
ruff check .    # lint
```

Detection rules are tested on hand-built event sequences (no log files needed), covering
the edges: one below the threshold, attempts spread just outside the window, long attacks
that must produce a single alert, and account-name case rules per OS. The Linux parser is
tested line by line (repeated messages, `invalid user`, year rollover, gzip, RFC 3339) and
end-to-end on the demo log.

## Roadmap

- [x] Windows Security `.evtx` parser
- [x] Linux SSH `auth.log` / `secure` parser
- [ ] HTML report with a timeline chart
- [ ] Kerberos (4771) and NTLM (4776) failures
- [ ] Correlation of distributed attacks across many source IPs

## Responsible use

authwatch is a **defensive** tool for analysing logs from systems you own or are
authorised to monitor. `samples/auth.log` is synthetic and uses documentation-only IP
ranges (RFC 5737); third-party recordings referenced in `samples/` come from public
research datasets - see that folder for sources.
