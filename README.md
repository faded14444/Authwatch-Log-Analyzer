# authwatch

<!-- After pushing to GitHub, add the CI badge (replace USER):
[![CI](https://github.com/USER/authwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/USER/authwatch/actions/workflows/ci.yml)
-->

**authwatch** reads raw Windows Security logs (`.evtx`) and detects authentication attacks
the way a SOC analyst would triage them: brute-force, password spraying, and - most
importantly - a successful logon right after a run of failures.

Every alert is mapped to **MITRE ATT&CK**, has a severity, and explains itself in one sentence.

```
authwatch · 1 file · 100 logon events (60 analysed) · 2026-10-01 09:14:00 → 2026-10-01 11:14:00 UTC
┌──────────┬────────────────────────┬────────────┬─────────────────────────┬──────────┬────────────────────────────────┬──────────────┐
│ Severity │ Rule                   │ Source IP  │ Account(s)              │ Attempts │ Time (UTC)                     │ MITRE        │
├──────────┼────────────────────────┼────────────┼─────────────────────────┼──────────┼────────────────────────────────┼──────────────┤
│ CRITICAL │ Success after failures │ 10.0.0.5   │ admin                   │       23 │ 2026-10-01 09:14:00 → 09:21:14 │ T1110, T1078 │
│ HIGH     │ Brute-force            │ 10.0.0.5   │ admin                   │       23 │ 2026-10-01 09:14:00 → 09:20:36 │ T1110.001    │
│ HIGH     │ Password spraying      │ 172.16.4.9 │ anowak, backup +10 more │       36 │ 2026-10-01 11:10:40 → 11:12:20 │ T1110.003    │
└──────────┴────────────────────────┴────────────┴─────────────────────────┴──────────┴────────────────────────────────┴──────────────┘
Details
  1. CRITICAL Account 'admin' logged on successfully from 10.0.0.5 after 23 failed attempts against this same account - verify this logon
  2. HIGH 23 failed logons for account 'admin' from 10.0.0.5 within 6m 36s
  3. HIGH 36 failed logons against 12 different accounts from 172.16.4.9 within 1m 40s

Summary: 3 alert(s) - 1 critical, 2 high
```
<sub>Example output on synthetic data. In a terminal, severities are colour-coded.</sub>

## Features

- Parses native **`.evtx`** files directly - no manual export from Event Viewer needed
- Three detection rules mapped to MITRE ATT&CK (see below)
- Sliding time windows: one long attack produces **one** alert, not hundreds
- Noise filtering of local, loopback and machine-account logons (common false positives)
- Colour terminal report + **JSON output** ready for a SIEM, a script or `jq`
- Robust: a corrupted record or chunk is skipped and reported, not fatal
- Script-friendly exit codes: `0` no alerts, `1` alerts found, `2` error
- Streams events from disk, so large logs do not need to fit in memory at the parsing stage

## Installation

Requires Python 3.11+.

```bash
git clone https://github.com/USER/authwatch.git
cd authwatch
python -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
# one file
authwatch scan Security.evtx

# a whole folder (searched recursively), only high+ alerts, save JSON
authwatch scan logs/ --min-severity high --output alerts.json

# tune thresholds for a noisier environment
authwatch scan Security.evtx --bf-threshold 20 --bf-window 10
```

Where to get a log: on a Windows machine you administer, open **Event Viewer → Windows
Logs → Security → Save All Events As… (.evtx)**. For ready-made attack recordings see
[`samples/`](samples/README.md).

## Detection rules

The parser reads two Windows events: **4625** (an account failed to log on) and **4624**
(an account was successfully logged on).

| Rule | Groups by | Fires when (default) | Severity | MITRE ATT&CK |
|---|---|---|---|---|
| **Brute-force** | source IP + account | ≥ 10 failures within 5 min | high | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Guessing |
| **Password spraying** | source IP | ≥ 5 *distinct accounts* failing within 30 min | high | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Password Spraying |
| **Success after failures** | source IP | a 4624 preceded by ≥ 5 failures within 10 min | **critical** | [T1110](https://attack.mitre.org/techniques/T1110/) → [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts |

### Why these thresholds?

Every threshold trades **sensitivity** (catching slow, careful attackers) against
**false positives** (users who mistype their password a few times). The defaults are a
starting point:

- **Brute-force 10 / 5 min.** A human who forgot their password rarely fails more than 3–5
  times before giving up or getting locked out. Ten failures in five minutes is machine speed.
- **Spraying 5 accounts / 30 min.** Sprayers deliberately go *slow and wide* to stay under
  the account-lockout policy, so this rule counts **distinct accounts** over a longer window
  instead of raw attempts. One workstation failing against five different accounts is very
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

- Distributed attacks from many IPs (one attempt per IP) are not correlated yet.
- Kerberos pre-auth failures (4771) and NTLM validation (4776) are not parsed yet.
- Timestamps are reported in UTC.

## Architecture

```
 parsers/            filters.py       detectors/                 reporters/
┌──────────────┐    ┌───────────┐    ┌───────────────────────┐   ┌──────────┐
│ evtx_parser  │──▶ │  drop     │──▶ │ brute_force           │──▶│ console  │
│ (.evtx→      │    │  noise    │    │ password_spray        │   │ json     │
│  AuthEvent)  │    └───────────┘    │ success_after_failures│   └──────────┘
└──────────────┘                     └───────────────────────┘
```

Each parser converts its log format into a common `AuthEvent`
([`models.py`](src/authwatch/models.py)). Detectors only ever see `AuthEvent`s, so adding
a new log source (e.g. Linux `auth.log`) means adding **one parser file** - the
detection rules and reports work unchanged.

## Development

```bash
pytest          # 80+ tests: rules (incl. edge cases), parser, filters, reports, CLI
ruff check .    # lint
```

Detection rules are tested on hand-built event sequences (no log files needed), covering
the edges: one below the threshold, attempts spread just outside the window, long attacks
that must produce a single alert, and case-insensitive account names.

## Roadmap

- [ ] Linux SSH `auth.log` parser
- [ ] HTML report with a timeline chart
- [ ] Kerberos (4771) and NTLM (4776) failures
- [ ] Correlation of distributed attacks across many source IPs

## Responsible use

authwatch is a **defensive** tool for analysing logs from systems you own or are
authorised to monitor. Sample logs referenced in `samples/` come from public research
datasets - see that folder for sources.
