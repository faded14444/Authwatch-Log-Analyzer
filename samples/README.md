# Sample logs

Put `.evtx` files in this folder to try authwatch on real attack recordings.
Any `.evtx` placed here is also picked up by the test suite (`tests/test_parser.py`)
to check that real files parse correctly.

## Where to get them

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
*Save All Events As…* → `.evtx`. Do not commit logs from real company systems - they contain
usernames, hostnames and IP addresses.
