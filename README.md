# Splunk SOC Home Lab — Detection Engineering with MITRE ATT&CK + AI-Assisted Triage

A hands-on Security Operations Center (SOC) lab: Splunk Enterprise running in Docker, loaded with a realistic attack dataset, used to author detections, map them to MITRE ATT&CK, alert on them, visualize them, and prototype an AI-assisted triage workflow.

> **Note on data:** This lab uses the public, CC0-licensed [Boss of the SOC v3 (BOTSv3)](https://github.com/splunk/botsv3) dataset. All hostnames, usernames, and IPs in the findings (e.g. the fictional "Frothly" company) are part of that public sample data, not real systems.

---

## Architecture

```
BOTSv3 dataset  ──►  Splunk Enterprise (Docker container)  ──►  Detections / Dashboard / Alerts
                                                            └──►  AI-assisted triage (LLM summary, analyst-verified)
```

- **Platform:** Splunk Enterprise in a single Docker container (macOS host, Apple Silicon under emulation)
- **Data source:** BOTSv3 — pre-indexed multi-source attack telemetry (Sysmon, Windows, network, cloud)
- **Frameworks:** MITRE ATT&CK for technique mapping

---

## What's in this repo

| File | Description |
| --- | --- |
| `README.md` | This file |
| `detection-log.md` | Full detection documentation: SPL, MITRE mapping, analyst notes |
| `soc_ai_enrichment.py` | AI-assisted triage script (sends detection results to an LLM, optional HEC write-back) |
| `screenshots/` | Dashboard, detection results, fired alert, AI triage output |

---

## Setup summary

1. Run Splunk Enterprise in Docker (Apple Silicon needs `--platform linux/amd64`):
   ```bash
   docker run -d --platform linux/amd64 --name splunk --hostname splunk \
     -p 8000:8000 -p 8088:8088 \
     -e "SPLUNK_PASSWORD=<password>" \
     -e "SPLUNK_START_ARGS=--accept-license" \
     -e "SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com" \
     splunk/splunk:latest
   ```
2. Load the BOTSv3 dataset into `/opt/splunk/etc/apps/` and restart the container.
3. Search with the time range set to **All time** (the data is from 2018).

---

## Featured detection — Encoded PowerShell Execution

**Behavior:** PowerShell invoked with base64-encoded/hidden commands, spawning a binary masquerading as Internet Explorer from a Temp directory.

**Detection logic (SPL):**
```
index=botsv3 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" ("-enc" OR "EncodedCommand" OR "FromBase64String")
| rex field=_raw "Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]+)"
| rex field=_raw "Name='User'>(?<User>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?<ParentImage>[^<]+)"
| table _time, host, User, Image, ParentImage, CommandLine
```

**What the investigation found:** 51 executions of a misspelled `iexeplorer.exe` running from `C:\Windows\Temp`, spawned by PowerShell, with base64 command lines pointing at an internal Apache Struts endpoint — consistent with command injection and staging of a Linux privilege-escalation exploit.

**MITRE ATT&CK mapping:**

| Technique | Name |
| --- | --- |
| T1059.001 | Command & Scripting Interpreter: PowerShell |
| T1027 | Obfuscated Files or Information |
| T1036.005 | Masquerading: Match Legitimate Name or Location |
| T1190 | Exploit Public-Facing Application |
| T1105 | Ingress Tool Transfer |
| T1059.004 | Command & Scripting Interpreter: Unix Shell |

See `detection-log.md` for full analyst notes, false-positive considerations, and recommended response.

---

## AI-assisted triage (`soc_ai_enrichment.py`)

A small, standalone script that takes a detection's exported results, sends them to an LLM, and returns a plain-language triage summary, MITRE mapping, and next investigation steps. It can optionally write the summary back into Splunk via the HTTP Event Collector.

**Design principle:** the analyst owns detection logic and the final decision. The LLM produces a *first-pass triage summary to verify* — it assists, it does not decide. AI output in this project is treated as a lead to confirm, not as fact.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python3 soc_ai_enrichment.py alert_results.json
```
(A free local-model alternative via Ollama is documented in the script.)

---

## Key takeaways

- A SIEM does not detect attacks on its own — it filters and displays data. Recognizing the threat and mapping it to a framework is the analyst's judgment.
- Field extraction (`rex`) exposes the data; interpretation turns data into a detection.
- AI is a useful triage accelerant when scoped narrowly and kept under analyst control.

---

## Disclaimer

Built for learning on a self-contained lab using public sample data. AI-generated triage in this project is analyst-verified, not authoritative.
