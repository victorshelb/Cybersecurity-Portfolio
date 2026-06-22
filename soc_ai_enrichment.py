#!/usr/bin/env python3
"""
soc_ai_enrichment.py  --  AI-assisted triage for Splunk detection alerts.

WHAT IT DOES
  Reads detection results exported from Splunk (JSON or JSONL), sends them to an
  LLM for a plain-language triage summary + MITRE ATT&CK mapping + next steps,
  prints the result, and (optionally) writes it back into Splunk via HEC.

DESIGN PRINCIPLE
  The analyst owns detection logic and the final decision. The LLM only produces
  a first-pass triage summary to speed up the human. AI assists; it does not decide.

USAGE
  1. Export your detection's results from Splunk Web: run the search, click
     Export, choose JSON, save as alert_results.json next to this script.
  2. Set your API key:           export ANTHROPIC_API_KEY=sk-ant-...
  3. (optional) set a HEC token:  export SPLUNK_HEC_TOKEN=xxxxxxxx-xxxx-...
  4. Run:                         python3 soc_ai_enrichment.py alert_results.json

Uses only the Python standard library -- nothing to pip install.
"""

import json
import os
import ssl
import sys
import urllib.error
import urllib.request

# ---- Configuration (read from environment, never hard-code keys) ----
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN")          # optional write-back
HEC_URL = "https://localhost:8088/services/collector/event"
MODEL = "claude-sonnet-4-6"                              # current Anthropic model string
RESULTS_FILE = sys.argv[1] if len(sys.argv) > 1 else "alert_results.json"
MAX_EVENTS = 5                                           # cap events sent to the LLM


def load_events(path):
    """Handles both a single JSON array and JSONL (one object per line)."""
    with open(path) as f:
        text = f.read().strip()
    try:
        data = json.loads(text)
        rows = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    return [row.get("result", row) for row in rows]


def build_prompt(events):
    sample = json.dumps(events[:MAX_EVENTS], indent=2)
    return (
        "You are a SOC analyst assistant. A detection alert has fired with the "
        "events below. Respond with:\n"
        "1. A plain-language summary of what likely happened (2-3 sentences).\n"
        "2. The most relevant MITRE ATT&CK technique ID(s) and name(s).\n"
        "3. Three concrete next investigation steps.\n\n"
        "Be concise. The human analyst makes the final call.\n\n"
        f"Events:\n{sample}"
    )


def call_anthropic(prompt):
    """Call the Anthropic Messages API. Swap this function out to use a different
    provider, or a local model via Ollama (see note at the bottom of this file)."""
    body = json.dumps({
        "model": MODEL,
        "max_tokens": 700,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        headers={
            "x-api-key": ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
    )
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read())
    return "".join(block.get("text", "") for block in data.get("content", []))


def send_to_splunk(summary):
    """Optional: write the AI triage back into Splunk via HEC (port 8088)."""
    if not HEC_TOKEN:
        print("\n(No SPLUNK_HEC_TOKEN set -- skipping write-back to Splunk.)")
        return
    body = json.dumps({
        "event": {"source": "ai_enrichment", "ai_triage": summary},
        "sourcetype": "ai:triage",
    }).encode()
    # Local Splunk in Docker uses a self-signed cert, so verification is disabled
    # here. Acceptable for localhost only -- never disable it against a real server.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        HEC_URL, data=body,
        headers={"Authorization": f"Splunk {HEC_TOKEN}", "content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            print(f"\nSent enrichment back to Splunk via HEC (HTTP {resp.status}).")
            print('Find it in Splunk with:  index=main sourcetype="ai:triage"')
    except urllib.error.URLError as e:
        print(f"\nHEC write-back failed (optional step): {e}")


def main():
    if not ANTHROPIC_API_KEY:
        sys.exit("Set your key first:  export ANTHROPIC_API_KEY=sk-ant-...")
    if not os.path.exists(RESULTS_FILE):
        sys.exit(f"Results file not found: {RESULTS_FILE}\n"
                 "Export your search from Splunk Web as JSON first.")
    events = load_events(RESULTS_FILE)
    if not events:
        sys.exit(f"No events found in {RESULTS_FILE}")
    print(f"Loaded {len(events)} event(s) from {RESULTS_FILE}. "
          f"Sending the first {min(len(events), MAX_EVENTS)} to the model...\n")
    summary = call_anthropic(build_prompt(events))
    print("=== AI triage summary (analyst to verify) ===\n")
    print(summary)
    send_to_splunk(summary)


if __name__ == "__main__":
    main()

# ----------------------------------------------------------------------------
# FREE LOCAL ALTERNATIVE (no API key, no cost):
#   1. Install Ollama (ollama.com) and run:  ollama pull llama3.1
#   2. Replace call_anthropic() with a POST to http://localhost:11434/api/generate
#      sending {"model": "llama3.1", "prompt": prompt, "stream": false} and read
#      the "response" field from the JSON reply.
# Everything else (export -> enrich -> HEC write-back) stays the same.
# ----------------------------------------------------------------------------
