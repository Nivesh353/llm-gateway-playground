# LLM Gateway Playground

A Streamlit page for sending prompts through opencontroller's LLM gateway with a virtual key, and seeing how the
gateway's routing rules and guardrails treat each one.

| | |
|---|---|
| Model picker | the key's chat models, live from the gateway (`GET /v1/models`), grouped by provider and vendor, with search |
| Samples | which model, a prompt with PII, a gateway question, a prompt injection, an exfiltration attempt |
| Route | Requested → LLM gateway → Answered by: routed, rerouted by a routing rule, blocked by a guardrail (HTTP 446), or refused by an LLM policy (HTTP 403) |
| Traces | optional: a root span per call to opencontroller's Observability intake, joined by the gateway's spans, with a link to open it |
| History | this session's earlier calls |

## Run

```sh
cp .env.example .env          # then fill in GATEWAY_URL and GATEWAY_VIRTUAL_KEY
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/streamlit run app.py   # http://localhost:8501
```

Tracing is on when `CONSOLE_URL` and `OBSERVABILITY_API_KEY` are set. The span it sends never carries the prompt or
the reply, since the prompt may hold the very personal data the gateway redacts.

An optional `models-checked.json` beside the app (`{"results": {"<model id>": {"ok": true}}}`) marks which models
answered an availability check; the picker then hides the ones that failed.

## Files

- `app.py`: the page
- `gateway.py`: the gateway's model list and chat calls, and the trace span
- `.env.example`: the settings, with no values

Every sample is made up: the names, card number and SSN are test data, and the credentials in the exfiltration
sample are fake, in AWS's documented example format.
