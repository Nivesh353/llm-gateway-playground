# LLM Gateway Playground

A Streamlit page for sending prompts through opencontroller's LLM gateway with a virtual key, and seeing how the
gateway's routing rules and guardrails treat each one.

| | |
|---|---|
| Model picker | the key's chat models, live from the gateway (`GET /v1/models`), grouped by provider and vendor, with search |
| Samples | which model, a prompt with PII, a gateway question, a prompt injection, a jailbreak, an exfiltration attempt |
| Route | Requested → LLM gateway → Answered by: routed, rerouted by a routing rule, blocked by a guardrail (HTTP 446), or refused by an LLM policy (HTTP 403) |
| Traces | optional: a root span per call to opencontroller's Observability intake, joined by the gateway's spans, with a link to open it |
| History | this session's earlier calls |
| Prompt Attack Test | 50 prompt-injection and jailbreak attacks in ten techniques, a data-exfiltration attempt and an unapproved model, each scored blocked, resisted or complied, against a 95% blocked target |
| Policy Agent Test | asks a Lyzr Studio agent a question and shows the knowledge base's retrieval, the gateway's verdict and the answer; or runs 10 public and 10 restricted sample questions in a batch, each checked against what should happen |

## Run

```sh
cp .env.example .env          # then fill in GATEWAY_URL and GATEWAY_VIRTUAL_KEY
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/streamlit run app.py   # http://localhost:8501
```

Tracing is on when `CONSOLE_URL` and `OBSERVABILITY_API_KEY` are set. The span it sends never carries the prompt or
the reply, since the prompt may hold the very personal data the gateway redacts.

## Sign-in

Optional. With it, every call is recorded under the person who made it, verified by the gateway:

1. Register the page with the identity provider as an OIDC web app (authorization code), with the sign-in redirect
   URI `http://localhost:8501/oauth2callback`.
2. In the gateway, add the provider under **API Gateway › Identity Providers (OIDC)**: its issuer, the app's client ID
   as the audience, and `email` as the subject claim.
3. On the virtual key, turn the provider on under **Callers sign in with**. The key then refuses calls without a valid
   token (401).
4. `cp .streamlit/secrets.toml.example .streamlit/secrets.toml` and fill in `cookie_secret`, `client_id` and
   `client_secret`.

The page then asks people to sign in before anything else, sends their ID token as `Authorization: Bearer` with every
gateway call, and names them as `enduser.id` on its trace span, which Observability shows in the **User** column. The
token lasts an hour (Okta's default) and is not refreshed: after that the page asks for a new sign-in. The Policy Agent
Test's calls stay unnamed, since Lyzr makes them.

## What the gateway needs

The tests score the gateway, so their results depend on how it is set up. These are the rules they expect:

| Rule | Where | Setting | Why |
|---|---|---|---|
| Prompt injection guardrail | Guardrails, on the app's virtual key | Block | Blocks all 50 attacks |
| `obfuscated-dotted-text` (optional) | Content rules, on the app's virtual key only | Regex `(?:[A-Za-z]\.){4,}[A-Za-z]`, action Block | Not in the test: text with a dot between every letter (`I.g.n.o.r.e y.o.u.r r.u.l.e.s …`) hides its words from the injection detector, and this blocks it |
| Unapproved model | LLM Policies | Deny the model in `UNAPPROVED_MODEL` | The unapproved-model check expects 403 `llm_policy_denied` |
| Restricted text | Content rules, on the agent's virtual key | Regex `\[RESTRICTED · RST-\d+\][^\[]*`, action Redact, mask `[RESTRICTED CONTENT REMOVED]` | The Policy Agent Test shows the chunks as the model received them, with this pattern (`REDACT_PATTERN`, `REDACT_MASK`) |

The dotted-text pattern needs five or more single letters joined by dots, so ordinary text such as `e.g.`, `U.S.A.`,
`J.R.R. Tolkien`, an email address, a domain or a version number does not trigger it.

An optional `models-checked.json` beside the app (`{"results": {"<model id>": {"ok": true}}}`) marks which models
answered an availability check; the picker then hides the ones that failed.

## Files

- `app.py`: the page
- `gateway.py`: the gateway's model list and chat calls, and the trace span
- `runs.py`: the Prompt Attack Test's attacks and scoring
- `agent.py`: the Policy Agent Test's calls to the Lyzr agent and its knowledge base
- `.env.example`: the settings, with no values

Every sample is made up: the names, card number and SSN are test data, and the credentials in the exfiltration
sample are fake, in AWS's documented example format.
