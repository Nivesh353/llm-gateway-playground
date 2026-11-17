"""The page's calls: the gateway's model list, chat, and the trace span.

Every chat goes to the LLM gateway with a virtual key and a W3C traceparent;
when an Observability key is set, a root span named "chat" is posted to
opencontroller's intake for the same trace, so the gateway's spans join it in
the project. The span never carries the prompt or the reply: the prompt may
hold the very PII the gateway redacts.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent


def _local(name: str) -> Path | None:
    """The app's own copy of a file, else the parent folder's: the app also runs
    from inside a larger project that keeps its .env one level up."""
    for path in (APP_DIR / name, APP_DIR.parent / name):
        if path.exists():
            return path
    return None


def load_env() -> None:
    """Reads KEY=value lines from .env into the environment, leaving set variables alone."""
    path = _local(".env")
    if path is None:
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


@dataclass
class Config:
    gateway: str
    virtual_key: str
    console: str
    obs_key: str
    project: str
    service: str
    only: list[str] = field(default_factory=list)

    @property
    def tracing(self) -> bool:
        return bool(self.console and self.obs_key)

    @property
    def traces(self) -> str | None:
        """Where a trace opens in opencontroller: <console>/observability/traces/<id>."""
        return f"{self.console}/observability/traces/" if self.tracing else None

    @property
    def gateway_host(self) -> str:
        return re.sub(r"^https?://", "", self.gateway).split("/")[0]


def config() -> Config:
    load_env()
    missing = [k for k in ("GATEWAY_URL", "GATEWAY_VIRTUAL_KEY") if not os.environ.get(k, "").strip()]
    if missing:
        raise RuntimeError(f"{', '.join(missing)} not set: copy .env.example to .env and fill it in")
    env = lambda k, d="": os.environ.get(k, d).strip()  # noqa: E731
    return Config(
        gateway=env("GATEWAY_URL").rstrip("/"),
        virtual_key=env("GATEWAY_VIRTUAL_KEY"),
        console=env("CONSOLE_URL").rstrip("/"),
        obs_key=env("OBSERVABILITY_API_KEY"),
        project=env("OBSERVABILITY_PROJECT", "LLM gateway playground"),
        service=env("SERVICE_NAME", "llm-gateway-playground"),
        only=[m.strip() for m in env("MODELS").split(",") if m.strip()],
    )


# --- models -------------------------------------------------------------------

# Not chat models, whatever their listing says.
NOT_CHAT = re.compile(
    r"(embed|rerank|canvas|image-|upscale|outpaint|inpaint|erase-object|remove-background|search-re|style-|"
    r"sketch|stable-|sonic|marengo|pegasus|voxtral)"
)
# Region-pinned copies of the same model (Bedrock's inference profiles for
# other regions) and the raw invoke route.
REGIONAL = re.compile(r"^(eu|apac|au|jp|global|us-gov(-east-1|-west-1)?)[./]|^invoke/")

VENDORS = {
    "amazon": "Amazon", "anthropic": "Anthropic", "meta": "Meta", "mistral": "Mistral AI", "openai": "OpenAI",
    "deepseek": "DeepSeek", "qwen": "Qwen", "google": "Google", "moonshot": "Moonshot AI",
    "moonshotai": "Moonshot AI", "zai": "Z.AI", "ai21": "AI21 Labs", "cohere": "Cohere", "minimax": "MiniMax",
    "nvidia": "NVIDIA", "writer": "Writer", "xai": "xAI", "twelvelabs": "TwelveLabs",
}
PROVIDERS = {"anthropic": "Anthropic", "bedrock": "AWS Bedrock", "openai": "OpenAI", "azure": "Azure OpenAI"}


def _vendor(provider: str, model: str, owned_by: str | None) -> str:
    if provider == "anthropic":
        return "Anthropic"
    # Bedrock ids name their vendor first, after any region prefix.
    parts = model.split(".")
    key = parts[1] if parts[0] == "us" and len(parts) > 1 else parts[0]
    return VENDORS.get(key) or (owned_by if owned_by and owned_by != "system" else key)


def _chats(m: dict) -> bool:
    model = "/".join(m["id"].split("/")[1:])
    if REGIONAL.search(model) or NOT_CHAT.search(model):
        return False
    out = (m.get("architecture") or {}).get("output_modalities")
    return not out or "TEXT" in out


def list_models(cfg: Config) -> list[dict]:
    """The chat models the key may call, as the gateway lists them, with what
    last availability check (models-checked.json) found for each, or None."""
    req = urllib.request.Request(f"{cfg.gateway}/v1/models", headers={"x-bf-vk": cfg.virtual_key})
    with urllib.request.urlopen(req, timeout=20) as res:
        body = json.load(res)
    checks = read_checks()
    results = (checks or {}).get("results", {})
    models = []
    for m in body.get("data") or []:
        if not _chats(m):
            continue
        provider, _, model = m["id"].partition("/")
        if cfg.only and m["id"] not in cfg.only:
            continue
        models.append({
            "id": m["id"],
            "name": m.get("name") or model,
            "provider": provider,
            "provider_name": PROVIDERS.get(provider, provider),
            "vendor": _vendor(provider, model, m.get("owned_by")),
            "context": m.get("context_length"),
            "deprecated": bool(m.get("is_deprecated")),
            "created": m.get("created") or 0,
            "check": results.get(m["id"]),
        })
    return models


def read_checks() -> dict | None:
    path = _local("models-checked.json")
    if path is None:
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


# --- chat -----------------------------------------------------------------------

def chat(cfg: Config, model: str, prompt: str) -> dict:
    trace_id, span_id = secrets.token_hex(16), secrets.token_hex(8)
    start = time.time_ns()
    status, body = 0, {}
    req = urllib.request.Request(
        f"{cfg.gateway}/v1/chat/completions",
        data=json.dumps({"model": model, "messages": [{"role": "user", "content": prompt}]}).encode(),
        headers={
            "content-type": "application/json",
            "x-bf-vk": cfg.virtual_key,
            "traceparent": f"00-{trace_id}-{span_id}-01",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as res:
            status, raw = res.status, res.read()
    except urllib.error.HTTPError as err:
        status, raw = err.code, err.read()
    except (urllib.error.URLError, TimeoutError) as err:
        raw = json.dumps({"error": {"message": f"the gateway did not answer: {err}"}}).encode()
    try:
        body = json.loads(raw or b"{}")
    except ValueError:
        body = {"error": {"message": raw[:500].decode(errors="replace")}}
    end = time.time_ns()

    ok = 200 <= status < 300
    error = body.get("error")
    result = {
        "status": status,
        "requested": model,
        "answered": _answered_by(body) if ok else None,
        "reply": ((body.get("choices") or [{}])[0].get("message") or {}).get("content") if ok else None,
        # 446 is the gateway's status for content its guardrail blocked.
        "blocked": status == 446,
        # A 403 of this type is an LLM policy refusing the model or provider.
        "denied": status == 403 and isinstance(error, dict) and error.get("type") == "llm_policy_denied",
        "error": None if ok else _error_of(body, status),
        "latency_ms": (end - start) // 1_000_000,
        "trace_id": trace_id,
        "trace": "off",
    }
    if cfg.tracing:
        result["trace"] = _send_span(cfg, trace_id, span_id, start, end, model, result)
    return result


def _answered_by(body: dict) -> str | None:
    x = body.get("extra_fields") or {}
    r = x.get("routing_info") or {}
    provider = r.get("provider") or x.get("provider")
    model = r.get("model") or x.get("resolved_model_used") or body.get("model")
    if not model:
        return None
    return f"{provider}/{model}" if provider and not model.startswith(f"{provider}/") else model


def _error_of(body: dict, status: int) -> str:
    e = body.get("error")
    msg = e if isinstance(e, str) else (e or {}).get("message") or body.get("message")
    return msg or f"the gateway answered {status}"


def _send_span(cfg: Config, trace_id: str, span_id: str, start: int, end: int, model: str, result: dict) -> str:
    def attr(key: str, value) -> dict:
        if isinstance(value, int) and not isinstance(value, bool):
            return {"key": key, "value": {"intValue": str(value)}}
        return {"key": key, "value": {"stringValue": str(value)}}

    attributes = [
        attr("openinference.span.kind", "CHAIN"),
        attr("demo.model.requested", model),
        attr("http.response.status_code", result["status"]),
    ]
    if result["answered"]:
        attributes.append(attr("demo.model.answered", result["answered"]))
    if result["blocked"]:
        attributes.append(attr("demo.guardrail.blocked", "true"))
    if result["denied"]:
        attributes.append(attr("demo.policy.denied", "true"))
    failed = result["error"] and not result["blocked"] and not result["denied"]
    payload = {"resourceSpans": [{
        "resource": {"attributes": [attr("service.name", cfg.service)]},
        "scopeSpans": [{"scope": {"name": cfg.service}, "spans": [{
            "traceId": trace_id,
            "spanId": span_id,
            "name": "chat",
            "kind": 2,  # SERVER
            "startTimeUnixNano": str(start),
            "endTimeUnixNano": str(end),
            "attributes": attributes,
            "status": {"code": 2, "message": result["error"]} if failed else {"code": 1},
        }]}],
    }]}
    req = urllib.request.Request(
        f"{cfg.console}/otlp/v1/traces",
        data=json.dumps(payload).encode(),
        headers={"content-type": "application/json", "x-api-key": cfg.obs_key, "x-project": cfg.project},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10):
            return "sent"
    except urllib.error.HTTPError as err:
        return f"not sent: the intake answered {err.code}"
    except (urllib.error.URLError, TimeoutError):
        return "not sent: the intake did not answer"
