from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx


PROVIDERS: dict[str, dict[str, Any]] = {
    "openai": {
        "label": "OpenAI",
        "endpoint": "https://api.openai.com/v1/responses",
        "default_model": "gpt-5.5",
        "env_keys": ("OPENAI_API_KEY",),
    },
    "grok": {
        "label": "Grok",
        "endpoint": "https://api.x.ai/v1/chat/completions",
        "default_model": "grok-4.3",
        "env_keys": ("XAI_API_KEY", "GROK_API_KEY"),
    },
    "claude": {
        "label": "Claude",
        "endpoint": "https://api.anthropic.com/v1/messages",
        "default_model": "claude-sonnet-4-5",
        "env_keys": ("ANTHROPIC_API_KEY",),
    },
}


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name, "").strip()
    if not value:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {value!r}") from exc


REQUEST_TIMEOUT_SECONDS = _env_int("SECURITY_RECIPES_CHAT_TIMEOUT_SECONDS", 90)
MAX_BODY_BYTES = _env_int("SECURITY_RECIPES_CHAT_MAX_BODY_BYTES", 262_144)
MAX_HISTORY_MESSAGES = _env_int("SECURITY_RECIPES_CHAT_MAX_HISTORY_MESSAGES", 12)
MAX_SYSTEM_CHARS = _env_int("SECURITY_RECIPES_CHAT_MAX_SYSTEM_CHARS", 40_000)
MAX_MESSAGE_CHARS = _env_int("SECURITY_RECIPES_CHAT_MAX_MESSAGE_CHARS", 20_000)
MAX_OUTPUT_TOKENS = _env_int("SECURITY_RECIPES_CHAT_MAX_OUTPUT_TOKENS", 1400)
HOST = os.environ.get("SECURITY_RECIPES_CHAT_HOST", "0.0.0.0")
PORT = _env_int("SECURITY_RECIPES_CHAT_PORT", 8000)


def _provider_key(provider: str) -> str:
    for env_key in PROVIDERS[provider]["env_keys"]:
        value = os.environ.get(env_key, "").strip()
        if value:
            return value
    return ""


def _configured_providers() -> list[str]:
    return [provider for provider in PROVIDERS if _provider_key(provider)]


def _text(value: Any, limit: int) -> str:
    text = str(value or "").strip()
    return text[:limit]


def _history(messages: Any) -> list[dict[str, str]]:
    if not isinstance(messages, list):
        return []
    normalized: list[dict[str, str]] = []
    for item in messages[-MAX_HISTORY_MESSAGES:]:
        if not isinstance(item, dict):
            continue
        role = item.get("role")
        content = _text(item.get("content"), MAX_MESSAGE_CHARS)
        if role not in {"user", "assistant"} or not content:
            continue
        normalized.append({"role": role, "content": content})
    return normalized


def _transcript(messages: list[dict[str, str]]) -> str:
    lines = []
    for item in messages:
        speaker = "Assistant" if item["role"] == "assistant" else "User"
        lines.append(f"{speaker}: {item['content']}")
    return "\n\n".join(lines)


def _provider_error(response: httpx.Response) -> str:
    detail = response.text[:2000]
    try:
        data = response.json()
    except ValueError:
        return detail or response.reason_phrase
    error = data.get("error") if isinstance(data, dict) else None
    if isinstance(error, dict):
        return str(error.get("message") or error.get("type") or detail or response.reason_phrase)
    if isinstance(error, str):
        return error
    return detail or response.reason_phrase


def _extract_openai(data: Any) -> str:
    if isinstance(data, dict) and isinstance(data.get("output_text"), str) and data["output_text"].strip():
        return data["output_text"].strip()
    chunks: list[str] = []
    for item in data.get("output", []) if isinstance(data, dict) else []:
        if not isinstance(item, dict):
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for part in content:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                chunks.append(part["text"])
    return "\n".join(chunks).strip() or "The OpenAI response did not include text output."


def _extract_chat_completion(data: Any) -> str:
    choices = data.get("choices") if isinstance(data, dict) else None
    choice = choices[0] if isinstance(choices, list) and choices else None
    message = choice.get("message") if isinstance(choice, dict) else None
    if not isinstance(message, dict):
        return "The chat completion response did not include a message."
    content = message.get("content")
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        return "\n".join(str(part.get("text") or part.get("content") or "") for part in content if isinstance(part, dict)).strip()
    return "The chat completion response did not include text content."


def _extract_claude(data: Any) -> str:
    content = data.get("content") if isinstance(data, dict) else None
    if not isinstance(content, list):
        return "The Claude response did not include content."
    chunks = [
        part["text"]
        for part in content
        if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str)
    ]
    return "\n".join(chunks).strip() or "The Claude response did not include text content."


def _call_provider(provider: str, model: str, system: str, history: list[dict[str, str]]) -> dict[str, Any]:
    api_key = _provider_key(provider)
    if not api_key:
        raise RuntimeError(
            f"{PROVIDERS[provider]['label']} is not configured on this server. "
            f"Set one of: {', '.join(PROVIDERS[provider]['env_keys'])}."
        )

    timeout = httpx.Timeout(REQUEST_TIMEOUT_SECONDS)
    with httpx.Client(timeout=timeout) as client:
        if provider == "openai":
            response = client.post(
                PROVIDERS[provider]["endpoint"],
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "instructions": system,
                    "input": _transcript(history),
                    "max_output_tokens": MAX_OUTPUT_TOKENS,
                },
            )
            if response.status_code >= 400:
                raise ProviderHTTPError(response.status_code, _provider_error(response))
            return {"text": _extract_openai(response.json())}

        if provider == "grok":
            response = client.post(
                PROVIDERS[provider]["endpoint"],
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "stream": False,
                    "max_tokens": MAX_OUTPUT_TOKENS,
                    "messages": [{"role": "system", "content": system}] + history,
                },
            )
            if response.status_code >= 400:
                raise ProviderHTTPError(response.status_code, _provider_error(response))
            return {"text": _extract_chat_completion(response.json())}

        response = client.post(
            PROVIDERS[provider]["endpoint"],
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": MAX_OUTPUT_TOKENS,
                "system": system,
                "messages": history,
            },
        )
        if response.status_code >= 400:
            raise ProviderHTTPError(response.status_code, _provider_error(response))
        return {"text": _extract_claude(response.json())}


class ProviderHTTPError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


class ChatHandler(BaseHTTPRequestHandler):
    server_version = "security-recipes-chat/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        if os.environ.get("SECURITY_RECIPES_CHAT_ACCESS_LOG", "").lower() in {"1", "true", "yes"}:
            super().log_message(fmt, *args)

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            self._send_json(200, {"ok": True, "configured_providers": _configured_providers()})
            return
        if parsed.path == "/api/chat/health":
            provider = parse_qs(parsed.query).get("provider", ["openai"])[0]
            if provider not in PROVIDERS:
                self._send_json(400, {"ok": False, "error": "Unsupported provider."})
                return
            self._send_json(
                200,
                {
                    "ok": True,
                    "provider": provider,
                    "provider_label": PROVIDERS[provider]["label"],
                    "configured": bool(_provider_key(provider)),
                    "configured_providers": _configured_providers(),
                },
            )
            return
        self._send_json(404, {"ok": False, "error": "Not found."})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/api/chat":
            self._send_json(404, {"ok": False, "error": "Not found."})
            return

        try:
            content_length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            self._send_json(400, {"ok": False, "error": "Invalid Content-Length."})
            return
        if content_length <= 0:
            self._send_json(400, {"ok": False, "error": "Request body is required."})
            return
        if content_length > MAX_BODY_BYTES:
            self._send_json(413, {"ok": False, "error": "Request body is too large."})
            return

        try:
            payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"ok": False, "error": "Request body must be JSON."})
            return
        if not isinstance(payload, dict):
            self._send_json(400, {"ok": False, "error": "Request body must be a JSON object."})
            return

        provider = _text(payload.get("provider"), 40) or os.environ.get("SECURITY_RECIPES_CHAT_DEFAULT_PROVIDER", "openai")
        if provider not in PROVIDERS:
            self._send_json(400, {"ok": False, "error": "Unsupported provider."})
            return

        model = _text(payload.get("model"), 120) or PROVIDERS[provider]["default_model"]
        system = _text(payload.get("system"), MAX_SYSTEM_CHARS)
        history = _history(payload.get("history"))
        if not system:
            self._send_json(400, {"ok": False, "error": "System instructions are required."})
            return
        if not history:
            self._send_json(400, {"ok": False, "error": "At least one chat message is required."})
            return

        try:
            result = _call_provider(provider, model, system, history)
        except ProviderHTTPError as exc:
            self._send_json(exc.status, {"ok": False, "provider": provider, "error": exc.detail})
            return
        except (httpx.HTTPError, RuntimeError) as exc:
            self._send_json(502, {"ok": False, "provider": provider, "error": str(exc)})
            return

        self._send_json(
            200,
            {
                "ok": True,
                "provider": provider,
                "provider_label": PROVIDERS[provider]["label"],
                "model": model,
                "text": result["text"],
            },
        )


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), ChatHandler)
    print(f"security-recipes chat server listening on {HOST}:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
