"""
Ollama client with tool-calling support.

Keeps it minimal: one synchronous HTTP client, one Complete() call,
one structured ToolCall result. No streaming needed for a 2-turn loop.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any]


@dataclass
class CompletionResponse:
    text: str
    tool_call: ToolCall | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    elapsed_s: float = 0.0


@dataclass
class Tool:
    """Schema for a single tool exposed to the model."""
    name: str
    description: str
    parameters: dict[str, Any]          # JSON Schema object

    def to_ollama(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class OllamaClient:
    """
    Thin wrapper around Ollama's /api/chat endpoint.

    Handles:
    - Tool-call extraction from Ollama's native tool response
    - Fallback JSON extraction when the model returns tool-call JSON
      embedded in its text (common with smaller models)
    - Hard max_tokens cap to prevent runaway generation
    - Configurable timeout
    """

    def __init__(
        self,
        endpoint: str = "http://localhost:11435",
        model: str = "llama3.2:3b",
        timeout: float = 120.0,
        temperature: float = 0.1,
        max_tokens: int = 256,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.temperature = temperature
        self.max_tokens = max_tokens

    def complete(
        self,
        system: str,
        prompt: str,
        tools: list[Tool] | None = None,
    ) -> CompletionResponse:
        """
        Single-shot completion.

        Returns a CompletionResponse with either .text (plain answer)
        or .tool_call (structured tool invocation) populated.
        """
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens,
                "num_ctx": 8192,
            },
        }

        if tools:
            payload["tools"] = [t.to_ollama() for t in tools]

        t0 = time.monotonic()
        try:
            resp = httpx.post(
                f"{self.endpoint}/api/chat",
                json=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
        except httpx.TimeoutException as exc:
            raise LLMError(f"Ollama request timed out after {self.timeout}s") from exc
        except httpx.HTTPStatusError as exc:
            raise LLMError(f"Ollama HTTP {exc.response.status_code}: {exc.response.text[:200]}") from exc
        except httpx.RequestError as exc:
            raise LLMError(f"Ollama connection error: {exc}") from exc

        elapsed = time.monotonic() - t0
        data = resp.json()

        message = data.get("message", {})
        text = message.get("content", "")
        raw_tool_calls = message.get("tool_calls", [])

        # Token counts (Ollama reports these at top level)
        input_tokens = data.get("prompt_eval_count", 0)
        output_tokens = data.get("eval_count", 0)

        tool_call: ToolCall | None = None

        # --- Native tool_calls array (Ollama >= 0.3) ---
        if raw_tool_calls:
            first = raw_tool_calls[0]
            fn = first.get("function", {})
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            tool_call = ToolCall(name=fn.get("name", ""), arguments=args)

        # --- Fallback: model returned JSON in text (common with 3b models) ---
        elif text and tools:
            tool_call = _extract_tool_call_from_text(text, tools)

        return CompletionResponse(
            text=text,
            tool_call=tool_call,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            elapsed_s=elapsed,
        )

    def health_check(self) -> bool:
        """Return True if Ollama is reachable and the model is loaded."""
        try:
            resp = httpx.get(f"{self.endpoint}/api/tags", timeout=5.0)
            resp.raise_for_status()
            models = [m["name"] for m in resp.json().get("models", [])]
            # Accept prefix match so "llama3.2:3b" matches "llama3.2:3b-instruct" etc.
            return any(m.startswith(self.model.split(":")[0]) for m in models)
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_tool_call_from_text(text: str, tools: list[Tool]) -> ToolCall | None:
    """
    Some smaller Ollama models emit the tool call as JSON in the text body
    instead of in the structured tool_calls array.

    Try to find a JSON block that matches any known tool name.
    """
    # Strip markdown code fences if present
    clean = text.strip()
    if clean.startswith("```"):
        lines = clean.splitlines()
        clean = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

    tool_names = {t.name for t in tools}

    # Try to parse the whole thing as JSON
    for attempt in (clean, text):
        try:
            obj = json.loads(attempt)
            if isinstance(obj, dict):
                name = obj.get("name") or obj.get("function") or obj.get("tool")
                args = obj.get("arguments") or obj.get("parameters") or obj.get("args") or {}
                if name and name in tool_names:
                    return ToolCall(name=name, arguments=args if isinstance(args, dict) else {})
        except (json.JSONDecodeError, TypeError):
            pass

    # Try to find an embedded JSON object
    start = text.find("{")
    while start != -1:
        end = text.rfind("}", start)
        if end == -1:
            break
        try:
            obj = json.loads(text[start : end + 1])
            name = obj.get("name") or obj.get("function") or obj.get("tool")
            args = obj.get("arguments") or obj.get("parameters") or obj.get("args") or {}
            if name and name in tool_names:
                return ToolCall(name=name, arguments=args if isinstance(args, dict) else {})
        except (json.JSONDecodeError, TypeError):
            pass
        start = text.find("{", start + 1)

    return None


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class LLMError(Exception):
    """Raised when the LLM call fails in a non-retryable way."""
