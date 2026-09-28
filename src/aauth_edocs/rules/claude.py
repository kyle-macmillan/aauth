"""Claude adapter for ``LlmPolicyEnforcer``.

Requires the ``policy`` extra (``anthropic``). The request carries no tools,
so the model's only possible output is the schema-constrained verdict text.
"""

from __future__ import annotations

from typing import Any

DEFAULT_MODEL = "claude-sonnet-5"


class ClaudeCompletionModel:
    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        *,
        api_key: str | None = None,
        timeout: float = 30.0,
        max_tokens: int = 512,
        client: Any = None,
    ) -> None:
        if client is None:
            import anthropic

            client = anthropic.Anthropic(api_key=api_key, timeout=timeout, max_retries=1)
        self._client = client
        self._max_tokens = max_tokens
        self.model_id = model

    def complete(self, *, system: str, user: str, schema: dict[str, Any]) -> str:
        response = self._client.messages.create(
            model=self.model_id,
            max_tokens=self._max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
            output_config={"format": {"type": "json_schema", "schema": schema}},
        )
        if response.stop_reason != "end_turn":
            raise RuntimeError(f"policy model stopped with {response.stop_reason!r}")
        texts = [block.text for block in response.content if block.type == "text"]
        if len(texts) != 1:
            raise RuntimeError("policy model returned no single text block")
        return texts[0]
