"""
v14.0 — Multi-turn conversational assistant.

Extends ``intelligence.assistant.ask()`` (v14.1 alpha, single-turn) into
a stateful multi-turn conversation that can chain tool calls.

How it differs from v14.1's `ask()`
-----------------------------------

* `ask()` does one-shot: plan → call tools → summarize.
* `Conversation.send(msg)` keeps state across messages, can issue
  follow-up tool calls based on what previous turns surfaced, and
  honors a maximum turn depth so it can't loop forever.

The LLM is still constrained to "answer only from the tool outputs;
say 'I don't have enough data' otherwise." Multi-turn doesn't relax
that — it just lets the operator drill in.

Public API
----------

* ``Conversation(*, max_turns=8, model=None)``
* ``conv.send(user_text)`` → dict shaped like ``assistant.ask()`` but
  with an added ``turn`` field
* ``conv.history()`` → list of turn dicts
* ``conv.reset()``

Honest non-goals
----------------

* No tool-result caching across conversations (each call hits the live
  store; the assistant is read-mostly anyway).
* No long-term memory across conversations (one conversation = one
  in-process Conversation instance).
* No "agentic" multi-step planning where the LLM picks the next tool
  based on prior outputs at LLM-decided depth — that's v15+ work.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from safecadence.intelligence.assistant import ask


@dataclass
class Turn:
    role: str                 # "user" | "assistant"
    text: str
    at: float = field(default_factory=time.time)
    calls: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class Conversation:
    """One stateful conversation with the operator."""

    def __init__(
        self,
        *,
        max_turns: int = 8,
        max_tools_per_turn: int = 3,
        model: str | None = None,
    ) -> None:
        self.max_turns = max_turns
        self.max_tools_per_turn = max_tools_per_turn
        self.model = model
        self._turns: list[Turn] = []

    def reset(self) -> None:
        self._turns = []

    def history(self) -> list[dict]:
        return [
            {"role": t.role, "text": t.text, "at": t.at,
             "calls": t.calls, "warnings": t.warnings}
            for t in self._turns
        ]

    def send(self, user_text: str) -> dict:
        """Process one user message. Returns the assistant response dict
        shaped like ``ask()`` plus a ``turn`` index."""
        if len([t for t in self._turns if t.role == "user"]) >= self.max_turns:
            return {
                "question": user_text,
                "answer": (
                    "Maximum turn count reached for this conversation. "
                    "Start a new conversation or call reset()."
                ),
                "calls": [], "llm_used": False,
                "warnings": ["max_turns_reached"],
                "turn": len(self._turns),
            }

        # Build a question that includes the conversation context so the
        # assistant has the prior turns available when routing tools.
        question = self._compose_question(user_text)
        self._turns.append(Turn(role="user", text=user_text))

        result = ask(
            question, max_tools=self.max_tools_per_turn, model=self.model,
        )

        self._turns.append(Turn(
            role="assistant",
            text=result.get("answer", ""),
            calls=result.get("calls", []),
            warnings=result.get("warnings", []),
        ))

        result["turn"] = len(self._turns)
        return result

    def _compose_question(self, latest: str) -> str:
        if not self._turns:
            return latest
        # Tail the last few turns so prompt size stays bounded.
        tail = self._turns[-6:]
        ctx_lines: list[str] = ["Conversation so far:"]
        for t in tail:
            who = "OPERATOR" if t.role == "user" else "ASSISTANT"
            ctx_lines.append(f"{who}: {t.text}")
        ctx_lines.append(f"OPERATOR (current): {latest}")
        return "\n".join(ctx_lines)


__all__ = ["Conversation", "Turn"]
