"""Token accounting and deterministic context compaction."""

from __future__ import annotations

from .llm.base import Message
from .prompts import compaction_notice

#: English text is roughly 4 characters per token for the models we target.
CHARS_PER_TOKEN = 4


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // CHARS_PER_TOKEN)


def conversation_tokens(system: str, messages: list[Message]) -> int:
    return estimate_tokens(system) + sum(estimate_tokens(m.content) for m in messages)


def ensure_alternating(messages: list[Message]) -> list[Message]:
    """Merge consecutive same-role messages; some APIs reject them."""
    merged: list[Message] = []
    for message in messages:
        if not message.content.strip():
            continue
        if merged and merged[-1].role == message.role:
            merged[-1] = Message(message.role, merged[-1].content + "\n\n" + message.content)
        else:
            merged.append(Message(message.role, message.content))
    if merged and merged[0].role != "user":
        merged.insert(0, Message("user", "(continuing)"))
    return merged


def compact(
    messages: list[Message],
    memory,
    *,
    step: int,
    keep_recent: int = 6,
    budget_tokens: int,
    system: str,
) -> tuple[list[Message], bool]:
    """Drop the middle of the conversation, replacing it with a state summary.

    The engagement brief (message 0) and the most recent exchanges are preserved;
    everything in between is represented by the scratchpad summary, which is
    deterministic and therefore free to build.
    """
    if conversation_tokens(system, messages) <= budget_tokens:
        return messages, False

    head = messages[:1]
    tail = messages[-keep_recent:] if len(messages) > keep_recent + 1 else messages[1:]

    # Never start the kept window mid-tool-call: skip leading assistant messages.
    while tail and tail[0].role == "assistant":
        tail = tail[1:]
    if not tail:
        tail = messages[-2:]
        while tail and tail[0].role == "assistant":
            tail = tail[1:]

    summary = Message("user", compaction_notice(step, memory.summary()))
    candidate = ensure_alternating([*head, summary, *tail])

    # Still too big? Shrink the tail further.
    while conversation_tokens(system, candidate) > budget_tokens and len(candidate) > 3:
        candidate = ensure_alternating([head[0], summary, *candidate[2:]])
        if len(candidate) <= 4:
            break
    if conversation_tokens(system, candidate) > budget_tokens:
        # Last resort: keep only the brief, the summary, and a truncated version of it.
        budget_chars = max(2000, (budget_tokens - estimate_tokens(system) - 1000) * CHARS_PER_TOKEN)
        trimmed = Message("user", summary.content[:budget_chars])
        candidate = ensure_alternating([head[0], trimmed])
    return candidate, True
