"""Context accounting and compaction."""

from __future__ import annotations

from redloop.context import (
    compact,
    conversation_tokens,
    ensure_alternating,
    estimate_tokens,
)
from redloop.llm.base import Message
from redloop.memory import Memory

SYSTEM = "system prompt " * 100


def test_estimate_tokens_is_roughly_chars_over_four():
    assert estimate_tokens("a" * 400) == 100
    assert estimate_tokens("") == 1


def test_conversation_tokens_includes_system():
    messages = [Message("user", "x" * 400)]
    assert conversation_tokens(SYSTEM, messages) > 400


def test_ensure_alternating_merges_same_role():
    messages = [Message("user", "a"), Message("user", "b"), Message("assistant", "c")]
    merged = ensure_alternating(messages)
    assert [m.role for m in merged] == ["user", "assistant"]
    assert merged[0].content == "a\n\nb"


def test_ensure_alternating_drops_empty_and_starts_with_user():
    messages = [Message("assistant", "hello"), Message("user", "   "), Message("user", "hi")]
    merged = ensure_alternating(messages)
    assert merged[0].role == "user"


def test_compaction_is_a_noop_below_budget():
    messages = [Message("user", "brief"), Message("assistant", "a"), Message("user", "b")]
    result, changed = compact(messages, Memory(), step=1, budget_tokens=100_000, system=SYSTEM)
    assert not changed
    assert result == messages


def test_compaction_keeps_brief_and_recent_and_adds_summary():
    memory = Memory()
    memory.add_flag("flag{kept}", step=2)
    memory.add_note("important context", step=3)
    messages = [Message("user", "THE BRIEF")]
    for index in range(40):
        messages.append(Message("assistant", f"assistant {index} " + "x" * 400))
        messages.append(Message("user", f"observation {index} " + "y" * 400))

    result, changed = compact(messages, memory, step=40, budget_tokens=3000, system=SYSTEM)
    assert changed
    assert len(result) < len(messages)
    assert result[0].content.startswith("THE BRIEF")
    combined = "\n".join(m.content for m in result)
    assert "HISTORY COMPACTED" in combined
    assert "flag{kept}" in combined
    assert "important context" in combined
    assert [m.role for m in result] == ["user"] + [m.role for m in result[1:]]
    # The result must actually fit the budget we asked for.
    assert conversation_tokens(SYSTEM, result) <= 3000


def test_compaction_never_starts_with_an_assistant_message():
    messages = [Message("user", "brief")]
    for index in range(20):
        messages.append(Message("assistant", f"a{index} " + "x" * 200))
        messages.append(Message("user", f"o{index} " + "y" * 200))
    result, _ = compact(messages, Memory(), step=20, budget_tokens=2000, system=SYSTEM)
    roles = [m.role for m in result]
    assert roles[0] == "user"
    # Roles must strictly alternate for providers that require it.
    assert all(a != b for a, b in zip(roles, roles[1:], strict=False))


def test_compaction_handles_a_tiny_budget():
    messages = [Message("user", "brief"), Message("assistant", "x" * 5000),
                Message("user", "y" * 5000)]
    result, changed = compact(messages, Memory(), step=1, budget_tokens=1500, system="sys")
    assert changed
    assert result
