"""The autonomous loop.

One iteration is: ask the model for the next action, parse it, execute exactly one
tool, feed the observation back, and emit events as we go.  Everything the model
sees about the world arrives through this loop, which is what keeps a long run
coherent: the brief, the observation and the state block are the only inputs.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import Config
from .context import compact, conversation_tokens, ensure_alternating, estimate_tokens
from .events import EventBus
from .llm.base import AuthError, ContextOverflowError, LLMClient, LLMError, Message, Usage
from .memory import Finding, Flag, Memory, detect_flags
from .prompts import (
    build_brief,
    format_observation,
    nudge_parse_error,
    nudge_repeat,
    nudge_unknown_tool,
    state_block,
    system_prompt,
)
from .protocol import parse_action
from .render import action_preview, fmt_elapsed
from .safety import ScopeGuard
from .tools import ToolContext, ToolResult, build_registry, tool_help

#: Stop if this many actions in a row produce nothing useful.
MAX_STUCK = 8


@dataclass
class RunResult:
    status: str = "exhausted"
    reason: str = ""
    steps: int = 0
    flags: list[Flag] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    cost_usd: float = 0.0
    duration: float = 0.0
    report_path: str = ""
    run_dir: str = ""


class Agent:
    def __init__(
        self,
        config: Config,
        bus: EventBus,
        *,
        client: LLMClient | None = None,
        registry: dict | None = None,
        guard: ScopeGuard | None = None,
        memory: Memory | None = None,
        run_dir: Path | None = None,
    ) -> None:
        self.config = config
        self.bus = bus
        self.client = client
        self.registry = registry or build_registry()
        self.guard = guard or ScopeGuard(
            target=config.target,
            scope=config.scope,
            enabled=config.scope_check,
            allow_private=config.allow_private_networks,
            allow_loopback=config.allow_loopback,
        )
        self.memory = memory or Memory()
        self.run_dir = Path(run_dir or config.runs_dir).expanduser().resolve()
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.system = system_prompt(tool_help(self.registry))

        self.step = 0
        self.usage = Usage()
        self.cost = 0.0
        self.started = time.monotonic()
        self.stuck_steps = 0
        self._signatures: dict[str, int] = {}
        self._recent: list[str] = []
        self._compactions = 0
        self._finalized = False
        self.result = RunResult()
        self.stop_requested = False

    # ------------------------------------------------------------------ api
    async def run(self) -> RunResult:
        status = "exhausted"
        reason = ""
        self.bus.emit(
            "session_start",
            target=self.config.target,
            objective=self.config.objective,
            scope=self.guard.describe(),
            provider=self.config.provider,
            model=self.config.effective_model,
            max_steps=self.config.max_steps,
            max_minutes=self.config.max_minutes,
            max_cost_usd=self.config.max_cost_usd,
            run_dir=str(self.run_dir),
            dry_run=self.config.dry_run,
        )
        # The brief carries no state: a fresh state block is appended per call.
        messages: list[Message] = [Message("user", build_brief(self.config))]
        try:
            for step in range(1, self.config.max_steps + 1):
                self.step = step
                early = self._limit_reason()
                if early:
                    status, reason = early
                    break
                self.bus.emit(
                    "step_start",
                    step=step,
                    max_steps=self.config.max_steps,
                    elapsed=self.elapsed,
                    tokens=self.usage.total,
                    cost_usd=self.cost,
                    findings=len(self.memory.findings),
                )
                # The state block is rebuilt for every call and sent as the final
                # user message. History itself stays clean, so compaction only has
                # to manage observations.
                state = self._state_text(compacted=False)
                messages, compacted = self._maybe_compact(
                    messages, extra_tokens=estimate_tokens(state)
                )
                if compacted:
                    self.bus.emit(
                        "compaction",
                        removed=compacted[0],
                        tokens=compacted[1],
                        step=step,
                    )
                    state = self._state_text(compacted=True)

                request = ensure_alternating([*messages, Message("user", state)])
                completion, auth_failure = await self._ask(request)
                if completion is None:
                    status, reason = "error", auth_failure or "the model could not be reached"
                    break

                self._track(completion)
                parsed = parse_action(completion.text)
                messages.append(Message("assistant", completion.text.strip()))

                if not parsed.ok:
                    self.bus.emit("thought", text=parsed.thought, step=step)
                    self.bus.emit("warning", message=_short(parsed.error or "unparseable reply"))
                    messages.append(Message("user", nudge_parse_error(str(parsed.error))))
                    await self._save_every_step()
                    continue

                action = parsed.action
                self.bus.emit("thought", text=parsed.thought, step=step)

                tool = self.registry.get(action.tool)
                if tool is None:
                    self.bus.emit(
                        "warning",
                        message=f"model called an unknown tool: {action.tool}",
                    )
                    messages.append(
                        Message("user", nudge_unknown_tool(action.tool, list(self.registry)))
                    )
                    await self._save_every_step()
                    continue

                signature = _signature(action.tool, action.args)
                if self._is_repeat(signature):
                    preview = action_preview(action.tool, action.args)
                    self.bus.emit(
                        "warning", message=f"repeated action suppressed: {preview[:90]}"
                    )
                    messages.append(Message("user", nudge_repeat(action.tool, preview[:200])))
                    self.memory.record_attempt(f"REPEAT (suppressed): {preview}")
                    self.stuck_steps += 1
                    await self._save_every_step()
                    continue

                self._signatures[signature] = self._signatures.get(signature, 0) + 1
                self._recent.append(signature)
                del self._recent[:-20]
                preview = action_preview(action.tool, action.args)
                self.bus.emit(
                    "action",
                    tool=action.tool,
                    args=action.args,
                    preview=preview,
                    spinner=tool.long_running,
                    step=step,
                )
                self.memory.record_attempt(f"{action.tool}: {preview}")

                result = await self._execute(tool, action.args)
                self.bus.emit(
                    "observation",
                    step=step,
                    tool=action.tool,
                    ok=result.ok,
                    blocked=result.blocked,
                    output=result.output,
                    duration=result.duration,
                    meta=result.meta,
                )
                if result.blocked:
                    self.bus.emit("blocked", reason=result.meta.get("guardrail", "out of scope"))
                self._learn(result)
                self._update_stuck(result)

                if result.meta.get("control") == "flag":
                    status = "flag"
                    reason = "the agent submitted a flag"
                    messages.append(
                        Message("user", format_observation(
                            result, tool=action.tool, step=step,
                            max_chars=self.config.max_output_chars,
                        ))
                    )
                    break
                if result.meta.get("control") == "give_up":
                    status = "completed"
                    reason = str(result.meta.get("reason", "the agent stopped"))
                    break
                if self.config.stop_on_flag and self.memory.flags:
                    status = "flag"
                    reason = "flag observed in tool output"
                    break

                observation = format_observation(
                    result, tool=action.tool, step=step, max_chars=self.config.max_output_chars
                )
                messages.append(Message("user", observation))
                if self.config.dry_run:
                    status = "completed"
                    reason = "dry run: one action planned, nothing executed"
                    break
                await self._save_every_step()
            else:
                status = "exhausted"
                reason = f"step budget of {self.config.max_steps} exhausted"

            early = self._limit_reason()
            if early and status in ("exhausted", "completed"):
                status, reason = early
        except asyncio.CancelledError:
            status, reason = "interrupted", "run cancelled"
            raise
        except KeyboardInterrupt:  # pragma: no cover - handled in the CLI
            status, reason = "interrupted", "operator interrupted the run"
        except Exception as exc:  # pragma: no cover - unexpected
            status, reason = "error", f"{type(exc).__name__}: {exc}"
            self.bus.emit("error", message=reason)
        finally:
            self._finalize(status, reason)
        return self.result

    # --------------------------------------------------------------- model
    async def _ask(self, messages: list[Message]) -> tuple[Any, str]:
        """Call the model, handling context overflow by compacting harder."""
        assert self.client is not None
        try:
            return await self.client.complete(
                self.system,
                messages,
                max_tokens=self.config.max_tokens,
                temperature=self.config.temperature,
            ), ""
        except ContextOverflowError:
            self.bus.emit("warning", message="context window exceeded; compacting and retrying")
            budget = max(1000, int(self.config.token_budget * 0.4))
            shrunk, _ = compact(
                messages,
                self.memory,
                step=self.step,
                keep_recent=4,
                budget_tokens=budget,
                system=self.system,
            )
            messages[:] = shrunk
            try:
                return await self.client.complete(
                    self.system,
                    messages,
                    max_tokens=self.config.max_tokens,
                    temperature=self.config.temperature,
                ), ""
            except LLMError as retry_exc:
                self.bus.emit("error", message=str(retry_exc))
                return None, str(retry_exc)
        except AuthError as exc:
            self.bus.emit("error", message=str(exc))
            return None, str(exc)
        except LLMError as exc:
            self.bus.emit("error", message=str(exc))
            return None, f"model call failed: {exc}"
        except Exception as exc:  # pragma: no cover - defensive
            message = f"{type(exc).__name__}: {exc}"
            self.bus.emit("error", message=message)
            return None, message

    def _track(self, completion: Any) -> None:
        usage = getattr(completion, "usage", Usage())
        self.usage += usage
        self.cost += self.config.cost_of(usage.input_tokens, usage.output_tokens)

    # ---------------------------------------------------------------- tools
    async def _execute(self, tool, args: dict[str, Any]) -> ToolResult:
        ctx = ToolContext(
            config=self.config,
            guard=self.guard,
            memory=self.memory,
            run_dir=self.run_dir,
            step=self.step,
            emit=lambda type_, **data: self.bus.emit(type_, **data),
        )
        try:
            return await tool.execute(args, ctx)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover - a tool bug must not end the run
            message = f"tool {tool.name} crashed: {type(exc).__name__}: {exc}"
            self.bus.emit("error", message=message)
            return ToolResult(False, message)

    def _learn(self, result: ToolResult) -> None:
        """Pull facts and flags out of every observation."""
        text = result.output or ""
        self.memory.ingest_facts(text)
        for value in detect_flags(text, self.config.flag_patterns()):
            record = self.memory.add_flag(
                value, source="captured from tool output", step=self.step
            )
            if record:
                self.bus.emit("flag", flag=record)

    def _update_stuck(self, result: ToolResult) -> None:
        productive = result.ok and len((result.output or "").strip()) >= 20
        if result.blocked or not productive:
            self.stuck_steps += 1
        else:
            self.stuck_steps = 0

    # -------------------------------------------------------------- context
    def _maybe_compact(
        self, messages: list[Message], *, extra_tokens: int = 0
    ) -> tuple[list[Message], tuple[int, int] | None]:
        system_tokens = estimate_tokens(self.system)
        current = conversation_tokens(self.system, messages) + extra_tokens
        if current <= self.config.token_budget:
            return ensure_alternating(messages), None
        before = len(messages)
        shrunk, changed = compact(
            messages,
            self.memory,
            step=self.step,
            keep_recent=6,
            budget_tokens=max(1500, self.config.token_budget - extra_tokens),
            system=self.system,
        )
        if not changed:
            return ensure_alternating(messages), None
        self._compactions += 1
        remaining = conversation_tokens(self.system, shrunk)
        return shrunk, (before - len(shrunk), max(system_tokens, remaining))

    def _state_text(self, last_result: str = "", compacted: bool = False) -> str:
        remaining_seconds = max(0.0, self.config.max_minutes * 60 - self.elapsed)
        return state_block(
            step=max(1, self.step),
            max_steps=self.config.max_steps,
            elapsed=fmt_elapsed(self.elapsed),
            remaining=fmt_elapsed(remaining_seconds),
            memory=self.memory,
            last_result=last_result,
            stuck_steps=self.stuck_steps,
            compacted=compacted,
        )

    async def _save_every_step(self) -> None:
        try:
            self.memory.save(self.run_dir)
        except OSError:  # pragma: no cover
            pass
        await asyncio.sleep(0)

    # ---------------------------------------------------------------- limits
    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def _limit_reason(self) -> tuple[str, str] | None:
        if self.stop_requested:
            return "interrupted", "stop requested"
        if self.memory.flags and self.config.stop_on_flag:
            return "flag", "flag captured"
        if self.elapsed >= self.config.max_minutes * 60:
            return "timeout", f"time budget of {self.config.max_minutes:.0f} minutes reached"
        if self.config.max_cost_usd and self.cost >= self.config.max_cost_usd:
            return "budget", f"cost budget of ${self.config.max_cost_usd:.2f} reached"
        if self.stuck_steps >= MAX_STUCK:
            return "exhausted", f"{MAX_STUCK} consecutive unproductive actions"
        return None

    def _is_repeat(self, signature: str) -> bool:
        count = self._signatures.get(signature, 0)
        if count >= 2:
            return True
        # Identical action three times anywhere in the recent window.
        return count >= 1 and self._recent[-3:].count(signature) >= 2

    # -------------------------------------------------------------- finalize
    def _finalize(self, status: str, reason: str) -> None:
        if self._finalized:
            return
        self._finalized = True
        report_path = ""
        try:
            self.memory.save(self.run_dir)
        except OSError:  # pragma: no cover
            pass
        try:
            from .report import write_report

            report_path = str(
                write_report(
                    run_dir=self.run_dir,
                    config=self.config,
                    memory=self.memory,
                    status=status,
                    reason=reason,
                    steps=self.step,
                    usage=self.usage,
                    cost_usd=self.cost,
                    duration=self.elapsed,
                    guard=self.guard,
                )
            )
        except Exception as exc:  # pragma: no cover - reporting must not fail the run
            self.bus.emit("error", message=f"could not write report: {exc}")
        self.result = RunResult(
            status=status,
            reason=reason,
            steps=self.step,
            flags=list(self.memory.flags),
            findings=list(self.memory.findings),
            usage=self.usage,
            cost_usd=self.cost,
            duration=self.elapsed,
            report_path=report_path,
            run_dir=str(self.run_dir),
        )
        self.bus.emit(
            "session_end",
            status=status,
            reason=reason,
            steps=self.step,
            duration=self.elapsed,
            usage=self.usage.to_dict(),
            cost_usd=self.cost,
            flags=[f.value for f in self.memory.flags],
            findings=len(self.memory.findings),
            report=report_path,
            run_dir=str(self.run_dir),
        )

    def request_stop(self) -> None:
        self.stop_requested = True


def _signature(tool: str, args: dict[str, Any]) -> str:
    try:
        body = json.dumps(args, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError):  # pragma: no cover
        body = str(args)
    return f"{tool}:{body[:600]}"


def _short(text: str, limit: int = 240) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
