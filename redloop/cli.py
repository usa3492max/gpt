"""Command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import re
import socket
import sys
from pathlib import Path

from . import __version__
from .agent import Agent
from .config import PRESETS, Config, load_env_file
from .doctor import doctor, env_hint
from .events import EventBus
from .llm import build_client
from .memory import Memory
from .render import build_renderer
from .safety import ScopeGuard
from .tools import build_registry, tool_help
from .transcript import Transcript

AUTHORISATION_NOTICE = """
redloop is an offensive-security tool. Use it only against systems you own or have
explicit written permission to test. Unauthorised access to computer systems is a
criminal offence in most jurisdictions (for example the Computer Fraud and Abuse Act
in the US and the Computer Misuse Act in the UK).

Nothing is sent to the target until you confirm with --i-am-authorized
(or REDLOOP_AUTHORIZED=1). Loopback targets run without it.
"""

EXIT = {
    "flag": 0,
    "completed": 0,
    "error": 1,
    "exhausted": 3,
    "timeout": 3,
    "budget": 3,
    "interrupted": 130,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redloop",
        description="Autonomous, LLM-driven penetration-testing agent.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_epilog(),
    )
    run = parser.add_argument_group("engagement")
    run.add_argument("-t", "--target", help="target IP, hostname, CIDR or URL")
    run.add_argument(
        "-o", "--objective",
        help="what success looks like (default: capture any flag / assess the target)",
    )
    run.add_argument(
        "-s", "--scope", nargs="+", default=None, metavar="HOST",
        help="additional authorised hosts, CIDRs or wildcards (*.example.com)",
    )
    run.add_argument(
        "--seed-notes", default=None,
        help="context to hand the agent up front (credentials, hints, intended path)",
    )
    run.add_argument(
        "--flag-regex", action="append", default=None, metavar="REGEX",
        help="extra regex for recognising flags (repeatable)",
    )
    run.add_argument(
        "--multi-flag", action="store_true", default=None,
        help="keep running after the first flag (challenges with several flags)",
    )

    model = parser.add_argument_group("model")
    model.add_argument(
        "-p", "--provider", default=None,
        help="provider preset: " + ", ".join(PRESETS) + " (default: anthropic)",
    )
    model.add_argument("-m", "--model", default=None, help="model name")
    model.add_argument("--api-key", default=None, help="API key (else read from the environment)")
    model.add_argument(
        "--base-url", default=None,
        help="override the endpoint, e.g. http://host.docker.internal:11434/v1",
    )
    model.add_argument("--temperature", type=float, default=None, help="sampling temperature (default 0.7)")
    model.add_argument("--max-tokens", type=int, default=None, help="max reply tokens (default 2048)")
    model.add_argument(
        "--context-window", type=int, default=None,
        help="model context size in tokens; drives when history is compacted",
    )

    limits = parser.add_argument_group("limits")
    limits.add_argument("--max-steps", type=int, default=None, help="action budget (default 40)")
    limits.add_argument("--max-minutes", type=float, default=None, help="wall-clock budget (default 90)")
    limits.add_argument(
        "--max-cost", type=float, default=None, metavar="USD",
        help="stop when the estimated API spend reaches this amount",
    )
    limits.add_argument(
        "--command-timeout", type=int, default=None,
        help="per-command timeout in seconds (default 300)",
    )
    limits.add_argument(
        "--max-output-chars", type=int, default=None,
        help="how much of each tool output reaches the model (default 6000)",
    )

    safety = parser.add_argument_group("guardrails")
    safety.add_argument(
        "--i-am-authorized", dest="authorized", action="store_true", default=None,
        help="confirm you are authorised to test the target (required for non-loopback targets)",
    )
    safety.add_argument(
        "--scope-check", action=argparse.BooleanOptionalAction, default=None,
        help="refuse actions against hosts outside the scope (default: on)",
    )
    safety.add_argument(
        "--allow-private-networks", action=argparse.BooleanOptionalAction, default=None,
        help="allow RFC1918 addresses as part of the target's environment (default: on)",
    )

    output = parser.add_argument_group("output")
    output.add_argument("--runs-dir", default=None, help="where to write run directories (default ./runs)")
    output.add_argument("--run-dir", default=None, help="write this run to an explicit directory")
    output.add_argument("--resume", default=None, metavar="DIR", help="continue a previous run directory")
    output.add_argument("--plain", action="store_true", default=None, help="line-oriented output, no colour")
    output.add_argument("--json-feed", action="store_true", default=None, help="emit the feed as JSON lines")
    output.add_argument("--verbose", "-v", action="store_true", default=None, help="show full tool output")
    output.add_argument("--quiet", "-q", action="store_true", default=None, help="only steps, actions and results")
    output.add_argument("--no-color", action="store_true", default=None, help="disable colour")

    misc = parser.add_argument_group("other")
    misc.add_argument("--dry-run", action="store_true", default=None,
                      help="plan one action with the model but execute nothing")
    misc.add_argument("--print-prompt", action="store_true", default=None,
                      help="print the exact system prompt and brief, then exit")
    misc.add_argument("--doctor", action="store_true", default=None, help="check the environment and exit")
    misc.add_argument("--check-model", action="store_true", default=None,
                      help="with --doctor: make a real model call")
    misc.add_argument("--list-tools", action="store_true", default=None, help="print the tool catalogue and exit")
    misc.add_argument("--env", action="store_true", default=None, help="list supported environment variables")
    misc.add_argument("--version", action="store_true", default=None, help="print the version and exit")
    return parser


def _epilog() -> str:
    return f"""examples:
  # Claude, against an HTB/CTF box
  export ANTHROPIC_API_KEY=sk-ant-...
  redloop -t 10.10.11.42 --i-am-authorized --max-steps 60

  # local model through Ollama (host machine)
  redloop -t 10.10.11.42 -p ollama -m qwen2.5-coder:14b --i-am-authorized

  # no API key at all: exercise the loop against the bundled lab
  redloop -t 127.0.0.1 -p mock

  # watch it decide, without touching the target
  redloop -t 10.10.11.42 --dry-run --i-am-authorized

  # web/API engagement with extra scope and a JSON feed for tooling
  redloop -t app.example.com -s api.example.com --json-feed --i-am-authorized

providers: {', '.join(PRESETS)}
exit codes: 0 flag or completed, 1 error, 2 usage/configuration, 3 budget exhausted, 130 interrupted
"""


# --------------------------------------------------------------------------- #
# config assembly
# --------------------------------------------------------------------------- #
CLI_TO_CONFIG = {
    "target": "target",
    "objective": "objective",
    "scope": "scope",
    "seed_notes": "seed_notes",
    "flag_regex": "extra_flag_patterns",
    "provider": "provider",
    "model": "model",
    "api_key": "api_key",
    "base_url": "base_url",
    "temperature": "temperature",
    "max_tokens": "max_tokens",
    "context_window": "context_window",
    "max_steps": "max_steps",
    "max_minutes": "max_minutes",
    "max_cost": "max_cost_usd",
    "command_timeout": "command_timeout",
    "max_output_chars": "max_output_chars",
    "scope_check": "scope_check",
    "allow_private_networks": "allow_private_networks",
    "runs_dir": "runs_dir",
    "plain": "plain",
    "json_feed": "json_feed",
    "verbose": "verbose",
    "quiet": "quiet",
    "no_color": "no_color",
    "dry_run": "dry_run",
    "authorized": "authorized",
}

BOOL_FLAGS = {
    "plain", "json_feed", "verbose", "quiet", "no_color", "dry_run", "authorized",
    "multi_flag", "print_prompt", "doctor", "check_model", "list_tools", "env", "version",
}


def config_from_args(args: argparse.Namespace) -> Config:
    config = Config()
    config = config.with_env()  # environment first ...
    for arg_name, attr in CLI_TO_CONFIG.items():
        value = getattr(args, arg_name, None)
        if value is None:
            continue
        if arg_name in BOOL_FLAGS and value is False:
            continue
        setattr(config, attr, value)
    if getattr(args, "multi_flag", None):
        config.stop_on_flag = False
    if isinstance(config.runs_dir, str):
        config.runs_dir = Path(config.runs_dir)
    if isinstance(config.scope, str):
        config.scope = [config.scope]
    return config.finalize()


def _needs_authorisation(config: Config) -> bool:
    if config.authorized:
        return False
    target = config.target
    if not target:
        return True
    if target.lower() in {"localhost", "127.0.0.1", "::1"}:
        return False
    try:
        address = ipaddress.ip_address(target.split("/")[0])
        return not (address.is_loopback or (address.is_private and str(address).startswith("127.")))
    except ValueError:
        pass
    try:
        resolved = socket.getaddrinfo(target, None)[0][4][0]
        address = ipaddress.ip_address(resolved)
        return not address.is_loopback
    except (socket.gaierror, ValueError, IndexError, OSError):
        return True


def run_directory(config: Config, args: argparse.Namespace) -> Path:
    if args.resume:
        path = Path(args.resume).expanduser().resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path
    if args.run_dir:
        path = Path(args.run_dir).expanduser().resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", config.target)[:48] or "run"
    from .report import run_timestamp

    path = (Path(config.runs_dir) / f"{run_timestamp()}_{slug}").expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    load_env_file()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"redloop {__version__}")
        return 0
    if args.env:
        print("environment variables:\n" + env_hint())
        return 0
    if args.list_tools:
        print("tools available to the agent:\n")
        print(tool_help(build_registry()))
        return 0

    config = config_from_args(args)

    if args.doctor:
        if not config.target:
            config.target = "127.0.0.1"
        return doctor(config, check_model=bool(args.check_model))

    problems = config.validate()
    if problems:
        print("configuration problem:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        if not config.effective_api_key and config.preset.kind != "mock":
            print("\nsupported environment variables:\n" + env_hint(), file=sys.stderr)
        print("\nrun `redloop --doctor` for a full environment check.", file=sys.stderr)
        return 2

    if args.print_prompt:
        from .prompts import brief_message, system_prompt

        print("===== SYSTEM PROMPT =====")
        print(system_prompt(tool_help(build_registry())))
        print("\n===== FIRST USER MESSAGE =====")
        print(brief_message(config, "(state block omitted)").content)
        return 0

    if _needs_authorisation(config):
        print(AUTHORISATION_NOTICE, file=sys.stderr)
        return 2

    registry = build_registry()
    guard = ScopeGuard(
        target=config.target,
        scope=config.scope,
        enabled=config.scope_check,
        allow_private=config.allow_private_networks,
        allow_loopback=config.allow_loopback,
    )

    run_dir = run_directory(config, args)
    memory = Memory()
    if args.resume:
        restored = Memory.load(run_dir)
        if restored is not None:
            memory = restored
            config.seed_notes = (
                (config.seed_notes + "\n\n" if config.seed_notes else "")
                + "RESUMING an earlier run in this directory. Previously recorded notes, findings "
                "and facts are in the state block; continue from the most promising lead rather "
                "than restarting enumeration."
            )

    config.runs_dir = run_dir
    bus = EventBus()
    renderer = build_renderer(config)
    transcript = Transcript(run_dir, config)
    bus.subscribe(renderer.handle)
    bus.subscribe(transcript.handle)

    def on_retry(attempt: int, delay: float, error: str) -> None:
        bus.emit("retrying", attempt=attempt, delay=delay, error=error)

    client = build_client(config, on_retry=on_retry)
    agent = Agent(
        config,
        bus,
        client=client,
        registry=registry,
        guard=guard,
        memory=memory,
        run_dir=run_dir,
    )

    interrupted = False
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        interrupted = True
        agent.request_stop()
        print("\ninterrupted — partial results saved", file=sys.stderr)
    finally:
        try:
            asyncio.run(client.aclose())
        except Exception:  # pragma: no cover
            pass
        transcript.close()

    result = agent.result
    if interrupted and result.status not in {"flag"}:
        result.status = "interrupted"
    _print_footer(result, config)
    return EXIT.get(result.status, 1)


def _print_footer(result, config: Config) -> None:
    plain = config.plain or config.json_feed or not sys.stdout.isatty()
    if plain:
        return
    try:
        from rich.console import Console

        console = Console(no_color=config.no_color)
        if result.report_path:
            console.print()
            console.print(
                f"[grey62]full report:[/grey62] [bold]{result.report_path}[/bold]"
            )
            console.print(
                f"[grey62]replay the feed:[/grey62] [bold]{result.run_dir}/feed.txt[/bold]"
            )
        if result.status == "flag":
            console.print(
                "[green]objective achieved.[/green] [grey62]verify the flag and clean up any "
                "artefacts you planted.[/grey62]"
            )
    except Exception:  # pragma: no cover
        pass


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
