"""ToolForge - safe integration of allowlisted third-party tools.

ToolForge lets an operator plug an external CLI security tool into a PEGASE
mission without writing a bespoke module, while keeping the safety guarantees:

  * only tools on an explicit allowlist may run (no arbitrary command exec),
  * every target is scope-checked before substitution,
  * the command template uses ``{target}`` placeholders only - no shell is
    invoked (``shell=False``), so there is no command-injection surface,
  * stdout/stderr and exit code are captured into the finding evidence.

Built-in allowlist covers common, broadly-available tools. Operators extend it
via configuration, never via free-form command strings.
"""

from __future__ import annotations

import asyncio
import shutil
from typing import Any

from pegase.core.logging import get_logger
from pegase.core.scope import ActionType, ScopeGuard
from pegase.modules.base import Finding, Module, ModuleResult

log = get_logger(__name__)

# name -> argv template (list form, no shell). {target} is substituted safely.
_ALLOWLIST: dict[str, list[str]] = {
    "nuclei": ["nuclei", "-u", "{target}", "-silent", "-jsonl"],
    "nikto": ["nikto", "-host", "{target}", "-Format", "json", "-nointeractive"],
    "whatweb": ["whatweb", "--log-json=-", "{target}"],
    "testssl": ["testssl.sh", "--jsonfile", "-", "{target}"],
    "dig": ["dig", "+short", "{target}"],
    "host": ["host", "{target}"],
}


class ToolForge(Module):
    name = "toolforge"
    description = "Run allowlisted third-party CLI tools with scope-checked targets."
    action_type = ActionType.ACTIVE

    async def run(
        self,
        *,
        targets: list[str],
        guard: ScopeGuard,
        parameters: dict[str, Any] | None = None,
    ) -> ModuleResult:
        params = parameters or {}
        tool = params.get("tool")
        if not tool:
            raise ValueError("toolforge requires parameters['tool'].")
        # Operators may register extra tools via config, but only as argv lists.
        allowlist = {**_ALLOWLIST, **params.get("extra_tools", {})}
        if tool not in allowlist:
            raise ValueError(
                f"tool '{tool}' not in allowlist {sorted(allowlist)}; "
                "register it explicitly to run it."
            )
        template = allowlist[tool]
        binary = template[0]
        if not shutil.which(binary):
            raise RuntimeError(f"'{binary}' not found on PATH.")

        timeout = float(params.get("timeout", 300))
        result = ModuleResult(module=self.name)

        for target in targets:
            guard.check(target, self.action_type)
            argv = [arg.replace("{target}", target) for arg in template]
            log.info("toolforge_exec", tool=tool, target=target, argv=argv)
            code, out, err = await _run(argv, timeout)
            result.raw.setdefault(target, {})[tool] = {
                "exit_code": code,
                "stdout_len": len(out),
            }
            severity = "info" if code == 0 else "low"
            snippet = out.strip()[:4000] or err.strip()[:1000]
            result.findings.append(
                Finding(
                    module=self.name,
                    target=target,
                    title=f"{tool} output for {target} (exit {code})",
                    description=(
                        snippet or f"{tool} produced no output."
                    ),
                    severity=severity,
                    evidence={
                        "tool": tool,
                        "argv": argv,
                        "exit_code": code,
                        "stdout": out[:20000],
                        "stderr": err[:4000],
                    },
                )
            )
        return result


async def _run(argv: list[str], timeout: float) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return 124, "", f"timed out after {timeout}s"
    return (
        proc.returncode or 0,
        out.decode("utf-8", "replace"),
        err.decode("utf-8", "replace"),
    )
