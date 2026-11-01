"""Task 48: real Deep Agents graph, synthetic model, one E2B adapter.

This is an integration probe, not Regulay's governance implementation (task 49).
Install only with ops/agent_probe/requirements.txt in the isolated executor.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import shlex
from typing import Any

from deepagents import create_deep_agent
from deepagents.profiles import (
    GeneralPurposeSubagentProfile, HarnessProfile, register_harness_profile,
)
from langchain.agents.middleware import AgentMiddleware
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import tool
from langchain_core.utils.function_calling import convert_to_openai_tool
from langgraph.types import Command
from pydantic import Field, PrivateAttr

MODEL_NAME = "regulay-probe:task48"
INPUT_PATH = "/workspace/input/numbers.csv"
OUTPUT_PATH = "/workspace/output/totals.json"
EXPECTED = {"rows": 3, "total_cents": 750}
CALL = {"name": "csv_totals", "args": {"input_path": INPUT_PATH},
        "id": "task48-csv-1", "type": "tool_call"}
# Fixed synthetic program. No exec/eval/subprocess in the executor. Only the
# sandbox backend executes it; integers avoid float/currency rounding artifacts.
CSV_SOURCE = Path(__file__).with_name("probe_csv.py").read_text(encoding="utf-8")
CSV_COMMAND = "python -I -c " + shlex.quote(CSV_SOURCE)
EXPECTED_TOOLS = frozenset({"write_todos", "ls", "read_file", "write_file",
                            "edit_file", "glob", "grep", "execute", "csv_totals"})


class ProbeRejected(RuntimeError):
    """A synthetic boundary rejected content; never includes the rejected data."""


def _wire(value: Any) -> Any:
    if isinstance(value, BaseMessage):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {k: _wire(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_wire(v) for v in value]
    return value


@dataclass
class ProbeBoundary:
    """Observable interception seams, with a TEST marker (not a privacy filter).

    Task 49 must replace these checks with trusted output contracts and governed
    inference. Recording hashes/counts here deliberately avoids storing content.
    """
    events: list[dict] = field(default_factory=list)
    received_results: list[dict] = field(default_factory=list)
    effective_tools: list[str] = field(default_factory=list)
    reject_marker: str = "TASK48_REJECT_SYNTHETIC"

    def inspect(self, surface: str, payload: Any, **labels: Any) -> None:
        encoded = json.dumps(_wire(payload), ensure_ascii=False, sort_keys=True)
        self.events.append({"surface": surface, **labels,
                            "sha256": hashlib.sha256(encoded.encode()).hexdigest()})
        if self.reject_marker in encoded:
            raise ProbeRejected("Synthetic probe boundary rejected content")

    def tool_result(self, call: dict, result: ToolMessage | Command):
        # Command.update can contain messages AND arbitrary state (e.g. todos).
        # Inspect the entire update, including ToolMessage.artifact and metadata.
        payload = result.update if isinstance(result, Command) else result
        self.inspect("tool.result", payload, name=call["name"], call_id=call["id"])
        return result


class ToolBoundary(AgentMiddleware):
    """Covers built-ins, custom tools, validation errors, Command and exceptions.

    FilesystemMiddleware is outside this wrapper and may subsequently offload a
    large result. The model boundary below therefore inspects the final request
    too, including summary prompts and offload references.
    """
    def __init__(self, boundary: ProbeBoundary):
        self.boundary = boundary

    def wrap_tool_call(self, request, handler):
        self.boundary.inspect("tool.arguments", request.tool_call)
        try:
            result = handler(request)
        except Exception:
            self.boundary.events.append({"surface": "tool.exception",
                                         "name": request.tool_call["name"]})
            # Propagate a constant, never a backend exception containing output.
            raise ProbeRejected("Probe tool failed; raw diagnostic withheld") from None
        return self.boundary.tool_result(request.tool_call, result)

    async def awrap_tool_call(self, request, handler):
        self.boundary.inspect("tool.arguments", request.tool_call)
        try:
            result = await handler(request)
        except Exception:
            self.boundary.events.append({"surface": "tool.exception",
                                         "name": request.tool_call["name"]})
            raise ProbeRejected("Probe tool failed; raw diagnostic withheld") from None
        return self.boundary.tool_result(request.tool_call, result)

    def wrap_model_call(self, request, handler):
        self.boundary.events.append({"surface": "agent.model_middleware"})
        return handler(request)

    async def awrap_model_call(self, request, handler):
        self.boundary.events.append({"surface": "agent.model_middleware"})
        return await handler(request)


class ScriptedModel(BaseChatModel):
    """Native messages through the real graph; no provider client or API key.

    _generate/_agenerate are the final model seam. Summarization invokes this
    same model directly, bypassing the agent's wrap_model_call middleware.
    Streaming uses BaseChatModel's non-streaming fallback through these methods.
    """
    model_name: str = MODEL_NAME
    boundary: ProbeBoundary = Field(exclude=True)
    replies: list[AIMessage] = Field(default_factory=list, exclude=True)
    _position: int = PrivateAttr(default=0)

    @property
    def _llm_type(self):
        return "regulay-probe"

    def bind_tools(self, tools, *, tool_choice=None, **kwargs):
        schemas = [convert_to_openai_tool(t) for t in tools]
        self.boundary.effective_tools = sorted(t["function"]["name"] for t in schemas)
        return self.bind(tools=schemas, **kwargs)

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        metadata = getattr(run_manager, "metadata", {}) or {}
        purpose = "compaction" if metadata.get("lc_source") == "summarization" else "generation"
        self.boundary.inspect("model.request", {"messages": messages,
                                               "tools": kwargs.get("tools", []),
                                               "stop": stop, "kwargs": kwargs}, purpose=purpose)
        if purpose == "compaction":
            reply = AIMessage(content="Synthetic conversation compacted; no personal data.")
        elif self._position < len(self.replies):
            reply = self.replies[self._position]
            self._position += 1
        else:
            for message in messages:
                if isinstance(message, ToolMessage) and message.name == "csv_totals":
                    self.boundary.received_results.append({
                        "name": message.name, "tool_call_id": message.tool_call_id,
                        "result": json.loads(message.content),
                    })
            reply = AIMessage(content="Synthetic probe complete.")
        # Native tool calls (name, args, id) are inspected without flattening them
        # into prose. Summary responses traverse this seam as well.
        self.boundary.inspect("model.response", reply, purpose=purpose)
        return ChatResult(generations=[ChatGeneration(message=reply)])

    async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs):
        return self._generate(messages, stop, run_manager, **kwargs)


# Public API verified in deepagents==0.6.12. An empty subagents list alone still
# creates a general-purpose subagent. Registry config is static, contains no
# conversation data, and applies only to our uniquely named simulated model.
register_harness_profile(MODEL_NAME, HarnessProfile(
    general_purpose_subagent=GeneralPurposeSubagentProfile(enabled=False),
))


def build_probe(backend, *, boundary=None, replies=None, extra_tools=(), model_profile=None):
    boundary = boundary or ProbeBoundary()

    @tool
    def csv_totals(input_path: str) -> dict:
        """Sum integer cents from the single synthetic CSV inside the sandbox."""
        if input_path != INPUT_PATH:
            raise ProbeRejected("Only the task 48 synthetic input is permitted")
        result = backend.execute(CSV_COMMAND, timeout=10)
        if result.exit_code != 0 or result.truncated:
            raise ProbeRejected("Sandbox calculation failed; diagnostic withheld")
        try:
            data = json.loads(result.output)
        except (TypeError, ValueError):
            raise ProbeRejected("Sandbox returned invalid JSON") from None
        if (not isinstance(data, dict) or set(data) != {"rows", "total_cents"}
                or any(type(data[k]) is not int for k in data) or data["rows"] < 0):
            raise ProbeRejected("Sandbox result violates the synthetic output contract")
        return data

    model = ScriptedModel(boundary=boundary,
                          replies=replies if replies is not None else [AIMessage(content="", tool_calls=[CALL])],
                          profile=model_profile, cache=False)
    graph = create_deep_agent(
        model=model, tools=[csv_totals, *extra_tools], backend=backend,
        middleware=[ToolBoundary(boundary)],
        subagents=[], memory=None, skills=None, store=None, checkpointer=None,
        system_prompt="Run the authorized synthetic CSV probe. No external services.",
    )
    return graph, boundary


def run_probe(backend) -> dict:
    graph, boundary = build_probe(backend)
    result = graph.invoke({"messages": [{"role": "user", "content": "Sum the synthetic CSV."}]},
                          config={"recursion_limit": 12})
    native_calls = [call for msg in result["messages"] if isinstance(msg, AIMessage)
                    for call in msg.tool_calls]
    if native_calls != [CALL]:
        raise AssertionError("Native tool call identity or arguments changed")
    if boundary.received_results != [{"name": CALL["name"], "tool_call_id": CALL["id"], "result": EXPECTED}]:
        raise AssertionError("Model did not receive the matching structured result")
    if set(boundary.effective_tools) != EXPECTED_TOOLS:
        raise AssertionError(f"Unexpected effective tool catalog: {boundary.effective_tools}")
    return {"native_tool_call": native_calls[0], "model_received": boundary.received_results[0],
            "effective_tools": boundary.effective_tools, "events": boundary.events,
            "paid_calls": 0, "global_memory": False, "automatic_delegation": False}
