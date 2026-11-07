"""SDK integration tests. Simulated E2B operations NEVER execute code locally."""
import asyncio
import errno
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import httpx

os.environ["LANGSMITH_TRACING"] = "false"
os.environ["LANGCHAIN_TRACING_V2"] = "false"
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "regulai"))

from deepagents.backends.protocol import (
    EditResult, FileDownloadResponse, FileUploadResponse, GlobResult, GrepResult,
    LsResult, ReadResult, WriteResult,
)
from e2b import Sandbox, CommandResult
from langchain_e2b import E2BSandbox
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.types import Command

from front.agents.integration_probe import (
    CALL, CSV_COMMAND, EXPECTED, EXPECTED_TOOLS, ProbeBoundary, ProbeRejected,
    ScriptedModel, ToolBoundary, build_probe, run_probe,
)


def simulated_backend():
    sandbox = Sandbox.create(debug=True, api_key="synthetic-task48-only",
                             sandbox_url="http://127.0.0.1:1", retries=0)
    sandbox.commands.run = Mock(return_value=CommandResult(
        stdout=json.dumps(EXPECTED), stderr="", exit_code=0, error=None))
    return E2BSandbox(sandbox=sandbox, workdir="/workspace/work"), sandbox


class ProbeTests(unittest.TestCase):
    def test_socket_errors_cannot_masquerade_as_network_denial(self):
        from runtime_checks import connect_probe
        cases = [('192.0.2.48', errno.ECONNREFUSED, '1', False),
                 ('2001:db8::48', errno.ECONNREFUSED, '1', False),
                 ('192.0.2.48', errno.EADDRNOTAVAIL, '1', False),
                 ('2001:db8::48', errno.EADDRNOTAVAIL, '0', False),
                 ('2001:db8::48', errno.EADDRNOTAVAIL, '1', True)]
        for address, error, kernel_setting, accepted in cases:
            with (self.subTest(address=address, errno=error, setting=kernel_setting),
                  patch('runtime_checks.socket.socket') as factory,
                  patch('runtime_checks.Path.read_text', return_value=kernel_setting)):
                factory.return_value.__enter__.return_value.connect.side_effect = OSError(error, 'synthetic socket failure')
                if accepted:
                    self.assertTrue(connect_probe(address, 8080, denied=True)['ipv6_disabled_by_kernel'])
                else:
                    with self.assertRaises(OSError):
                        connect_probe(address, 8080, denied=True)

    def test_native_roundtrip_official_adapter(self):
        backend, sandbox = simulated_backend()
        proof = run_probe(backend)
        self.assertEqual(proof["native_tool_call"], CALL)
        self.assertEqual(proof["model_received"]["result"], EXPECTED)
        self.assertEqual(set(proof["effective_tools"]), EXPECTED_TOOLS)
        sandbox.commands.run.assert_called_once_with(CSV_COMMAND, cwd="/workspace/work", timeout=10)

    def test_async_native_roundtrip(self):
        backend, _ = simulated_backend()
        graph, boundary = build_probe(backend)
        asyncio.run(graph.ainvoke({"messages": [HumanMessage(content="Synthetic CSV")]},
                                  config={"recursion_limit": 12}))
        self.assertEqual(boundary.received_results[0]["tool_call_id"], CALL["id"])
        self.assertEqual(boundary.received_results[0]["result"], EXPECTED)

    def test_every_effective_tool_passes_result_hook(self):
        backend, _ = simulated_backend()
        # Backend I/O is simulated; tools, validation, ToolNode, middleware and
        # Command messages are the installed SDK's actual implementations.
        cases = {
            "ls": {"path": "/workspace"},
            "read_file": {"file_path": "/workspace/work/a.txt"},
            "write_file": {"file_path": "/workspace/work/a.txt", "content": "synthetic"},
            "edit_file": {"file_path": "/workspace/work/a.txt", "old_string": "a", "new_string": "b"},
            "glob": {"pattern": "*.csv", "path": "/workspace/input"},
            "grep": {"pattern": "synthetic", "path": "/workspace/input"},
            "execute": {"command": "synthetic-command-never-run"},
            "write_todos": {"todos": [{"content": "Synthetic check", "status": "completed"}]},
            "csv_totals": CALL["args"],
        }
        with (patch.object(backend, "ls", return_value=LsResult(entries=[])),
              patch.object(backend, "read", return_value=ReadResult(file_data={"content": "synthetic", "encoding": "utf-8"})),
              patch.object(backend, "write", return_value=WriteResult(path="/workspace/work/a.txt")),
              patch.object(backend, "edit", return_value=EditResult(path="/workspace/work/a.txt", occurrences=1)),
              patch.object(backend, "glob", return_value=GlobResult(matches=[])),
              patch.object(backend, "grep", return_value=GrepResult(matches=[]))):
            for name, args in cases.items():
                with self.subTest(tool=name):
                    call = {"name": name, "args": args, "id": "test-" + name, "type": "tool_call"}
                    graph, audit = build_probe(backend, replies=[AIMessage(content="", tool_calls=[call])])
                    result = graph.invoke({"messages": [HumanMessage(content="Synthetic check")]})
                    self.assertTrue(any(e["surface"] == "tool.result" and e["name"] == name for e in audit.events))
                    messages = [m for m in result["messages"] if isinstance(m, ToolMessage)]
                    self.assertEqual(messages[0].tool_call_id, call["id"])
                    self.assertEqual(messages[0].status, "success")
        self.assertEqual(set(cases), EXPECTED_TOOLS)

    def test_validation_errors_and_unknown_tools_are_intercepted(self):
        for name, args in [("read_file", {}), ("does_not_exist", {})]:
            backend, _ = simulated_backend()
            graph, audit = build_probe(backend, replies=[AIMessage(content="", tool_calls=[
                {"name": name, "args": args, "id": "invalid", "type": "tool_call"}])])
            result = graph.invoke({"messages": [HumanMessage(content="Test validation")]})
            self.assertTrue(any(e["surface"] == "tool.result" for e in audit.events))
            self.assertEqual(next(m for m in result["messages"] if isinstance(m, ToolMessage)).status, "error")

    def test_exception_diagnostic_is_not_forwarded(self):
        backend, sandbox = simulated_backend()
        sandbox.commands.run.side_effect = RuntimeError("private-synthetic-diagnostic")
        graph, audit = build_probe(backend)
        with self.assertRaisesRegex(ProbeRejected, "raw diagnostic withheld"):
            graph.invoke({"messages": [HumanMessage(content="Test exception")]})
        self.assertTrue(any(e["surface"] == "tool.exception" for e in audit.events))

    def test_bad_or_extra_output_fields_fail_closed(self):
        for output in ['not JSON', '{"rows":true,"total_cents":750}',
                       '{"rows":3,"total_cents":750,"raw":"private"}']:
            backend, sandbox = simulated_backend()
            sandbox.commands.run.return_value = CommandResult(stdout=output, stderr="", exit_code=0, error=None)
            graph, audit = build_probe(backend)
            with self.assertRaises(ProbeRejected):
                graph.invoke({"messages": [HumanMessage(content="Bad result")]})
            self.assertEqual(audit.received_results, [])

    def test_result_content_artifact_command_and_arguments_rejected(self):
        marker = ProbeBoundary().reject_marker
        boundary = ProbeBoundary()
        for result in [ToolMessage(content=marker, tool_call_id="c"),
                       ToolMessage(content="ok", artifact={"image": marker}, tool_call_id="c"),
                       Command(update={"messages": [ToolMessage(content=marker, tool_call_id="c")]}),
                       Command(update={"messages": [], "private_state": marker})]:
            with self.assertRaises(ProbeRejected):
                boundary.tool_result({"name": "test", "id": "c"}, result)
        backend, sandbox = simulated_backend()
        graph, _ = build_probe(backend, replies=[AIMessage(content="", tool_calls=[
            {"name": "execute", "args": {"command": marker}, "id": "rejected", "type": "tool_call"}])])
        with self.assertRaises(ProbeRejected):
            graph.invoke({"messages": [HumanMessage(content="Reject generated arguments")]})
        sandbox.commands.run.assert_not_called()

    def test_model_multimodal_and_metadata_surfaces_are_checked(self):
        audit = ProbeBoundary()
        model = ScriptedModel(boundary=audit)
        for message in [HumanMessage(content=[{"type": "image_url", "image_url": {"url": audit.reject_marker}}]),
                        HumanMessage(content="ok", additional_kwargs={"file": audit.reject_marker})]:
            with self.assertRaises(ProbeRejected):
                model.invoke([message])

    def test_large_result_is_checked_before_sdk_offloads_it(self):
        backend, _ = simulated_backend()
        backend.upload_files = Mock()

        @tool
        def long_result() -> str:
            """Return a deliberately rejected large synthetic tool result."""
            return "synthetic " * 20000 + ProbeBoundary().reject_marker

        graph, audit = build_probe(backend, extra_tools=[long_result], replies=[AIMessage(content="", tool_calls=[
            {"name": "long_result", "args": {}, "id": "large", "type": "tool_call"}])])
        with self.assertRaises(ProbeRejected):
            graph.invoke({"messages": [HumanMessage(content="Test large result")]})
        self.assertTrue(any(e["surface"] == "tool.result" for e in audit.events))
        backend.upload_files.assert_not_called()

    def test_streaming_fallback_cannot_skip_model_boundary(self):
        boundary = ProbeBoundary()
        model = ScriptedModel(boundary=boundary)
        with self.assertRaises(ProbeRejected):
            list(model.stream([HumanMessage(content=boundary.reject_marker)]))

    def test_self_hosted_runner_rejects_cloud_defaults(self):
        from run_e2b import private_endpoint
        for url in ("https://api.e2b.dev", "https://api.e2b.app", "http://169.254.169.254", "http://user:secret@localhost"):
            with self.assertRaises(ValueError):
                private_endpoint(url)
        self.assertEqual(private_endpoint("http://e2b-api:3000"), "http://e2b-api:3000")

    def test_real_e2b_sdk_serializes_denied_network_with_mock_http_transport(self):
        from run_e2b import create_sandbox
        requests = []

        def handle(request):
            requests.append(request)
            if request.method == "DELETE":
                return httpx.Response(204)
            return httpx.Response(201, json={"templateID": "synthetic-template",
                "sandboxID": "synthetic-sandbox", "clientID": "synthetic-client",
                "envdVersion": "0.9.0", "domain": "task48.internal"})

        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "synthetic.key"
            key.write_text("e2b_synthetic_only_task48")
            config = {"api_url": "http://e2b-api:3000", "sandbox_url": "http://e2b-proxy:3002",
                      "api_key_file": str(key), "template": "synthetic-template"}
            with patch("e2b.api.client_sync.get_transport", return_value=httpx.MockTransport(handle)):
                sandbox = create_sandbox(config)
                self.assertEqual(sandbox.sandbox_id, "synthetic-sandbox")
                sandbox.kill()
        body = json.loads(requests[0].content)
        self.assertEqual(requests[0].url.path, "/v2/sandboxes")
        self.assertFalse(body["allow_internet_access"])
        self.assertEqual(body["network"]["denyOut"], ["0.0.0.0/0"])
        self.assertFalse(body["network"]["allowPublicTraffic"])
        self.assertEqual(body["envVars"], {})
        self.assertEqual(len(requests), 2)

    def test_compaction_reaches_model_boundary_sync_and_async(self):
        for asynchronous in [False, True]:
            backend, _ = simulated_backend()
            # History persistence is sandbox I/O; it is mocked only in this SDK test.
            backend.download_files = Mock(side_effect=lambda paths: [
                FileDownloadResponse(path=p, content=None, error="file_not_found") for p in paths])
            backend.upload_files = Mock(side_effect=lambda files: [
                FileUploadResponse(path=p, error=None) for p, _ in files])
            graph, audit = build_probe(backend, replies=[], model_profile={"max_input_tokens": 2000})
            history = []
            for _ in range(20):
                history.extend([HumanMessage(content="synthetic history " * 100), AIMessage(content="noted")])
            history.append(HumanMessage(content="Summarize synthetic progress"))
            with (patch.object(backend, "write", return_value=WriteResult(path="/conversation_history/test.md")),
                  patch.object(backend, "read", return_value=ReadResult(error="File not found"))):
                if asynchronous:
                    asyncio.run(graph.ainvoke({"messages": history}, config={"recursion_limit": 12}))
                else:
                    graph.invoke({"messages": history}, config={"recursion_limit": 12})
            calls = [e for e in audit.events if e["surface"] == "model.request"]
            self.assertIn("compaction", [e["purpose"] for e in calls])
            self.assertIn("generation", [e["purpose"] for e in calls])
            wrappers = [e for e in audit.events if e["surface"] == "agent.model_middleware"]
            self.assertLess(len(wrappers), len(calls))

    def test_compaction_retries_cannot_bypass_rejection(self):
        backend, _ = simulated_backend()
        backend.download_files = Mock(side_effect=lambda paths: [
            FileDownloadResponse(path=p, error="file_not_found") for p in paths])
        backend.upload_files = Mock(side_effect=lambda files: [
            FileUploadResponse(path=p) for p, _ in files])
        graph, audit = build_probe(backend, replies=[], model_profile={"max_input_tokens": 2000})
        history = [HumanMessage(content=(audit.reject_marker + " synthetic ") * 1000),
                   AIMessage(content="noted"), HumanMessage(content="Current synthetic request")]
        with self.assertRaises(ProbeRejected):
            graph.invoke({"messages": history}, config={"recursion_limit": 12})
        calls = [e for e in audit.events if e["surface"] == "model.request"]
        self.assertTrue(calls)
        self.assertTrue(all(e["purpose"] == "compaction" for e in calls))
        self.assertFalse(any(e["surface"] == "model.response" for e in audit.events))


if __name__ == "__main__":
    unittest.main(verbosity=2)
