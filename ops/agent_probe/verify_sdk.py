"""Persist reproducible, explicitly simulated SDK evidence (no infrastructure claim)."""
import argparse
import hashlib
import importlib.metadata
import inspect
import io
import json
from pathlib import Path
import unittest

from test_probe import ProbeTests, simulated_backend
from front.agents.integration_probe import build_probe, run_probe
from deepagents import create_deep_agent
from deepagents.profiles import HarnessProfile, GeneralPurposeSubagentProfile
from e2b import Sandbox
from langchain_e2b import E2BSandbox


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ProbeTests))
    (args.output / "tests.log").write_text(stream.getvalue(), encoding="utf-8")
    if not result.wasSuccessful():
        print(stream.getvalue())
        return 1
    proof = run_probe(simulated_backend()[0])
    graph, _ = build_probe(simulated_backend()[0])
    proof.update({"scope": "real Deep Agents and official adapter; E2B commands.run simulated",
                  "sandbox_execution": "NOT demonstrated by this test", "tests_passed": result.testsRun,
                  "versions": {dist.metadata["Name"]: dist.version for dist in importlib.metadata.distributions()},
                  "tool_schemas": {name: tool.args for name, tool in graph.nodes["tools"].bound.tools_by_name.items()},
                  "verified_parameters": {obj.__name__: list(inspect.signature(obj).parameters)
                    for obj in (create_deep_agent, HarnessProfile, GeneralPurposeSubagentProfile, Sandbox.create, E2BSandbox)},
                  "source_sha256": {str(p.relative_to(Path(__file__).resolve().parents[2])): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in (Path(__file__).resolve().parents[2] / "regulai/front/agents").glob("*.py")}})
    (args.output / "sdk-proof.json").write_text(json.dumps(proof, indent=2), encoding="utf-8")
    print(f"{result.testsRun} SDK tests passed; this SDK-only test does not validate infrastructure")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
