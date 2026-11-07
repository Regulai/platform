"""Pinned SDK against the test application's HTTP; no paid provider or local exec."""
import json
from pathlib import Path
import sys
from unittest.mock import patch
import httpx

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parent))
from test_probe import simulated_backend
from front.agents.adapter import build_agent, InternalClient, InternalOperationError
from front.agents.integration_probe import CSV_COMMAND, INPUT_PATH
from langchain_core.messages import ToolMessage
from langchain_core.tools import tool


def main():
    config = json.load(sys.stdin)
    scenario = config.pop('scenario', 'normal')
    backend, sandbox = simulated_backend()
    if scenario == 'tool-error':
        sandbox.commands.run.side_effect = RuntimeError('Nombre: Persona Sintetica; error@example.invalid')
    forwarded = httpx.Client(trust_env=False, follow_redirects=False, timeout=30)
    lost = False

    def transport(request):
        nonlocal lost
        response = forwarded.send(request)
        response.read()
        if request.url.path.endswith('/inference/') and not lost:
            lost = True
            raise httpx.ReadError('Simulated lost internal response')
        return response

    @tool
    def csv_totals(input_path: str) -> dict:
        """Compute the authorized CSV in the sandbox."""
        if input_path != INPUT_PATH:
            raise ValueError('Unauthorized input')
        result = backend.execute(CSV_COMMAND, timeout=10)
        return json.loads(result.output)

    internal = InternalClient(**config, transport=httpx.MockTransport(transport))
    try:
        graph = build_agent(backend, internal, tools=[csv_totals])
        try:
            result = graph.invoke({'messages': [{'role': 'user', 'content': 'Sum the synthetic CSV.'}]},
                config={'recursion_limit': 12})
        except InternalOperationError:
            if scenario != 'revoked':
                raise
            print(json.dumps({'revocation_stopped': True, 'paid_calls': 0}))
            return
        message = next(m for m in result['messages'] if isinstance(m, ToolMessage))
        print(json.dumps({'tool_call_id': message.tool_call_id, 'view': json.loads(message.content),
                          'lost_response_replayed': lost, 'paid_calls': 0}))
    finally:
        internal.close()
        forwarded.close()


if __name__ == '__main__':
    main()
