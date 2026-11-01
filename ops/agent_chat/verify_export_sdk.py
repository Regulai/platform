"""Official Deep Agents HITL/checkpoint restart; sandbox and model simulated."""
import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys
import tempfile

root = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(root / 'regulai'), str(root / 'ops/agent_probe')]
from test_probe import simulated_backend
from front.agents.adapter import build_agent
from langchain_core.messages import HumanMessage
from langchain_core.tools import tool
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import Command

CALL = {'id': 'sdk-durable-save', 'name': 'save_revision', 'args': {
    'artifact_reference': 'synthetic-reference', 'sha256': 'a' * 64, 'name': 'report.docx'}}


class Boundary:
    def __init__(self):
        self.effects = 0

    def operation(self, name, payload):
        if name == 'inference':
            return {'content': 'Confirmed' if any(m['role'] == 'tool' for m in payload['messages']) else '',
                'tool_calls': [] if any(m['role'] == 'tool' for m in payload['messages']) else [CALL]}
        if name == 'authorize-tool':
            assert payload == CALL
            return {'status': 'authorized'}
        if name == 'tool-results':
            assert payload['call'] == CALL
            return {'status': 'approved', 'reference': 'opaque-export-reference'}
        raise AssertionError(name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    boundary = Boundary()
    @tool
    def save_revision(artifact_reference: str, sha256: str, name: str):
        """Save one verified revision."""
        boundary.effects += 1
        return {'reference': 'opaque-export-reference'}
    config = {'configurable': {'thread_id': 'synthetic-restart'}, 'recursion_limit': 8}
    def graph(saver):
        return build_agent(simulated_backend()[0], boundary, tools=[save_revision], allowed_tools=['save_revision'],
            checkpointer=saver, interrupt_on={'save_revision': {'allowed_decisions': ['approve', 'reject']}},
            model_profile={'max_input_tokens': 200000, 'max_output_tokens': 8000})
    with tempfile.TemporaryDirectory() as temporary:
        database = str(Path(temporary) / 'private.sqlite')
        with SqliteSaver.from_conn_string(database) as saver:
            first = graph(saver).invoke({'messages': [HumanMessage(content='Save synthetic revision')]}, config=config)
            assert first['__interrupt__'] and boundary.effects == 0
        with SqliteSaver.from_conn_string(database) as saver:
            restored = graph(saver)
            checkpoint = restored.get_state(config)
            assert checkpoint.next and checkpoint.values['messages'][-1].tool_calls[0]['id'] == CALL['id']
            restored.invoke(Command(resume={'decisions': [{'type': 'approve'}]}), config=config)
            assert boundary.effects == 1 and not restored.get_state(config).next
        with SqliteSaver.from_conn_string(database) as saver:
            assert not graph(saver).get_state(config).next and boundary.effects == 1
            saver.delete_thread('synthetic-restart')
            assert not graph(saver).get_state(config).values
    report = {'passed': True, 'official_interrupt_before_effect': True, 'sqlite_close_reopen_resume': True,
        'native_call_id_preserved': True, 'effects': boundary.effects, 'official_retention_delete': True,
        'scope': 'Real installed SDK, simulated sandbox/model; PostgreSQL and real E2B tested separately',
        'versions': {name: importlib.metadata.version(name) for name in
            ('deepagents', 'langgraph', 'langgraph-checkpoint-sqlite', 'langchain-e2b')},
        'adapter_sha256': hashlib.sha256((root/'regulai/front/agents/adapter.py').read_bytes()).hexdigest()}
    (args.output / 'proof.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
