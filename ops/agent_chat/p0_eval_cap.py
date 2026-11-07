"""Keep the full pre-dispatch bound for an evidenced HTTP 400, without retrying it."""
import argparse
from decimal import Decimal
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ops.agent_chat.p0_eval_app import configure, STATE
from ops.agent_chat.p0_eval_budget import BudgetGuard


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('reservation_id')
    args = parser.parse_args()
    config = configure()
    events = [json.loads(line) for line in (STATE / 'provider.jsonl').read_text().splitlines()]
    matching = [event for event in events if event['reservation_id'] == args.reservation_id]
    if len(matching) != 1 or matching[0].get('http_status') != 400 or matching[0].get('status') != 'unknown':
        raise RuntimeError('Requires exactly one completed HTTP 400 response without usage.')
    event = matching[0]
    guard = BudgetGuard(STATE / 'budget.json', limit=Decimal(config['budget_usd']))
    guard.cap_unknown(args.reservation_id, reason='http_error_without_usage',
        evidence_id='provider.jsonl/' + event['call_id'])
    summary = {key: value for key, value in guard.snapshot().items() if key != 'reservations'}
    proof = {'reservation_id': args.reservation_id, 'http_status': 400, 'call_id': event['call_id'],
        'execution_id': event['execution_id'], 'actual_cost': None,
        'policy': 'Full reserved upper bound consumed irreversibly; original call cannot be retried.',
        'budget': summary}
    (STATE / 'budget-reconciliation.json').write_text(json.dumps(proof, indent=2))
    print(json.dumps(proof))


if __name__ == '__main__':
    main()
