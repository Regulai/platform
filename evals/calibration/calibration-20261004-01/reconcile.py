"""Read-only final reconciliation of the shared ledger, retaining every reservation."""
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal
from hashlib import sha256
import argparse
import importlib.util
import json
from pathlib import Path
import sqlite3

CAMPAIGN = Path(__file__).resolve().parent
ROOT = CAMPAIGN.parents[2]


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def write(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(CAMPAIGN) or output.exists():
        raise ValueError('Use a new evidence directory inside this campaign')
    source = ROOT / 'regulai/front/evaluation_budget.py'
    spec = importlib.util.spec_from_file_location('reconciled_budget', source)
    budget = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(budget)
    database = ROOT / '.claude/pilot-real-budget.sqlite3'
    before = digest(database)

    @contextmanager
    def readonly_transaction():
        connection = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)
        try:
            connection.execute('PRAGMA query_only=ON')
            yield connection
        finally:
            connection.close()

    # Do not invoke the constructor or the normal writer transaction.
    ledger = budget.EvaluationBudget.__new__(budget.EvaluationBudget)
    ledger.cap = Decimal('1.66')
    ledger.transaction = readonly_transaction
    snapshot = ledger.snapshot()
    with readonly_transaction() as connection:
        head = budget.EvaluationBudget.head(connection)
        terms = budget.EvaluationBudget.campaign_terms(connection, head)
        connection.row_factory = sqlite3.Row
        extensions = [dict(row) for row in connection.execute('SELECT * FROM approval_extensions ORDER BY sequence')]
        runs = [dict(row) for row in connection.execute('SELECT * FROM extension_runs ORDER BY rowid')]
    historical_path = CAMPAIGN / 'batches/baseline-smoke-02/activation.json'
    latest_path = CAMPAIGN / 'batches/r4-smoke-01/live-run-01/budget.json'
    historical = read(historical_path)['snapshot']
    latest = read(latest_path)
    assert snapshot == latest, 'Ledger changed after mandatory campaign stop'
    assert snapshot['calls'][:len(historical['calls'])] == historical['calls'], 'Historical calls changed'
    assert digest(database) == before, 'Ledger bytes changed during read-only reconciliation'
    fields = ('known_cost_usd', 'provider_reported_usd', 'tariff_estimated_usd',
              'budget_exposure_usd', 'uncertain_reservations_usd')
    new_calls = snapshot['calls'][len(historical['calls']):]
    new = {key: str(Decimal(snapshot[key]) - Decimal(historical[key])) for key in fields}
    report = {
        'completed_utc': datetime.now(timezone.utc).isoformat(),
        'database_open_mode': 'ro', 'query_only': True, 'ledger_bytes_unchanged': True,
        'ledger_sha256': before, 'historical_calls_unchanged': True,
        'matches_final_runtime_snapshot': True, 'cap_eur': '2.00', 'cap_usd': '1.66',
        'historical': {key: historical[key] for key in fields},
        'campaign_increment': new, 'total': {key: snapshot[key] for key in fields},
        'remaining_usd': snapshot['remaining_usd'],
        'conservative_total_exposure_eur': str(Decimal(snapshot['budget_exposure_usd']) * Decimal('1.35') / Decimal('1.1225')),
        'all_ledger_entries_n': len(snapshot['calls']), 'campaign_entries_n': len(new_calls),
        'campaign_entry_status': dict(Counter(call['status'] for call in new_calls)),
        'campaign_external_calls_n': sum(call['metadata'].get('scope_external_call') is True for call in new_calls),
        'campaign_external_calls_by_purpose': dict(Counter(call['purpose'] for call in new_calls
                                                        if call['metadata'].get('scope_external_call') is True)),
        'uncertain_calls': [call for call in snapshot['calls'] if call['cost'] is None],
        'authorization_head': head, 'campaign_terms': terms,
        'stop_new_paid_calls': True,
        'stop_reason': 'Invalid Jev response produced outcome_unknown; no automatic retry or subsequent calls',
        'unvalidated_charge_in_invalid_response_usd': '0.000035742',
        'charge_note': 'Not added to validated provider-reported totals; the full 0.003 USD reservation remains retained.',
        'cost_note': 'Known combines reported and estimated. Exposure retains tariff bounds and unknown reserves; do not add it to known costs.',
        'source_sha256': {str(path.relative_to(ROOT)): digest(path)
                          for path in (Path(__file__), source, historical_path, latest_path)},
    }
    assert report['campaign_external_calls_n'] == 49
    assert Decimal(report['conservative_total_exposure_eur']) < Decimal('2')
    output.mkdir(parents=True)
    write(output / 'ledger-snapshot.json', snapshot)
    write(output / 'authorization-chain.json', {'extensions': extensions, 'runs': runs})
    write(output / 'summary.json', report)
    print(json.dumps({key: report[key] for key in ('total', 'campaign_increment', 'remaining_usd',
          'conservative_total_exposure_eur', 'campaign_external_calls_n', 'historical_calls_unchanged')}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
