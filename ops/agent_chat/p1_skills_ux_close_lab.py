"""Remove only this turn's synthetic lab database after its server has stopped."""
import json
from pathlib import Path
import socket

import p1_skills_ux_lab as lab


def main():
    lab.owner_check()
    with socket.socket() as probe:
        if probe.connect_ex(('127.0.0.1', 8873)) == 0:
            raise RuntimeError('stop_owned_ui_server_before_removing_its_database')
    report = json.loads((lab.OUT / 'lab.json').read_text(encoding='utf-8'))
    if not report['fixture'] or report['database'] != lab.DATABASE or report['pg_container'] != lab.PG_ID:
        raise RuntimeError('synthetic_lab_receipt_mismatch')
    lab.configure(database=False)
    from django.db import connection
    assert connection.settings_dict['HOST'] == '127.0.0.1'
    assert str(connection.settings_dict['PORT']) == '55468'
    assert connection.settings_dict['NAME'] == 'postgres'
    with connection.cursor() as cursor:
        cursor.execute('SELECT count(*) FROM pg_stat_activity WHERE datname=%s', [lab.DATABASE])
        if cursor.fetchone()[0]:
            raise RuntimeError('synthetic_lab_has_active_connections')
        cursor.execute('DROP DATABASE ' + connection.ops.quote_name(lab.DATABASE))
    path = lab.OUT / 'private/browser-state.json'
    if path.exists():
        if not path.is_file() or path.is_symlink():
            raise RuntimeError('synthetic_browser_state_not_regular')
        path.unlink()
    receipt = {'fixture': True, 'database_removed': lab.DATABASE,
        'browser_state_removed': True, 'real_data_modified': False,
        'postgres_container_stopped': False, 'provider_requests': 0}
    (lab.OUT / 'lab-cleanup.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
