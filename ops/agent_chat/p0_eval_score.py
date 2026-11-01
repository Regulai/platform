"""Score saved P0 evidence offline. Never calls a model, imports Django or uses the network.

Usage: python ops/agent_chat/p0_eval_score.py EVIDENCE_DIRECTORY [--corpus PATH]
Only score.json and score.md are written, beside the existing results.json.
Prose matches are evidence for a human, never an automatic semantic approval.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from decimal import Decimal, InvalidOperation
import hashlib
from html.parser import HTMLParser
import io
import json
from pathlib import Path, PurePosixPath
import re
import unicodedata
from urllib.parse import unquote, urlsplit
from zipfile import ZipFile, BadZipFile

REPO = Path(__file__).resolve().parents[2]
DEFAULT_CORPUS = REPO / 'evals/corpora/p0-conversations-20261016'
MAX_ARTIFACT_BYTES = 20_000_000


def normalized(value):
    return ''.join(c for c in unicodedata.normalize('NFKD', str(value).casefold()) if not unicodedata.combining(c))


def check(name, passed=None, detail=None):
    return {'name': name, 'status': 'manual' if passed is None else 'pass' if passed else 'fail', 'detail': detail}


def decimal(value):
    result = Decimal(str(value))
    if not result.is_finite():
        raise ValueError('Non-finite number')
    return result


def csv_rows(raw, columns):
    reader = csv.DictReader(io.StringIO(raw.decode('utf-8-sig'), newline=''))
    if reader.fieldnames != columns:
        raise ValueError(f'Expected columns {columns}; found {reader.fieldnames}')
    rows = list(reader)
    if any(None in row or None in row.values() for row in rows):
        raise ValueError('CSV has an incomplete row or extra fields')
    return rows


def score_sales(raw, oracle):
    rows = csv_rows(raw, ['region', 'net_revenue_eur'])
    actual = {row['region']: decimal(row['net_revenue_eur']) for row in rows}
    expected = {key: decimal(value) for key, value in oracle['regions_eur'].items()}
    expected['TOTAL'] = decimal(oracle['total_eur'])
    return [check('sales_rows_and_amounts', len(rows) == len(actual) == 4 and actual == expected,
                  {'actual': actual, 'expected': expected}),
            check('sales_decimal_format', all(re.fullmatch(r'-?\d+\.\d{2}', row['net_revenue_eur']) for row in rows))]


def score_simulation(raw, oracle):
    fields = ['day', 'opening', 'arrivals', 'demand', 'served', 'lost', 'closing']
    rows = csv_rows(raw, fields)
    actual = [{key: decimal(row[key]) for key in fields} for row in rows]
    expected = [{key: decimal(row[key]) for key in fields} for row in oracle['days']]
    invariant = all(row['opening'] + row['arrivals'] == row['served'] + row['closing'] and
                    row['demand'] == row['served'] + row['lost'] and
                    all(value >= 0 for value in row.values()) and
                    row['served'] == min(row['opening'] + row['arrivals'], row['demand'])
                    for row in actual)
    continuity = all(actual[i]['opening'] == actual[i - 1]['closing'] for i in range(1, len(actual)))
    return [check('simulation_ten_days', actual == expected, {'actual': actual, 'expected': expected}),
            check('simulation_stock_invariants', bool(actual) and invariant and continuity)]


class HtmlEvidence(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.tokens, self.text, self.buttons, self.resources, self.active = [], [], [], [], []
        self.feed(text)
        self.close()

    def handle_starttag(self, tag, attrs):
        attrs = [(key, value or '') for key, value in attrs]
        self.tokens.append(('start', tag, sorted(attrs)))
        if tag == 'button':
            self.buttons.append(dict(attrs))
        if tag in ('script', 'iframe', 'object', 'embed'):
            self.active.append(tag)
        for key, value in attrs:
            if key.startswith('on') or value.lstrip().lower().startswith('javascript:'):
                self.active.append(key)
            if key in ('src', 'href', 'poster', 'data', 'action') and value:
                self.resources.append(value)
            if key == 'srcset':
                self.resources.extend(part.strip().split()[0] for part in value.split(',') if part.strip())

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        self.tokens.append(('end', tag))

    def handle_data(self, data):
        value = ' '.join(data.split())
        if value:
            self.tokens.append(('text', value))
            self.text.append(value)


def color(value):
    value = re.sub(r'\s+', '', value.lower()).replace('!important', '')
    match = re.fullmatch(r'rgb\((\d+),(\d+),(\d+)\)', value)
    if match and all(int(part) <= 255 for part in match.groups()):
        return '#' + ''.join(f'{int(part):02x}' for part in match.groups())
    return value


def button_background(text):
    """Return an unambiguous literal declaration span, never pretend to compute CSS."""
    parsed = HtmlEvidence(text)
    if len(parsed.buttons) != 1:
        return None
    button = parsed.buttons[0]
    selectors = {'button'}
    if button.get('id'):
        selectors.add('#' + button['id'])
        selectors.add('button#' + button['id'])
    for item in button.get('class', '').split():
        selectors.add('.' + item)
        selectors.add('button.' + item)
    candidates = []
    declaration = re.compile(r'(?<![-\w])background(?:-color)?\s*:\s*([^;}]+)', re.I)
    # This deliberately declines CSS variables, pseudo states, nested rules and cascade ambiguity.
    for style in re.finditer(r'<style\b[^>]*>(.*?)</style\s*>', text, re.I | re.S):
        for rule in re.finditer(r'([^{}]+)\{([^{}]*)\}', style[1]):
            if rule[1].strip() in selectors:
                for match in declaration.finditer(rule[2]):
                    start = style.start(1) + rule.start(2) + match.start(1)
                    candidates.append((start, start + len(match[1]), color(match[1])))
    for tag in re.finditer(r'<button\b[^>]*>', text, re.I | re.S):
        for style in re.finditer(r'\bstyle\s*=\s*([\'"])(.*?)\1', tag[0], re.I | re.S):
            for match in declaration.finditer(style[2]):
                start = tag.start() + style.start(2) + match.start(1)
                candidates.append((start, start + len(match[1]), color(match[1])))
    return candidates[0] if len(candidates) == 1 and re.fullmatch(r'#[0-9a-f]{6}', candidates[0][2]) else None


def html_checks(raw, specification):
    text = raw.decode('utf-8-sig')
    html = HtmlEvidence(text)
    results = []
    for fact in specification.get('contains', []):
        if fact.startswith('#'):
            background = button_background(text)
            results.append(check('html_button_background', None if background is None else background[2] == fact,
                                 {'expected': fact, 'observed': background[2] if background else 'CSS requires manual inspection'}))
        else:
            results.append(check('html_contains_' + fact, normalized(fact) in normalized(' '.join(html.text))))
    if specification.get('no_scripts'):
        results.append(check('html_no_scripts_or_active_elements', not html.active, html.active))
    if specification.get('no_external_resources'):
        resources = html.resources + re.findall(r'url\(\s*[\'"]?([^\)\'\"]+)', text, re.I)
        outside = [url for url in resources if not url.startswith(('#', 'data:'))]
        imports = re.findall(r'@import\s+[^;]+', text, re.I)
        results.append(check('html_self_contained', not outside and not imports, outside + imports))
    return results


def revision_content(old_raw, new_raw):
    old, new = old_raw.decode('utf-8-sig'), new_raw.decode('utf-8-sig')
    before, after = button_background(old), button_background(new)
    if before is None or after is None:
        return check('html_only_button_background_changed', None, 'CSS is outside the conservative parser; inspect diff manually')
    before_text = old[:before[0]] + '__P0_BACKGROUND__' + old[before[1]:]
    after_text = new[:after[0]] + '__P0_BACKGROUND__' + new[after[1]:]
    same = HtmlEvidence(before_text).tokens == HtmlEvidence(after_text).tokens
    # A DOM/CSS formatting difference is not proof of unwanted semantic change.
    return check('html_only_button_background_changed', True if same else None,
                 'DOM and CSS equal after replacing the button background' if same else 'Other serialized differences require a human diff review')


def score_zip(raw, specification, original):
    with ZipFile(io.BytesIO(raw)) as archive, ZipFile(original) as source:
        infos = archive.infolist()
        if len(infos) > 128 or sum(item.file_size for item in infos) > MAX_ARTIFACT_BYTES:
            raise ValueError('Archive exceeds offline inspection limits')
        names = [item.filename for item in infos if not item.is_dir()]
        safe = all(not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts
                   and '\\' not in name and ':' not in name for name in names)
        if not safe or len(names) != len(set(names)):
            raise ValueError('Archive has unsafe paths or duplicate members')
        results = [check('zip_crc', archive.testzip() is None),
                   check('zip_exact_members', sorted(names) == sorted(specification['members']), names)]
        for name in specification['unchanged_members']:
            results.append(check('zip_unchanged_' + name, name in names and archive.read(name) == source.read(name)))
        name = specification['changed_member']
        if name not in names:
            results.append(check('zip_changed_member', False, f'Missing {name}'))
        else:
            old, new = source.read(name).decode('utf-8'), archive.read(name).decode('utf-8')
            # The fixture uses one direct button rule. Whitespace-only reformatting is accepted.
            expected = old.replace('#2457d6', specification['contains_in_changed_member'])
            compact = lambda value: re.sub(r'\s+', '', value)
            results.append(check('zip_only_expected_color_change', compact(new) == compact(expected)))
        unresolved = []
        for name in names:
            if name.endswith('.html'):
                references = HtmlEvidence(archive.read(name).decode('utf-8')).resources
            elif name.endswith('.css'):
                references = re.findall(r'url\(\s*[\'"]?([^\)\'\"]+)', archive.read(name).decode('utf-8'), re.I)
            else:
                continue
            for reference in references:
                if reference.startswith(('#', 'data:')):
                    continue
                parsed = urlsplit(reference)
                target = (PurePosixPath(name).parent / unquote(parsed.path)).as_posix()
                if parsed.scheme or parsed.netloc or target not in names:
                    unresolved.append({'member': name, 'reference': reference})
        results.append(check('zip_relative_dependencies', not unresolved, unresolved))
        return results


def read_artifact(evidence, download):
    relative = download.get('evidence_file')
    if not isinstance(relative, str):
        raise ValueError('No saved artifact bytes')
    path = (evidence / relative).resolve()
    if not path.is_relative_to(evidence) or not path.is_file():
        raise ValueError('Artifact path is missing or escapes evidence directory')
    if path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise ValueError('Artifact exceeds offline inspection size')
    return path.read_bytes()


def answer_text(turn):
    value = turn.get('snapshot', {}).get('result', {}).get('assistant_message', {})
    return value.get('content', '') if isinstance(value, dict) else ''


def numeric_evidence(text, expected, prefix=''):
    evidence = []
    if isinstance(expected, dict):
        for key, value in expected.items():
            evidence.extend(numeric_evidence(text, value, prefix + '.' + key if prefix else key))
    elif not isinstance(expected, (list, bool)) and expected is not None:
        try:
            number = decimal(expected)
        except (ValueError, InvalidOperation):
            return []
        forms = {str(expected), str(expected).replace('.', ','), format(number.normalize(), 'f')}
        matched = any(re.search(r'(?<![\d.,])' + re.escape(form) + r'(?![\d.,])', text) for form in forms)
        evidence.append({'oracle_key': prefix, 'expected': str(expected), 'literal_found': matched,
                         'interpretation': 'manual: presence does not establish the quantity or claim'})
    return evidence


def score_turn(case_id, wanted, actual, previous, evidence, corpus, oracle):
    if actual is None:
        return {'id': wanted['id'], 'status': 'not_run', 'checks': [], 'manual_review': []}
    rubric = wanted['rubric']
    checks, manual, files = [], [], {}
    checks.append(check('execution_completed', actual.get('status') == 'completed', actual.get('status')))
    downloads = actual.get('downloads', [])
    for item in downloads:
        identity = str(item.get('id'))
        try:
            raw = read_artifact(evidence, item)
            digest = hashlib.sha256(raw).hexdigest()
            hashes = [item.get(key) for key in ('sha256', 'download_sha256') if item.get(key)]
            checks.append(check('artifact_integrity_' + identity, item.get('download_status') == 200 and
                                bool(hashes) and all(value == digest for value in hashes) and
                                item.get('download_bytes') == len(raw), {'sha256': digest, 'bytes': len(raw)}))
            checks.append(check('artifact_other_tenant_denied_' + identity,
                                None if 'other_tenant_status' not in item else item['other_tenant_status'] == 404))
            files.setdefault(item.get('format'), []).append((item, raw))
        except (OSError, ValueError) as error:
            checks.append(check('artifact_read_' + identity, False, str(error)))
    for specification in rubric.get('artifacts', []):
        kind = specification['format']
        candidates = files.get(kind, [])
        checks.append(check('required_artifact_' + kind, len(candidates) == 1, {'count': len(candidates)}))
        if len(candidates) != 1:
            continue
        item, raw = candidates[0]
        if specification.get('filename'):
            filename = item.get('filename') or item.get('name')
            checks.append(check('artifact_filename', None if filename is None else filename == specification['filename'],
                                {'expected': specification['filename'], 'observed': filename}))
        try:
            if case_id == 'c03' and kind == 'csv':
                checks += score_sales(raw, oracle['sales'])
            elif case_id == 'c09' and kind == 'csv':
                checks += score_simulation(raw, oracle['simulation'])
            elif kind == 'html':
                checks += html_checks(raw, specification)
            elif kind == 'zip':
                checks += score_zip(raw, specification, corpus / 'fixtures/site.zip')
        except (ValueError, InvalidOperation, UnicodeError, KeyError, BadZipFile, RuntimeError, csv.Error) as error:
            checks.append(check('artifact_content_' + kind, False, str(error)))
    if rubric.get('reissue_from'):
        old = previous.get(rubric['reissue_from'], {})
        identities = lambda value: sorted((str(row.get('id')), row.get('download_sha256')) for row in value.get('downloads', []))
        checks.append(check('reissue_same_ids_and_hashes', bool(downloads) and identities(actual) == identities(old),
                            {'before': identities(old), 'after': identities(actual)}))
        checks.append(check('reissue_zero_provider_events', None if 'provider_events' not in actual else actual['provider_events'] == []))
    if rubric.get('revision_of'):
        old = previous.get(rubric['revision_of'], {})
        older = [row for row in old.get('downloads', []) if row.get('format') == 'html']
        if len(older) == 1 and len(files.get('html', [])) == 1:
            item, raw = files['html'][0]
            old_item = older[0]
            checks.append(check('revision_link', item.get('logical_id') is not None and item.get('logical_id') == old_item.get('logical_id') and
                                isinstance(item.get('revision'), int) and isinstance(old_item.get('revision'), int) and item['revision'] > old_item['revision']))
            checks.append(check('revision_new_bytes', item.get('download_sha256') != old_item.get('download_sha256')))
            try:
                checks.append(revision_content(read_artifact(evidence, old_item), raw))
            except (ValueError, UnicodeError, OSError) as error:
                checks.append(check('revision_comparison', False, str(error)))
        else:
            checks.append(check('revision_base', False, 'Base or new HTML missing'))
        if 'prior_revision_downloads' in actual:
            expected_prior = {str(row.get('id')): row.get('download_sha256') for row in older}
            prior = actual['prior_revision_downloads']
            checks.append(check('prior_revision_still_downloadable', bool(expected_prior) and
                                {str(row.get('id')) for row in prior} == set(expected_prior) and
                                all(row.get('http_status') == 200 and row.get('same_bytes') is True and
                                    row.get('sha256') == expected_prior.get(str(row.get('id'))) for row in prior)))
        else:
            manual.append('La descarga inicial no prueba que la revisión anterior siga accesible después de editar; falta una descarga posterior.')
    snapshot = actual.get('snapshot', {})
    operations = snapshot.get('operations', [])
    if rubric.get('actual_execution_evidence_required'):
        executed = [row for row in operations if row.get('name') == 'execute' and row.get('status') == 'completed']
        checks.append(check('simulation_execute_operation_completed', bool(executed), {'count': len(executed)}))
        manual.append('Relacionar el comando ejecutado con la simulación; una operación execute por sí sola no prueba qué calculó.')
    if rubric.get('sandbox_expected') is False:
        acquisitions = [row for row in snapshot.get('events', []) if row.get('kind') in ('sandbox_acquired', 'sandbox_prepared') or
                        row.get('data', {}).get('resource') == 'sandbox']
        checks.append(check('text_no_recorded_sandbox_acquisition', None if 'events' not in snapshot else not acquisitions,
                            {'event_count': len(acquisitions), 'scope': 'only recorded events'}))
    text = answer_text(actual)
    if not rubric.get('reissue_from'):
        manual.append('Revisar contenido visible, corrección contextual, afirmaciones, citas y datos desconocidos frente a la rúbrica. Las coincidencias literales no aprueban la respuesta.')
    if rubric.get('external_dependency'):
        manual.append('Comprobar apertura exitosa de la URL en fuentes/operaciones antes de aprobar la afirmación de haberla leído; un fallo externo es blocked.')
    events = actual.get('provider_events', [])
    result = {'id': wanted['id'], 'execution_status': actual.get('status'), 'checks': checks, 'manual_review': manual,
              'answer': text, 'literal_evidence': {fact: normalized(fact) in normalized(text) for fact in rubric.get('facts', [])},
              'numeric_evidence': numeric_evidence(text, oracle.get(rubric.get('oracle_ref'), {})),
              'trace_summary': {'wall_seconds': actual.get('wall_seconds'), 'provider_events': len(events),
                  'provider_statuses': dict(Counter(row.get('status', 'missing') for row in events)),
                  'provider_phases': dict(Counter(row.get('phase', 'missing') for row in events)),
                  'tools': dict(Counter(row.get('name', 'missing') for row in operations)),
                  'input_tokens_known': sum(row['input_tokens'] for row in events if type(row.get('input_tokens')) is int),
                  'output_tokens_known': sum(row['output_tokens'] for row in events if type(row.get('output_tokens')) is int),
                  'usage_complete': all(type(row.get('input_tokens')) is int and type(row.get('output_tokens')) is int for row in events)}}
    result['status'] = 'fail' if any(row['status'] == 'fail' for row in checks) else 'manual' if manual or any(row['status'] == 'manual' for row in checks) else 'pass'
    return result


def permission_denied(row):
    """A stream can return HTTP 200 while its final application result is 403."""
    try:
        if row.get('entry') == 'web_stream' and row.get('status') == 200:
            finals = []
            for block in row.get('body', '').replace('\r\n', '\n').split('\n\n'):
                lines = block.splitlines()
                if 'event: final' not in lines:
                    continue
                payload = json.loads('\n'.join(line[5:].lstrip() for line in lines if line.startswith('data:')))
                finals.append(payload)
            return len(finals) == 1 and finals[0].get('type') == 'final' and finals[0].get('http_status') == 403 and (
                finals[0].get('result', {}).get('error_type') == 'agent_access_denied' and
                finals[0].get('result', {}).get('success') is False)
        payload = json.loads(row.get('body', ''))
        return row.get('status') == 403 and payload.get('error_type') == 'agent_access_denied' and payload.get('success') is False
    except (ValueError, TypeError, AttributeError):
        return False


def control_checks(report):
    checks = []
    permission = report.get('permission_checks', {})
    rows = permission.get('no_grant', [])
    checks.append(check('no_grant_three_entries', None if not rows else len(rows) == 3 and
                        {row.get('entry') for row in rows} == {'api', 'web_sync', 'web_stream'} and
                        all(permission_denied(row) for row in rows) and permission.get('provider_calls') == 0))
    replays = report.get('idempotency', [])
    for entry in ('api', 'web_sync', 'web_stream'):
        matches = [row for row in replays if row.get('entry') == entry]
        checks.append(check('idempotency_' + entry, None if not matches else all(row.get('passed') and
                            row.get('counts_before') == row.get('counts_after') for row in matches)))
    budget = report.get('budget', {})
    try:
        limit, known, reserved, committed = [decimal(budget[key]) for key in ('limit_usd', 'known_cost_usd', 'reserved_usd', 'committed_usd')]
        capped = decimal(budget.get('capped_unknown_usd', '0'))
        checks.append(check('budget_bound', 0 < limit <= 5 and min(known, reserved, capped) >= 0 and known + reserved + capped == committed <= limit,
                            {key: budget.get(key, '0') for key in ('limit_usd', 'known_cost_usd', 'reserved_usd', 'capped_unknown_usd', 'committed_usd')}))
        unknown = budget.get('unknown_reservations', [])
        breached = budget.get('breached_reservations', [])
        checks.append(check('cost_usage_resolved', False if breached else None if unknown or reserved or capped else True,
                            {'unknown': unknown, 'reserved_usd': str(reserved), 'capped_unknown_usd': str(capped), 'breaches': breached}))
    except (KeyError, ValueError, InvalidOperation):
        checks.append(check('budget_evidence', None, 'Missing or invalid budget summary'))
    return checks


def evaluate(evidence, corpus):
    report = json.loads((evidence / 'results.json').read_text(encoding='utf-8'))
    cases = json.loads((corpus / 'cases.json').read_text(encoding='utf-8'))
    oracle = json.loads((corpus / 'oracle.json').read_text(encoding='utf-8'))
    if report.get('corpus_id') != cases['corpus_id']:
        raise ValueError('Results and corpus IDs differ')
    observed = {row['id']: row for row in report.get('conversations', [])}
    scored = []
    for case in cases['conversations']:
        actual_case = observed.get(case['id'], {})
        turns = {row['id']: row for row in actual_case.get('turns', [])}
        scored.append({'id': case['id'], 'title': case['title'], 'turns': [
            score_turn(case['id'], turn, turns.get(turn['id']), turns, evidence, corpus, oracle) for turn in case['turns']]})
    flat = [turn for case in scored for turn in case['turns']]
    return {'schema_version': 1, 'corpus_id': cases['corpus_id'], 'source': 'results.json',
            'source_sha256': hashlib.sha256((evidence / 'results.json').read_bytes()).hexdigest(),
            'scope': 'Offline artifact and trace checks; semantic quality remains manual.',
            'summary': dict(Counter(turn['status'] for turn in flat)), 'control_checks': control_checks(report),
            'conversations': scored, 'budget': {key: value for key, value in report.get('budget', {}).items() if key != 'reservations'}}


def markdown(score):
    lines = ['# Evaluación offline de las diez conversaciones', '',
             'Los estados `manual` requieren lectura humana. Una coincidencia numérica o textual no demuestra una respuesta correcta.', '',
             '| Caso | Turno | Resultado | Segundos | Llamadas proveedor | Comprobaciones fallidas |',
             '| --- | --- | --- | ---: | ---: | --- |']
    for case in score['conversations']:
        for turn in case['turns']:
            trace = turn.get('trace_summary', {})
            failures = ', '.join(row['name'] for row in turn['checks'] if row['status'] == 'fail') or '—'
            lines.append(f"| {case['id']} | {turn['id']} | {turn['status']} | {trace.get('wall_seconds', '—')} | {trace.get('provider_events', '—')} | {failures} |")
    lines += ['', 'Controles obligatorios:', '']
    lines.extend(f"- {row['name']}: {row['status']}." for row in score['control_checks'])
    lines += ['', 'El detalle, las respuestas visibles, las diferencias y la evidencia numérica están en `score.json`.',
              'No se ejecutaron modelos, herramientas del agente ni peticiones de red al puntuar.', '']
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--corpus', type=Path, default=DEFAULT_CORPUS)
    args = parser.parse_args()
    evidence, corpus = args.evidence.resolve(), args.corpus.resolve()
    score = evaluate(evidence, corpus)
    (evidence / 'score.json').write_text(json.dumps(score, ensure_ascii=False, indent=2, default=str) + '\n', encoding='utf-8')
    (evidence / 'score.md').write_text(markdown(score), encoding='utf-8')
    print(json.dumps({'summary': score['summary'], 'score': str(evidence / 'score.json')}, ensure_ascii=False))


if __name__ == '__main__':
    main()
