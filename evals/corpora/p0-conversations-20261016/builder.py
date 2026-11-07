"""Build ten synthetic conversations and independent answer oracles; never call an agent."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from decimal import Decimal, ROUND_HALF_UP
from zipfile import ZIP_STORED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / 'fixtures'
FIXED_ZIP_DATE = (2026, 10, 16, 0, 0, 0)
CORPUS_ID = 'p0-conversations-20261016'


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def write_csv(path, rows):
    with path.open('w', newline='', encoding='utf-8') as stream:
        csv.writer(stream, lineterminator='\n').writerows(rows)


def deterministic_zip(path, entries):
    with ZipFile(path, 'w', compression=ZIP_STORED) as archive:
        for name, content in sorted(entries.items()):
            info = ZipInfo(name, FIXED_ZIP_DATE)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, content)


def normalize_xlsx(path):
    # Timestamps and relationship IDs are packaging metadata, not test inputs.
    with ZipFile(path) as archive:
        entries = {name: archive.read(name) for name in archive.namelist()}
    identifiers = {}
    for name, content in sorted(entries.items()):
        if name.endswith('.rels'):
            for index, match in enumerate(re.finditer(rb'\bId="([^"]+)"', content)):
                identifiers[match[1]] = b'R' + hashlib.sha256(f'{name}:{index}'.encode()).hexdigest()[:16].encode()
    for name, content in entries.items():
        if name.endswith(('.xml', '.rels')):
            for previous, stable in identifiers.items():
                content = content.replace(b'"' + previous + b'"', b'"' + stable + b'"')
            entries[name] = content
    if 'docProps/core.xml' in entries:
        entries['docProps/core.xml'] = re.sub(
            rb'(<dcterms:(?:created|modified)[^>]*>).*?(</dcterms:(?:created|modified)>)',
            rb'\g<1>2026-10-16T00:00:00Z\g<2>', entries['docProps/core.xml'])
    deterministic_zip(path, entries)


def build_pdf():
    from reportlab.pdfgen.canvas import Canvas
    canvas = Canvas(str(FIXTURES / 'project-brief.pdf'), pagesize=(595, 842), invariant=1)
    canvas.setTitle('Proyecto Faro - datos sinteticos')
    canvas.setAuthor('Regulay synthetic evaluation')
    pages = [
        ['PROYECTO FARO', 'Ficha sintetica de evaluacion - pagina 1', '',
         'Objetivo: revisar 120 sensores de prueba.', 'Inicio: 2 de noviembre de 2026.',
         'Fecha limite: 6 de noviembre de 2026.', 'Presupuesto total: 4.800 EUR.',
         'Distribucion: materiales 1.800 EUR; trabajo 3.000 EUR.'],
        ['CRITERIOS DE ACEPTACION', 'Ficha sintetica de evaluacion - pagina 2', '',
         'Cada sensor debe superar las pruebas A y B.',
         'Un sensor que falle cualquiera de ellas no se acepta.',
         'Resultado del lote piloto: 18 aceptados de 20 examinados.',
         'La ficha no indica quien dirige el proyecto.',
         'La ficha no permite extrapolar el resultado piloto a los 120 sensores.'],
    ]
    for lines in pages:
        for index, line in enumerate(lines):
            canvas.setFont('Helvetica-Bold' if index == 0 else 'Helvetica', 16 if index == 0 else 11)
            canvas.drawString(46, 790 - index * 28, line)
        canvas.showPage()
    canvas.save()


def build_inputs(node):
    FIXTURES.mkdir(exist_ok=True)
    (ROOT / 'verification').mkdir(exist_ok=True)
    write_csv(FIXTURES / 'sales.csv', [
        ['order_id', 'region', 'product', 'quantity', 'unit_price_eur', 'status'],
        ['S01', 'Norte', 'Luz', 7, '10.00', 'completed'],
        ['S02', 'Norte', 'Base', 2, '25.00', 'completed'],
        ['S03', 'Sur', 'Base', 4, '25.00', 'completed'],
        ['S04', 'Sur', 'Luz', 3, '10.00', 'completed'],
        ['S05', 'Norte', 'Luz', -1, '10.00', 'refund'],
        ['S06', 'Este', 'Cable', 2, '8.00', 'completed'],
        ['S07', 'Norte', 'Base', 99, '25.00', 'cancelled'],
    ])
    write_json(FIXTURES / 'inventory-source.json', {
        'Productos': [['sku', 'stock_inicial', 'minimo'], ['A', 10, 8], ['B', 6, 5], ['C', 0, 3]],
        'Movimientos': [['sku', 'tipo', 'unidades'], ['C', 'salida', 3], ['A', 'entrada', 4],
                        ['B', 'salida', 2], ['C', 'entrada', 7], ['A', 'salida', 5]],
    })
    subprocess.run([str(node), str(ROOT / 'build_workbook.mjs')], check=True, cwd=ROOT)
    inspection = FIXTURES / 'inventory.xlsx.inspect.ndjson'
    if inspection.exists():
        inspection.replace(ROOT / 'verification' / inspection.name)
    normalize_xlsx(FIXTURES / 'inventory.xlsx')
    build_pdf()
    site = {
        'index.html': '<!doctype html>\n<html lang="es"><head><meta charset="utf-8"><title>Observatorio Nube</title>'
                      '<link rel="stylesheet" href="assets/style.css"></head><body><h1>Observatorio Nube</h1>'
                      '<p id="tagline">Datos claros, decisiones sencillas.</p><img src="assets/mark.svg" '
                      'alt="Marca Nube"><button>Explorar</button></body></html>\n',
        'assets/style.css': 'body { background: #fafafa; color: #202020; font-family: sans-serif; }\n'
                            'button { background: #2457d6; color: #ffffff; border: 0; padding: 12px; }\n',
        'assets/mark.svg': '<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">'
                           '<circle cx="32" cy="32" r="24" fill="#2457d6"/></svg>\n',
    }
    deterministic_zip(FIXTURES / 'site.zip', {k: v.encode('utf-8') for k, v in site.items()})
    write_json(FIXTURES / 'simulation.json', {
        'initial_stock': 12, 'days': 10, 'demands': [3, 4, 2, 5, 1, 3, 4, 2, 6, 1],
        'arrivals': {'4': 8, '8': 6},
        'rules': ['Receive arrivals at the start of each day.',
                  'Served demand is min(stock, demand). Unserved demand is lost, not backordered.',
                  'Closing stock equals opening stock plus arrivals minus served demand.'],
    })
    write_csv(FIXTURES / 'orders.csv', [
        ['order_id', 'status', 'amount_eur'], ['O1', 'completed', '120.00'],
        ['O2', 'completed', '80.00'], ['O3', 'cancelled', '50.00'],
        ['O4', 'completed', '75.00'], ['O4', 'completed', '75.00'],
        ['O5', 'completed', '40.00'], ['O5', 'completed', '45.00'],
    ])
    write_json(FIXTURES / 'reconciliation.json', {
        'reported_collections_eur': '320.00',
        'payments': [{'order_id': 'O1', 'amount_eur': '120.00'}, {'order_id': 'O2', 'amount_eur': '80.00'},
                     {'order_id': 'O3', 'amount_eur': '50.00'}, {'order_id': 'O4', 'amount_eur': '70.00'}],
        'rules': ['Deduplicate identical order rows.', 'A conflicting duplicate amount makes that order uncertain.',
                  'Exclude cancelled orders from valid sales and valid collections.',
                  'Do not assume which of two conflicting amounts is correct.'],
    })
    build_reconciliation_archive()


def build_reconciliation_archive():
    deterministic_zip(FIXTURES / 'reconciliation-inputs.zip', {
        name: (FIXTURES / name).read_bytes() for name in ('orders.csv', 'reconciliation.json')
    })


def oracle():
    """Re-open fixture bytes and calculate, independently of model output or turns."""
    from openpyxl import load_workbook
    from pypdf import PdfReader
    regional = {}
    with (FIXTURES / 'sales.csv').open(encoding='utf-8', newline='') as stream:
        sales = list(csv.DictReader(stream))
    for row in sales:
        if row['status'] == 'cancelled':
            continue
        regional[row['region']] = regional.get(row['region'], Decimal(0)) + Decimal(row['quantity']) * Decimal(row['unit_price_eur'])
    workbook = load_workbook(FIXTURES / 'inventory.xlsx', read_only=True, data_only=True)
    stock = {row[0]: row[1] for row in list(workbook['Productos'].values)[1:]}
    minimum = {row[0]: row[2] for row in list(workbook['Productos'].values)[1:]}
    for sku, direction, count in list(workbook['Movimientos'].values)[1:]:
        stock[sku] += count * (1 if direction == 'entrada' else -1)
    workbook.close()
    pdf = PdfReader(FIXTURES / 'project-brief.pdf')
    assert len(pdf.pages) == 2 and '18 aceptados de 20' in pdf.pages[1].extract_text()
    simulation = json.loads((FIXTURES / 'simulation.json').read_text(encoding='utf-8'))
    balance, days = simulation['initial_stock'], []
    for day, demand in enumerate(simulation['demands'], 1):
        opening = balance
        arrival = simulation['arrivals'].get(str(day), 0)
        served = min(balance + arrival, demand)
        balance += arrival - served
        days.append({'day': day, 'opening': opening, 'arrivals': arrival, 'demand': demand,
                     'served': served, 'lost': demand - served, 'closing': balance})
    with (FIXTURES / 'orders.csv').open(encoding='utf-8', newline='') as stream:
        orders = list(csv.DictReader(stream))
    unique = {tuple(sorted(row.items())) for row in orders}
    grouped = {}
    for items in unique:
        row = dict(items)
        grouped.setdefault(row['order_id'], []).append(row)
    known = {key: rows[0] for key, rows in grouped.items() if len(rows) == 1 and rows[0]['status'] == 'completed'}
    reconciliation = json.loads((FIXTURES / 'reconciliation.json').read_text(encoding='utf-8'))
    payments = {row['order_id']: Decimal(row['amount_eur']) for row in reconciliation['payments']}
    known_sales = sum(Decimal(row['amount_eur']) for row in known.values())
    known_collections = sum(payments.get(key, Decimal(0)) for key in known)
    resolved_o5 = Decimal('40.00')  # Explicit new fact supplied by c10.t02.
    subtotal = Decimal(3) * Decimal('19.95') + Decimal(2) * Decimal('7.50')
    discounted = (subtotal * Decimal('0.90')).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    vat = (discounted * Decimal('0.21')).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    return {
        'context': {'event': 'Nébula', 'city': 'Bilbao', 'time': '18:30', 'day': 'sábado'},
        'arithmetic': {'subtotal_eur': str(subtotal), 'discounted_eur': str(discounted), 'vat_eur': str(vat), 'total_eur': str(discounted + vat)},
        'sales': {'regions_eur': {k: str(v.quantize(Decimal('0.01'))) for k, v in sorted(regional.items())},
                  'total_eur': str(sum(regional.values()).quantize(Decimal('0.01'))),
                  'top_region': max(regional, key=regional.get), 'cancelled_rows_excluded': 1},
        'inventory': {'closing_by_sku': stock, 'replenishment': {k: minimum[k] - v for k, v in stock.items() if v < minimum[k]}},
        'pdf': {'pages': 2, 'budget_eur': 4800, 'deadline': '2026-11-06', 'pilot_acceptance_percent': 90,
                'project_owner': None, 'population_acceptance_percent': None},
        'simulation': {'days': days, 'served_total': sum(d['served'] for d in days),
                       'lost_total': sum(d['lost'] for d in days), 'closing_stock': balance,
                       'days_with_loss': [d['day'] for d in days if d['lost']]},
        'reconciliation': {'identical_duplicate': 'O4', 'conflicting_duplicate': 'O5', 'cancelled_payment': 'O3',
                           'known_valid_sales_eur': str(known_sales),
                           'known_valid_collections_eur': str(known_collections),
                           'known_outstanding_eur': str(sum(Decimal(row['amount_eur']) - payments.get(key, Decimal(0)) for key, row in known.items())),
                           'reported_collections_error_eur': str(Decimal(reconciliation['reported_collections_eur']) - known_collections),
                           'resolved_valid_sales_eur': str(known_sales + resolved_o5),
                           'resolved_outstanding_eur': str(known_sales + resolved_o5 - known_collections)},
    }


def turn(id, prompt, rubric, attachments=()):
    return {'id': id, 'prompt': prompt, 'attachments': [f'fixtures/{name}' for name in attachments], 'rubric': rubric}


def case(id, title, difficulty, profile, turns, entry='api'):
    return {'id': id, 'title': title, 'difficulty': difficulty, 'desired_work_profile': profile,
            'preferred_entry': entry, 'turns': turns}


def build_cases():
    return {
        'schema_version': 1, 'corpus_id': CORPUS_ID, 'language': 'es',
        'constraints': {'conversations': 10, 'turns': 17, 'synthetic_only': True,
                        'sequential_execution': True, 'max_output_tokens_suggested': 1600,
                        'paid_execution_requires_numeric_budget': True,
                        'never_send_rubric_or_oracle_to_model': True},
        'conversations': [
            case('c01', 'Corrección de contexto', 'easy', 'short_text', [
                turn('t01', 'Organizamos el evento ficticio Nébula en Sevilla el sábado a las 18:30. Confirma estos tres datos en una frase.',
                     {'facts': ['Nébula', 'Sevilla', 'sábado', '18:30'], 'sandbox_expected': False}),
                turn('t02', 'Corrección: la ciudad será Bilbao. Mantén todo lo demás. Confirma el cambio en una frase.',
                     {'facts': ['Bilbao', '18:30'], 'forbidden_current_facts': ['Sevilla'], 'sandbox_expected': False}),
                turn('t03', '¿Dónde y cuándo es al final el evento? Responde en una sola línea.',
                     {'oracle_ref': 'context', 'facts': ['Bilbao', 'sábado', '18:30'], 'forbidden_current_facts': ['Sevilla'], 'sandbox_expected': False}),
            ], 'web_sync'),
            case('c02', 'Aritmética y redondeo', 'easy', 'short_text', [
                turn('t01', 'Un pedido ficticio tiene 3 piezas a 19,95 EUR y 2 a 7,50 EUR. Aplica un descuento del 10%; redondea esa base a céntimos con mitad hacia arriba y calcula después el IVA del 21%, redondeado igual. Indica subtotal, base descontada, IVA y total. Respuesta breve.',
                     {'oracle_ref': 'arithmetic', 'numeric_tolerance': '0.00', 'sandbox_expected': False}),
            ]),
            case('c03', 'Ventas y reentrega de archivo', 'medium', 'bounded', [
                turn('t01', 'Analiza el adjunto: ignora pedidos cancelled y resta las devoluciones refund, cuyas cantidades ya son negativas. Indica ingresos netos por región, total y región líder. Crea resumen.csv con columnas region,net_revenue_eur y una fila TOTAL; usa punto decimal y dos decimales.',
                     {'oracle_ref': 'sales', 'artifacts': [{'format': 'csv', 'filename': 'resumen.csv', 'columns': ['region', 'net_revenue_eur'], 'rows': 4}]} , ['sales.csv']),
                turn('t02', 'Dámelo otra vez.', {'reissue_from': 't01', 'same_artifact_id': True, 'same_sha256': True, 'new_provider_calls': 0}),
            ], 'web_stream'),
            case('c04', 'Cruce de dos hojas', 'medium', 'bounded', [
                turn('t01', 'Analiza el libro adjunto. Une Productos y Movimientos por sku, aunque las filas estén en distinto orden. Calcula stock final de A, B y C; indica qué producto queda bajo su mínimo y cuántas unidades necesita para alcanzar ese mínimo. Responde aquí, sin crear archivos.',
                     {'oracle_ref': 'inventory', 'required_sheets': ['Productos', 'Movimientos'], 'artifacts': []}, ['inventory.xlsx']),
            ]),
            case('c05', 'Lectura de documento y límites de evidencia', 'medium', 'bounded', [
                turn('t01', 'Lee el documento adjunto completo. Dime presupuesto, fecha límite y porcentaje aceptado en el lote piloto, indicando la página de cada dato. ¿Quién dirige el proyecto y qué porcentaje de los 120 sensores se aceptará? Si el documento no lo permite saber, dilo. Responde aquí, sin crear archivos.',
                     {'oracle_ref': 'pdf', 'citations': {'budget_page': 1, 'deadline_page': 1, 'pilot_page': 2},
                      'must_acknowledge_unknown': ['project_owner', 'population_acceptance_percent']}, ['project-brief.pdf']),
            ], 'web_sync'),
            case('c06', 'Crear, recuperar y editar una página', 'medium', 'bounded', [
                turn('t01', 'Crea un HTML autónomo llamado nebula.html para el evento ficticio Nébula. Debe mostrar Bilbao, sábado 18:30 y un botón Reservar con fondo #2457d6. Todo el estilo dentro del archivo, sin JavaScript ni recursos externos.',
                     {'artifacts': [{'format': 'html', 'filename': 'nebula.html', 'contains': ['Nébula', 'Bilbao', '18:30', 'Reservar', '#2457d6'], 'no_external_resources': True, 'no_scripts': True}]}),
                turn('t02', 'Dámelo.', {'reissue_from': 't01', 'same_artifact_id': True, 'same_sha256': True, 'new_provider_calls': 0}),
                turn('t03', 'Cambia únicamente el fondo del botón a #147d45 y conserva el resto. Genera la nueva revisión.',
                     {'revision_of': 't01', 'new_sha256': True, 'prior_revision_still_downloadable': True,
                      'artifacts': [{'format': 'html', 'contains': ['Nébula', 'Bilbao', '18:30', 'Reservar', '#147d45'], 'no_external_resources': True}]}),
            ], 'web_stream'),
            case('c07', 'Editar un paquete con dependencias', 'complex', 'bounded', [
                turn('t01', 'Modifica el paquete adjunto: cambia solamente el fondo del botón a #147d45. Genera un ZIP con la estructura y los nombres originales. Conserva el título, el texto y la imagen.',
                     {'artifacts': [{'format': 'zip', 'members': ['index.html', 'assets/style.css', 'assets/mark.svg'],
                                     'changed_member': 'assets/style.css', 'unchanged_members': ['index.html', 'assets/mark.svg'],
                                     'contains_in_changed_member': '#147d45', 'relative_dependencies_resolve': True}]}, ['site.zip']),
                turn('t02', 'Dámelo otra vez.', {'reissue_from': 't01', 'same_artifact_id': True, 'same_sha256': True, 'new_provider_calls': 0}),
            ]),
            case('c08', 'Consultar una página pública', 'medium', 'bounded', [
                turn('t01', 'Abre https://www.iana.org/help/example-domains y explica en dos frases para qué se reservan example.com y example.org. Incluye el enlace de la fuente consultada. Si no puedes acceder, indica ese fallo y no finjas haberla leído.',
                     {'external_dependency': 'https://www.iana.org/help/example-domains',
                      'expected_semantics': ['dominios de ejemplo para documentación', 'no disponibles para registro o transferencia'],
                      'source_url_required': True, 'successful_network_evidence_required_for_pass': True,
                      'network_failure_is_blocked_not_semantic_pass': True}),
            ], 'web_stream'),
            case('c09', 'Simulación reproducible de inventario', 'complex', 'bounded', [
                turn('t01', 'Ejecuta una simulación de inventario con el adjunto. Cada día recibe primero las entradas; atiende min(stock disponible, demanda); la demanda no atendida se pierde. Crea simulacion.csv con day,opening,arrivals,demand,served,lost,closing. Indica demanda atendida, perdida, stock final y días con pérdida. Limita el cálculo a los diez días dados; no uses azar.',
                     {'oracle_ref': 'simulation', 'actual_execution_evidence_required': True,
                      'artifacts': [{'format': 'csv', 'filename': 'simulacion.csv', 'rows': 10,
                                     'columns': ['day', 'opening', 'arrivals', 'demand', 'served', 'lost', 'closing']}],
                      'invariant': 'opening + arrivals = served + closing; demand = served + lost; nonnegative stock'}, ['simulation.json']),
            ]),
            case('c10', 'Reconciliación con datos contradictorios', 'complex', 'bounded', [
                turn('t01', 'Reconcílialo todo con el ZIP adjunto, que contiene orders.csv y reconciliation.json. Lee ambos archivos. Elimina duplicados idénticos, excluye cancelados de ventas y cobros válidos, y no elijas arbitrariamente un importe contradictorio. Indica ventas y cobros válidos que sí son ciertos, saldo pendiente cierto y errores detectados. Separa lo que no puedes resolver. Responde breve, sin crear archivos.',
                     {'oracle_ref': 'reconciliation', 'uncertain_order': 'O5',
                      'input_archive_members': ['orders.csv', 'reconciliation.json'],
                      'must_identify': ['identical_duplicate', 'conflicting_duplicate', 'cancelled_payment', 'reported_collections_error_eur']}, ['reconciliation-inputs.zip']),
                turn('t02', 'Confirmo que el importe correcto de O5 es 40,00 EUR y que no tiene ningún cobro. Actualiza las ventas válidas totales y el saldo pendiente total. No cambies ninguna otra regla.',
                     {'oracle_ref': 'reconciliation', 'numeric_keys': ['resolved_valid_sales_eur', 'resolved_outstanding_eur'], 'context_correction_required': True}),
            ], 'web_sync'),
        ],
    }


def manifest():
    paths = sorted(p for p in FIXTURES.rglob('*') if p.is_file())
    return {'corpus_id': CORPUS_ID, 'files': [{'path': p.relative_to(ROOT).as_posix(), 'size_bytes': p.stat().st_size,
                                             'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in paths]}


def validate(cases, expected):
    assert len(cases['conversations']) == 10
    assert sum(len(item['turns']) for item in cases['conversations']) == 17
    assert len({item['id'] for item in cases['conversations']}) == 10
    for item in cases['conversations']:
        for item_turn in item['turns']:
            for attachment in item_turn['attachments']:
                path = (ROOT / attachment).resolve()
                assert path.is_relative_to(FIXTURES) and path.is_file()
            if 'oracle_ref' in item_turn['rubric']:
                assert item_turn['rubric']['oracle_ref'] in expected
    assert expected['sales']['total_eur'] == '256.00'
    assert expected['arithmetic']['total_eur'] == '81.52'
    assert expected['inventory']['replenishment'] == {'B': 1}
    assert expected['reconciliation']['known_valid_sales_eur'] == '275.00'
    assert expected['reconciliation']['known_valid_collections_eur'] == '270.00'
    # The deliberately false reported total is 320: it includes a cancelled payment.
    assert expected['simulation']['served_total'] + expected['simulation']['lost_total'] == 31
    with ZipFile(FIXTURES / 'site.zip') as archive:
        assert archive.testzip() is None
        assert sorted(archive.namelist()) == ['assets/mark.svg', 'assets/style.css', 'index.html']
    with ZipFile(FIXTURES / 'reconciliation-inputs.zip') as archive:
        assert archive.testzip() is None
        assert sorted(archive.namelist()) == ['orders.csv', 'reconciliation.json']
        for name in archive.namelist():
            assert archive.read(name) == (FIXTURES / name).read_bytes()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify-only', action='store_true', help='Read fixtures and compare cases/oracles/manifest without regeneration.')
    runtime = Path(os.environ.get('USERPROFILE', str(Path.home()))) / '.cache/codex-runtimes/codex-primary-runtime/dependencies'
    parser.add_argument('--node', type=Path, default=runtime / 'node/bin/node.exe')
    args = parser.parse_args()
    if not args.verify_only:
        build_inputs(args.node)
    cases, expected = build_cases(), oracle()
    validate(cases, expected)
    documents = {'cases.json': cases, 'oracle.json': expected, 'manifest.json': manifest()}
    for name, value in documents.items():
        path = ROOT / name
        if args.verify_only:
            assert json.loads(path.read_text(encoding='utf-8')) == value, f'{name} does not match fixtures or builder'
        else:
            write_json(path, value)
    print(json.dumps({'status': 'verified' if args.verify_only else 'built', 'conversations': 10, 'turns': 17,
                      'fixtures': len(documents['manifest.json']['files']), 'model_calls': 0}))


if __name__ == '__main__':
    main()
