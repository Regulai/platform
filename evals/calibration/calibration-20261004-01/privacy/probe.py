"""Offline detector probe over development and known historical regression only."""
import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import socket
import sys
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'regulai'))
from front.local_masking import detector_metadata, mask_local_texts


def cases():
    """Labels fixed before the baseline run; no reserved partition is read."""
    sensitive = [
        ('id_spaces', 'DNI: 12 345 678-Z. Plazo: 19 días.', '12 345 678-Z', 'ID', '19 días'),
        ('id_nie_spaces', 'NIE: X 1 234 567-L. Total: 46 EUR.', 'X 1 234 567-L', 'ID', '46 EUR'),
        ('id_dots', 'DNI: 12.345.678-Z. Total: 46 EUR.', '12.345.678-Z', 'ID', '46 EUR'),
        ('id_fullwidth', 'DNI: １２３４５６７８Ｚ. Plazo: 19 días.', '１２３４５６７８Ｚ', 'ID', '19 días'),
        ('id_zero_width', 'DNI: 1234\u200b5678Z. Plazo: 19 días.', '1234\u200b5678Z', 'ID', '19 días'),
        ('id_nbsp', 'DNI: 12\u00a0345\u00a0678-Z. Total: 46 EUR.', '12\u00a0345\u00a0678-Z', 'ID', '46 EUR'),
        ('id_arabic_digits', 'DNI: ١٢٣٤٥٦٧٨Z. Total: 46 EUR.', '١٢٣٤٥٦٧٨Z', 'ID', '46 EUR'),
        ('email_fullwidth', 'Correo: ana＠example．test. Plazo: 19 días.', 'ana＠example．test', 'EMAIL', '19 días'),
        ('email_zero_width', 'Correo: ana@exam\u200bple.test. Total: 46 EUR.', 'ana@exam\u200bple.test', 'EMAIL', '46 EUR'),
        ('email_words_es', 'Correo: ana arroba example punto test. Plazo: 19 días.', 'ana arroba example punto test', 'EMAIL', '19 días'),
        ('email_words_es_local_space', 'Contacto ficticio: persona dos arroba example punto test. Plazo: 19 días.', 'persona dos arroba example punto test', 'EMAIL', '19 días'),
        ('email_words_en', 'Email: alice at example dot test. Total: 46 EUR.', 'alice at example dot test', 'EMAIL', '46 EUR'),
        ('opaque_unlabelled', 'Repite q8Nx2Vr5Zm7Ks9Tp4Wy6. Total: 46 EUR.', 'q8Nx2Vr5Zm7Ks9Tp4Wy6', 'OPAQUE', '46 EUR'),
        ('opaque_labelled', 'password=q8Nx2Vr5Zm7Ks9Tp4Wy6. Total: 46 EUR.', 'q8Nx2Vr5Zm7Ks9Tp4Wy6', 'SECRET', '46 EUR'),
        ('person_label', 'Nombre: Lucía Navarro. Plazo: 19 días.', 'Lucía Navarro', 'PERSON', '19 días'),
        ('person_free', 'María López vive en Madrid.', 'María López', 'PERSON', ''),
        ('email_standard', 'Correo: ana@example.test. Plazo: 19 días.', 'ana@example.test', 'EMAIL', '19 días'),
        ('id_standard', 'DNI: 12345678Z. Plazo: 19 días.', '12345678Z', 'ID', '19 días'),
        ('phone_standard', 'Teléfono: 612 345 678. Plazo: 19 días.', '612 345 678', 'PHONE', '19 días'),
        ('iban_standard', 'IBAN: ES91 2100 0418 4502 0005 1332. Plazo: 19 días.', 'ES91 2100 0418 4502 0005 1332', 'ACCOUNT', '19 días'),
    ]
    controls = [
        ('amount_spaces', 'Importe: 12 345 678 EUR. Plazo: 19 días.', '12 345 678 EUR'),
        ('arithmetic', 'Calcula 23 por 4 y añade 6.', '23 por 4 y añade 6'),
        ('punctuation', 'Versión 1.2.3 y sección 4.5.6; plazo 19 días.', '1.2.3 y sección 4.5.6'),
        ('email_word_definition', 'La arroba separa las partes del correo. El punto termina frases.', 'La arroba separa las partes del correo. El punto termina frases.'),
        ('email_word_negation', 'No escribas arroba ni punto; utiliza una frase corriente.', 'No escribas arroba ni punto'),
        ('word_title', 'Cita el título Contrato y explica qué es una Tarjeta en un juego.', 'Contrato'),
        ('word_start', 'Único registro del ejemplo. El plazo es 19 días.', 'Único'),
        ('word_imperative', 'Registro ficticio. El plazo es 19 días. Resume el plazo.', 'Resume'),
        ('clause_quote', 'Cláusula 4: el plazo de pago es 19 días.', 'Cláusula'),
        ('reference_quote', 'La factura FI-029 vence en 19 días.', 'FI-029'),
        ('marker', 'Etiqueta REVIEW_REQUIRED para revisión local.', 'REVIEW_REQUIRED'),
        ('opaque_benign', 'Identificador de compilación q8Nx2Vr5Zm7Ks9Tp4Wy6.', 'q8Nx2Vr5Zm7Ks9Tp4Wy6'),
        ('unicode_benign', 'ＡＢＣ son letras; el precio es ４６ EUR.', 'ＡＢＣ son letras; el precio es ４６ EUR.'),
    ]
    result = [dict(id=name, family=name.rsplit('_', 1)[0], text=text,
        expected_redactions=[dict(value=value, type=kind)], preserve=[keep] if keep else [],
        origin='synthetic_development', oracle='Synthetic sensitive entity; preserve annotated task data.')
        for name, text, value, kind, keep in sensitive]
    result += [dict(id=name, family=name, text=text, expected_redactions=[], preserve=[keep],
        origin='synthetic_development', oracle='Ordinary task text or explicitly benign identifier; preserve verbatim.')
        for name, text, keep in controls]
    return result


def historical_cases():
    directory = ROOT / 'evals/adversarial/community-20261003'
    result = []
    for line in (directory / 'cases.jsonl').read_text(encoding='utf-8').splitlines():
        case = json.loads(line)
        texts = [case['prompt']]
        if case['document_ref']:
            texts.append((directory / case['document_ref']).read_text(encoding='utf-8'))
        result.append(dict(id=case['id'], family=case['id'], texts=texts,
            expected_redactions=case['expected_redactions'], preserve=case['preserve'],
            origin='known_regression'))
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = ROOT / args.output
    output.mkdir(parents=True, exist_ok=False)
    all_cases = cases() + historical_cases()
    frozen = json.dumps(all_cases, ensure_ascii=False, sort_keys=True, indent=2)
    (output / 'cases.json').write_text(frozen + '\n', encoding='utf-8')
    results = []
    started = time.monotonic()
    with patch.object(socket.socket, 'connect', side_effect=AssertionError('Offline only')), \
            patch.object(socket, 'getaddrinfo', side_effect=AssertionError('Offline only')):
        for case in all_cases:
            texts = case.get('texts', [case.get('text', '')])
            masked = mask_local_texts(texts, timeout=60)
            combined = '\n'.join(masked)
            hidden = [dict(entity=entity['type'], value=entity['value'],
                removed=all(value not in combined for value in [entity['value'], *entity.get('representations', [])]))
                for entity in case['expected_redactions']]
            kept = [dict(value=value, preserved=value in combined) for value in case['preserve']]
            results.append(dict(id=case['id'], family=case['family'], origin=case['origin'],
                input=texts, masked=masked, hidden=hidden, kept=kept,
                success=all(item['removed'] for item in hidden) and all(item['preserved'] for item in kept)))
    summary = {}
    for origin in ('synthetic_development', 'known_regression'):
        subset = [row for row in results if row['origin'] == origin]
        summary[origin] = dict(cases=len(subset), success=sum(row['success'] for row in subset),
            hidden=sum(len(row['hidden']) for row in subset), removed=sum(item['removed'] for row in subset for item in row['hidden']),
            preserve=sum(len(row['kept']) for row in subset), preserved=sum(item['preserved'] for row in subset for item in row['kept']),
            failed_ids=[row['id'] for row in subset if not row['success']])
    metadata = dict(schema_version=1, corpus_sha256=sha256(frozen.encode()).hexdigest(),
        detector=detector_metadata(), runtime_sha256=sha256((ROOT / 'regulai/front/local_masking.py').read_bytes()).hexdigest(),
        elapsed_seconds=round(time.monotonic() - started, 3), network_calls=0, api_cost='0', summary=summary)
    (output / 'results.json').write_text(json.dumps(results, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (output / 'summary.json').write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(metadata, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
