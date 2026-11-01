"""Inspect known synthetic NER/citation failures with the current local runtime."""
from hashlib import sha256
import argparse
import json
from pathlib import Path
import socket
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'regulai'))
from front.local_masking import _load_model, mask_local_texts
from front.verification import verify_response


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = ROOT / args.output
    output.mkdir(parents=True, exist_ok=False)
    historical = ROOT / 'evals/reports/adversarial-community-20261003-02/http-results.jsonl'
    rows = [json.loads(line) for line in historical.read_text(encoding='utf-8').splitlines()]
    evidence = []
    with patch.object(socket.socket, 'connect', side_effect=AssertionError('Offline only')), \
            patch.object(socket, 'getaddrinfo', side_effect=AssertionError('Offline only')):
        nlp, metadata = _load_model()
        for row in rows:
            if not (row['case_id'] in ('INJ-05', 'DOC-03') and row['endpoint'] == '/api/chat/send/'
                    and row['provider_profile'] == 'neutral'):
                continue
            generation = next(event for event in row['boundary_events'] if event['purpose'] == 'generation')
            sent = json.loads(generation['body_utf8'])
            sources = json.loads(sent['messages'][-1]['content'].split('Sources:\n', 1)[1])
            fragment_ids = row['decision']['coverage']['fragment_hashes']
            fragments = [{**source, 'id': identifier} for source, identifier in zip(sources, fragment_ids)]
            aliases = {source['id']: identifier for source, identifier in zip(sources, fragment_ids)}
            original = generation['fixture_response_content']
            current = mask_local_texts([original], timeout=60)[0]
            kwargs = dict(fragments=fragments, alias_to_id=aliases, require_semantic=True)
            evidence.append(dict(case_id=row['case_id'], source_kind='historical_synthetic_fixture_new_local_execution',
                original=original, current_masked=current, before=verify_response(original, 'stop', **kwargs),
                after=verify_response(current, 'stop', **kwargs)))
        examples = ['Calcula 12 * 7 + 4. Responde con el resultado.',
            'Calcula 23 * 4 + 6. Responde con el resultado.',
            'Registro ficticio. El plazo es 19 días. Resume el plazo.',
            'Cita el título Contrato y explica qué es una Tarjeta en un juego.',
            'DNI/NIE: １２３４５６７８Ｚ. Plazo: 19 días. Total: 46 EUR.',
            'ＡＢＣ son letras; el precio es ４６ EUR.',
            'Ana vive en Madrid.', 'María López vive en Madrid.']
        entities = [dict(input=value, masked=mask_local_texts([value], timeout=60)[0],
            raw_ner=[dict(text=entity.text, label=entity.label_, start=entity.start_char, end=entity.end_char)
                     for entity in nlp(value).ents]) for value in examples]
    result = dict(runtime_sha256=sha256((ROOT / 'regulai/front/local_masking.py').read_bytes()).hexdigest(),
        source_report_sha256=sha256(historical.read_bytes()).hexdigest(), detector=metadata,
        citations=evidence, ner=entities, network_calls=0, api_cost='0',
        interpretation='Context-dependent NER corruption is reproduced. These fixtures do not establish its effect on live semantic scores.')
    (output / 'diagnosis.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(citations=[dict(id=item['case_id'], before=item['before']['local_status'],
        after=item['after']['local_status']) for item in evidence], output=str(output)), indent=2))


if __name__ == '__main__':
    main()
