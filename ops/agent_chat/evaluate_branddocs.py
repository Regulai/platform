"""Deterministic synthetic evaluation of the pinned upstream; no inference."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile
from docx import Document
from document_fixture import create_template


def main():
    root = Path(__file__).resolve().parents[2]
    output = Path(sys.argv[1]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    engine = root / '.task51-branddocs-source/scripts/brandkit/cli.py'
    template = create_template(output / 'template.docx')
    rows = [[f'Concepto español {n:02d}: año, acción, piñón', f'{n},25 €'] for n in range(1, 66)]
    content = {'cover': {'title': 'Informe económico de España', 'subtitle': 'Año 2026'}, 'blocks': [
        {'type': 'heading', 'level': 1, 'runs': [{'t': 'Resumen ejecutivo'}]},
        {'type': 'paragraph', 'runs': [{'t': 'Análisis sintético con tildes, ñ y símbolos: 1.250,00 €, £ y $.'}]},
        {'type': 'list', 'ordered': True, 'items': [{'text': 'Comprobar los importes originales.'},
            {'text': 'Conservar la trazabilidad de las revisiones.'}]},
        {'type': 'table', 'role': 'default', 'columns': ['Concepto', 'Importe (€)'], 'rows': rows},
        {'type': 'heading', 'level': 1, 'runs': [{'t': 'Notas de revisión'}]},
        {'type': 'paragraph', 'runs': [{'t': 'Los importes se expresan en euros. Año 2026; revisión técnica.'}]}]}
    (output / 'content.json').write_text(json.dumps(content, ensure_ascii=False), encoding='utf-8')
    commands = []
    for name, args in [('doctor', ['doctor']), ('extract', ['extract', '--name', 'synthetic',
            '--template', str(template), '--scope', 'project']),
            ('generate', ['generate', '--name', 'synthetic', '--scope', 'project', '--qa', 'strict',
                '--input', str(output / 'content.json'), '--output', str(output / 'candidate.docx')])]:
        command = [sys.executable, str(engine), *args]
        result = subprocess.run(command, cwd=output, capture_output=True, timeout=240)
        (output / f'{name}.log').write_bytes(result.stdout + result.stderr)
        commands.append({'command': command, 'exit_code': result.returncode})
    result = {'commit': '97a6e384cb0664cd44ba8113c0b80c9761700670', 'commands': commands,
              'template_sha256': hashlib.sha256(template.read_bytes()).hexdigest()}
    candidate = output / 'candidate.docx'
    if candidate.exists():
        before, after = Document(template), Document(candidate)
        result['sections'] = [len(before.sections), len(after.sections)]
        with zipfile.ZipFile(template) as a, zipfile.ZipFile(candidate) as b:
            parts = [name for name in a.namelist() if name.startswith(('word/header', 'word/footer'))
                     or name == 'word/numbering.xml']
            result['unchanged_parts'] = {name: name in b.namelist() and a.read(name) == b.read(name) for name in parts}
        result['candidate_sha256'] = hashlib.sha256(candidate.read_bytes()).hexdigest()
    (output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
