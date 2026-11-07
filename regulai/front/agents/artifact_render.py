"""Trusted sandbox renderer used by publication; no model-chosen preview bytes."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def render(source, destination, maximum):
    source, target = Path(source), Path(destination)
    target.mkdir(parents=True, exist_ok=False)
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    if source.suffix.lower() == '.pdf':
        pdf = source
    else:
        result = subprocess.run(['libreoffice', '-env:UserInstallation=file://' + str(target / 'lo'),
            '--headless', '--convert-to', 'pdf', '--outdir', str(target), str(source)],
            capture_output=True, timeout=90)
        pdf = target / (source.stem + '.pdf')
        if result.returncode or not pdf.is_file():
            raise ValueError('Document rendering failed: ' + result.stderr.decode(errors='replace')[:500])
    from pypdf import PdfReader
    pages = len(PdfReader(pdf).pages)
    if not 1 <= pages <= maximum:
        raise ValueError('Rendered page count exceeds budget')
    subprocess.run(['pdftoppm', '-png', '-r', '96', '-scale-to', '1400', str(pdf), str(target / 'page')],
        check=True, capture_output=True, timeout=90)
    images = sorted(target.glob('page-*.png'), key=lambda p: int(p.stem.split('-')[-1]))
    if len(images) != pages or hashlib.sha256(source.read_bytes()).hexdigest() != before:
        raise ValueError('Rendered source changed or page missing')
    return {'pdf_path': str(pdf), 'page_paths': [str(path) for path in images], 'source_sha256': before,
        'engine': 'libreoffice-poppler', 'pages': pages}


if __name__ == '__main__':
    print(json.dumps(render(sys.argv[1], sys.argv[2], int(sys.argv[3]))))
