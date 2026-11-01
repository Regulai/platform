"""Fetch pinned public DATA only; never import or execute downloaded files."""
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'evals/calibration/calibration-20261004-01/corpus/sources'
REVISIONS = {
    'llmail': '1063bdf01ec8762b812d5e06ee768a06faa5a6f7',
    'gretel': '7b844d16738527a04264f50214cb426a4cea0897',
    'pint': '0efab3f463eae9c823130d8faffb71b2e7c06e63',
    'bipia': 'a004b69ec0dd446e0afd461d98cb5e96e120a5d0',
    'gsm8k': '3101c7d5072418e28b9008a6636bde82a006892c',
}
BASES = {
    'llmail': 'https://huggingface.co/datasets/microsoft/llmail-inject-challenge/resolve/',
    'gretel': 'https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual/resolve/',
    'pint': 'https://raw.githubusercontent.com/CheckPointSW/pint-benchmark/',
    'bipia': 'https://raw.githubusercontent.com/microsoft/BIPIA/',
    'gsm8k': 'https://raw.githubusercontent.com/openai/grade-school-math/',
}
FILES = {
    'llmail': ['README.md', 'data/labelled_unique_submissions_phase2.json'],
    'gretel': ['README.md', 'data/Spanish_train-00000-of-00001.parquet'],
    'pint': ['README.md', 'DETAILS.md', 'LICENSE', 'benchmark/data/example-dataset.yaml'],
    'bipia': ['README.md', 'LICENSE', 'NOTICE.md', 'benchmark/README.md',
              'benchmark/text_attack_train.json', 'benchmark/text_attack_test.json'],
    'gsm8k': ['README.md', 'LICENSE', 'grade_school_math/data/train.jsonl'],
}


def main():
    DEST.mkdir(parents=True, exist_ok=True)
    records = []
    for source, names in FILES.items():
        for name in names:
            url = BASES[source] + REVISIONS[source] + '/' + name
            path = DEST / source / name
            if not path.exists():
                path.parent.mkdir(parents=True, exist_ok=True)
                request = urllib.request.Request(url, headers={'User-Agent': 'regulai-corpus-research/1.0'})
                with urllib.request.urlopen(request, timeout=60) as response:
                    # Entire small files only. LLMail phase2 is the smallest useful
                    # deduplicated submission file (68.6 MB); phase1 is 448 MB.
                    data = response.read(75_000_001)
                if len(data) > 75_000_000:
                    raise ValueError('Source file exceeds documented bound')
                path.write_bytes(data)
            data = path.read_bytes()
            records.append({'source': source, 'revision': REVISIONS[source], 'file': name,
                            'url': url, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
            print(source, name, len(data), flush=True)
    (DEST / 'downloads.json').write_text(json.dumps(records, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
