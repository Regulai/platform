"""Remove only the two explicitly owned P1 physical runtimes; keep evidence and PostgreSQL."""
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'output/p1-20261016/physical'


def run(*args):
    return subprocess.run(['rtk', 'proxy', *map(str, args)], check=True,
        capture_output=True, text=True, encoding='utf-8')


def main():
    removed = []
    for kind in ('documental', 'physical'):
        name = f'regulai-p1-{kind}-20261016'
        program = (
            "import pathlib,shutil,sys; name=sys.argv[1]; "
            "assert name in ('regulai-p1-physical-20261016','regulai-p1-documental-20261016'); "
            "p=pathlib.Path('/tmp')/name; "
            "assert p.is_dir() and not p.is_symlink() and p.resolve()==p; "
            "assert (p/'owner').read_text()==name; "
            "shutil.rmtree(p); print(str(p))"
        )
        removed.append(run('wsl', '-d', 'Ubuntu', '--', 'python3', '-c', program, name).stdout.strip())
        image = f'regulai-p1-{kind}-runtime:20261016'
        info = json.loads(run('docker', 'image', 'inspect', image).stdout)[0]
        assert info['Config']['Labels'][f'regulai.p1_{kind}'] == '20261016'
        run('docker', 'image', 'rm', image)
        removed.append(image)
    for relative in ('runtime.tar', 'documental-runtime/runtime.tar', 'documental-runtime/officecli-linux-x64'):
        target = OUT / relative
        assert target.resolve().is_relative_to(OUT.resolve()) and not target.is_symlink()
        assert target.is_file()
        target.unlink()
        removed.append(str(target.relative_to(ROOT)))
    result = {'removed': removed, 'postgresql_stopped': False,
        'reason_postgresql_retained': 'Root still collecting browser streaming evidence',
        'evidence_and_final_artifacts_retained': True, 'unrelated_services_changed': False}
    (OUT / 'cleanup.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
