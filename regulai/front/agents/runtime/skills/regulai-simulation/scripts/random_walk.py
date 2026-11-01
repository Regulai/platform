"""Bounded finite nearest-neighbour simulations; no network or installation."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import signal
import stat
import sys
import tempfile
import time

try:
    import numpy as np
except ImportError:
    print(json.dumps({'status': 'failed', 'code': 'runtime_dependency_missing',
                      'summary': 'This skill requires preinstalled NumPy; ask the runtime administrator to provide it.'}))
    raise SystemExit(2)

SCHEMA = 'regulai-random-walk-v1'
MAX_SPEC_BYTES = 8192
MAX_RESULT_BYTES = 32768
MAX_WALKERS = 20000
MAX_STEPS = 10000
MAX_WORK = 100000000
MAX_HORIZONS = 64


class SimulationError(ValueError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def integer(value, name, lower, upper):
    if type(value) is not int or not lower <= value <= upper:
        raise SimulationError('invalid_spec', f'{name} must be an integer between {lower} and {upper}.')
    return value


def validate_spec(value):
    required = {'dimensions', 'seed', 'walkers', 'steps'}
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - {'horizons'}:
        raise SimulationError('invalid_spec', 'Use dimensions, seed, walkers, steps and optional horizons only.')
    dimensions = value['dimensions']
    if (not isinstance(dimensions, list) or not 1 <= len(dimensions) <= 2
            or any(type(d) is not int or d not in (2, 3) for d in dimensions)
            or len(set(dimensions)) != len(dimensions)):
        raise SimulationError('invalid_dimensions', 'dimensions must contain 2 and/or 3 without duplicates.')
    seed = integer(value['seed'], 'seed', 0, 2 ** 64 - 1)
    walkers = integer(value['walkers'], 'walkers', 1, MAX_WALKERS)
    steps = integer(value['steps'], 'steps', 1, MAX_STEPS)
    if walkers * steps * len(dimensions) > MAX_WORK:
        raise SimulationError('work_limit', f'walkers*steps*dimensions exceeds {MAX_WORK}; reduce the requested workload.')
    horizons = value.get('horizons', [steps])
    if not isinstance(horizons, list) or not 1 <= len(horizons) <= MAX_HORIZONS:
        raise SimulationError('invalid_horizons', f'horizons must contain between 1 and {MAX_HORIZONS} steps.')
    for horizon in horizons:
        integer(horizon, 'horizon', 1, steps)
    if sorted(set(horizons)) != horizons:
        raise SimulationError('invalid_horizons', 'horizons must be distinct and sorted in increasing order.')
    return {'dimensions': list(dimensions), 'seed': seed, 'walkers': walkers, 'steps': steps, 'horizons': list(horizons)}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def environment():
    build = np.__config__.show(mode='dicts')
    return {'algorithm': 'PCG64', 'numpy_version': np.__version__,
        'numpy_build_sha256': hashlib.sha256(canonical(build)).hexdigest(),
        'platform': platform.system(), 'machine': platform.machine(), 'python_version': platform.python_version(),
        'integer_dtype': 'int64', 'draw_order': 'dimension resets seed; one walkers-sized draw per ascending step',
        'move_mapping': 'axis=k//2; sign=2*(k%2)-1'}


def deadline_guard(deadline, cancelled):
    if cancelled():
        raise SimulationError('cancelled', 'Simulation cancelled; no partial result was published.')
    if time.monotonic() >= deadline:
        raise SimulationError('deadline_exceeded', 'Simulation reached its time limit; reduce the workload or use an authorized longer limit.')


def walk(dimension, walkers, steps, horizons, draw, guard):
    """Keep only current positions and first-return membership; draw is testable."""
    positions = np.zeros((walkers, dimension), dtype=np.int32)
    returned = np.zeros(walkers, dtype=np.bool_)
    rows = np.arange(walkers)
    requested = set(horizons)
    samples = []
    for step in range(1, steps + 1):
        guard()
        moves = draw(0, 2 * dimension, size=walkers, dtype=np.int64)
        positions[rows, moves // 2] += (2 * (moves % 2) - 1).astype(np.int32)
        returned |= np.all(positions == 0, axis=1)
        if step in requested:
            count = int(np.count_nonzero(returned))
            samples.append({'steps': step, 'returned_walkers': count, 'fraction': count / walkers})
    return {'dimension': dimension, 'horizons': samples}


def simulate(raw_spec, *, timeout_seconds=10, cancelled=lambda: False):
    spec = validate_spec(raw_spec)
    if type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 60:
        raise SimulationError('invalid_timeout', 'timeout_seconds must be positive and no greater than 60.')
    deadline = time.monotonic() + timeout_seconds
    guard = lambda: deadline_guard(deadline, cancelled)
    guard()
    results = []
    for dimension in spec['dimensions']:
        guard()
        generator = np.random.Generator(np.random.PCG64(spec['seed']))
        results.append(walk(dimension, spec['walkers'], spec['steps'], spec['horizons'], generator.integers, guard))
    guard()
    value = {'schema': SCHEMA, 'spec': spec, 'rng': environment(), 'results': results,
             'interpretation': 'finite_horizon_estimate_not_asymptotic_proof'}
    if len(canonical(value)) > MAX_RESULT_BYTES:
        raise SimulationError('result_too_large', 'Result exceeds 32 KiB; request fewer horizons.')
    return value


def check(value, *, timeout_seconds=10, cancelled=lambda: False):
    if not isinstance(value, dict) or set(value) != {'schema', 'spec', 'rng', 'results', 'interpretation'} or value['schema'] != SCHEMA:
        raise SimulationError('invalid_result', 'Result must use the complete regulai-random-walk-v1 schema.')
    spec = validate_spec(value['spec'])
    if value['rng'] != environment():
        raise SimulationError('environment_mismatch', 'NumPy/build/platform differs; verify using the recorded environment.')
    if value['interpretation'] != 'finite_horizon_estimate_not_asymptotic_proof':
        raise SimulationError('invalid_result', 'Result interpretation must remain a finite-horizon estimate.')
    if not isinstance(value['results'], list) or len(value['results']) != len(spec['dimensions']):
        raise SimulationError('invalid_result', 'Result must include exactly the requested dimensions.')
    for row, dimension in zip(value['results'], spec['dimensions']):
        if (not isinstance(row, dict) or set(row) != {'dimension', 'horizons'}
                or type(row['dimension']) is not int or row['dimension'] != dimension):
            raise SimulationError('invalid_result', 'Result dimensions/order differ from the requested specification.')
        samples = row['horizons']
        if not isinstance(samples, list) or len(samples) != len(spec['horizons']):
            raise SimulationError('invalid_result', 'Result must include exactly the requested horizons.')
        previous = 0
        previous_step = 0
        for sample, step in zip(samples, spec['horizons']):
            if (not isinstance(sample, dict) or set(sample) != {'steps', 'returned_walkers', 'fraction'}
                    or type(sample['steps']) is not int or sample['steps'] != step):
                raise SimulationError('invalid_result', 'Result horizon fields differ from the specification.')
            count = integer(sample['returned_walkers'], 'returned_walkers', 0, spec['walkers'])
            fraction = sample['fraction']
            if (type(fraction) not in (int, float) or not math.isfinite(fraction) or not 0 <= fraction <= 1
                    or not math.isclose(fraction, count / spec['walkers'], rel_tol=0, abs_tol=1e-15)
                    or count < previous or (step == 1 and count != 0)
                    or (step == previous_step + 1 and step % 2 and count != previous)):
                raise SimulationError('invariant_failed', 'Return counts/fractions must be bounded, cumulative and obey even-step returns.')
            previous, previous_step = count, step
    replay = simulate(spec, timeout_seconds=timeout_seconds, cancelled=cancelled)
    if value != replay:
        raise SimulationError('replay_mismatch', 'Recorded counts differ from the deterministic replay; regenerate from the same specification.')
    return {'status': 'verified', 'schema': SCHEMA, 'canonical_sha256': hashlib.sha256(canonical(value)).hexdigest(),
            'dimensions': spec['dimensions'], 'horizons': spec['horizons'], 'checks': ['bounds', 'monotonicity', 'parity', 'deterministic_replay']}


def read_json(path, limit):
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise SimulationError('symlink_refused', 'Input must be a regular file, not a symbolic link.')
    if not stat.S_ISREG(path.stat().st_mode):
        raise SimulationError('invalid_file', 'Input must be a regular JSON file.')
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise SimulationError('input_too_large', f'Input exceeds {limit} bytes; use a bounded JSON file.')
    try:
        def unique_fields(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('Duplicate JSON key')
                result[key] = value
            return result
        return json.loads(raw, object_pairs_hook=unique_fields,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Non-finite JSON number')))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise SimulationError('invalid_json', 'Input must be UTF-8 JSON with finite numbers.') from error


def write_exclusive(path, value, before_publish=lambda: None):
    if path.exists() or path.is_symlink():
        raise SimulationError('file_exists', 'Output already exists; choose a new authorized filename.')
    if any(parent.is_symlink() for parent in (path.parent, *path.parent.parents)):
        raise SimulationError('symlink_refused', 'Output directory must not traverse symbolic links.')
    raw = canonical(value) + b'\n'
    if len(raw) > MAX_RESULT_BYTES:
        raise SimulationError('result_too_large', 'Result exceeds 32 KiB; request fewer horizons.')
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.random-walk-', delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        before_publish()
        os.link(temporary, path)  # Atomic publish, fails rather than replacing a concurrent file.
    except FileExistsError as error:
        raise SimulationError('file_exists', 'Output appeared concurrently; choose a new authorized filename.') from error
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    run = commands.add_parser('run')
    run.add_argument('--spec', type=Path, required=True)
    run.add_argument('--out', type=Path, required=True)
    run.add_argument('--timeout-seconds', type=float, default=10)
    verify = commands.add_parser('check')
    verify.add_argument('result', type=Path)
    verify.add_argument('--timeout-seconds', type=float, default=10)
    args = parser.parse_args(argv)
    interrupted = False

    def cancel(signum, frame):
        nonlocal interrupted
        interrupted = True

    for name in ('SIGINT', 'SIGTERM'):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), cancel)
    try:
        started = time.monotonic()
        if args.command == 'run':
            if args.out.exists() or args.out.is_symlink():
                raise SimulationError('file_exists', 'Output already exists; choose a new authorized filename.')
            result = simulate(read_json(args.spec, MAX_SPEC_BYTES), timeout_seconds=args.timeout_seconds,
                              cancelled=lambda: interrupted)
            deadline_guard(started + args.timeout_seconds, lambda: interrupted)
            write_exclusive(args.out, result,
                before_publish=lambda: deadline_guard(started + args.timeout_seconds, lambda: interrupted))
            print(canonical({'status': 'completed', 'result': result,
                             'canonical_sha256': hashlib.sha256(canonical(result)).hexdigest()}).decode())
        else:
            print(canonical(check(read_json(args.result, MAX_RESULT_BYTES), timeout_seconds=args.timeout_seconds,
                                  cancelled=lambda: interrupted)).decode())
        return 0
    except SimulationError as error:
        print(canonical({'status': 'failed', 'code': error.code, 'summary': str(error)}).decode())
        return 130 if error.code == 'cancelled' else 2
    except OSError as error:
        print(canonical({'status': 'failed', 'code': 'file_io_error',
                         'summary': 'Cannot read or create the requested file; verify its directory and permissions.',
                         'errno': error.errno}).decode())
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
