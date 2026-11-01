"""Independent path oracle and CLI boundaries for the reviewed local skill."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import importlib.util
import itertools
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'regulai/front/agents/runtime/skills/regulai-simulation/scripts/random_walk.py'
SPEC = importlib.util.spec_from_file_location('p1_random_walk', SCRIPT)
walk = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(walk)
FULL = {'dimensions': [2, 3], 'seed': 20261016, 'walkers': 2000, 'steps': 2000}


def scalar_oracle(paths, dimension):
    """Deliberately independent: pure Python coordinates, no NumPy reductions."""
    returned_at = []
    for path in paths:
        position = [0] * dimension
        first = None
        for step, direction in enumerate(path, 1):
            for axis in range(dimension):
                if direction == 2 * axis:
                    position[axis] -= 1
                elif direction == 2 * axis + 1:
                    position[axis] += 1
            if first is None and all(coordinate == 0 for coordinate in position):
                first = step
        returned_at.append(first)
    return [sum(first is not None and first <= horizon for first in returned_at)
            for horizon in range(1, len(paths[0]) + 1)]


class SimulationTests(unittest.TestCase):
    def test_all_short_paths_match_independent_oracle_and_even_return_law(self):
        for dimension in (2, 3):
            with self.subTest(dimension=dimension):
                paths = list(itertools.product(range(2 * dimension), repeat=4))
                moves = iter(np.asarray(paths, dtype=np.int64).T)
                observed = walk.walk(dimension, len(paths), 4, [1, 2, 3, 4],
                    lambda low, high, size, dtype: next(moves), lambda: None)
                expected = scalar_oracle(paths, dimension)
                counts = [row['returned_walkers'] for row in observed['horizons']]
                self.assertEqual(counts, expected)
                self.assertEqual(counts[0], 0)
                self.assertEqual(counts[1], counts[2])
                self.assertAlmostEqual(counts[1] / len(paths), 1 / (2 * dimension))

    def test_full_plan_problem_repeats_with_recorded_rng_build_and_no_extra_dimensions(self):
        started = time.monotonic()
        result = walk.simulate(FULL)
        checked = walk.check(result)
        self.assertEqual(checked['status'], 'verified')
        self.assertEqual([row['dimension'] for row in result['results']], [2, 3])
        self.assertEqual(result['rng']['algorithm'], 'PCG64')
        self.assertEqual(result['rng']['numpy_version'], np.__version__)
        self.assertEqual(len(result['rng']['numpy_build_sha256']), 64)
        self.assertLess(len(walk.canonical(result)), walk.MAX_RESULT_BYTES)
        for row in result['results']:
            self.assertEqual(len(row['horizons']), 1)
            self.assertEqual(row['horizons'][0]['steps'], 2000)
        destination = ROOT / 'output/p1-20261016/e5'
        destination.mkdir(parents=True, exist_ok=True)
        (destination / 'simulation-local.json').write_text(json.dumps({
            'result': result, 'check': checked, 'run_and_check_seconds': time.monotonic() - started,
            'execution': 'local application Python; not isolated sandbox',
            'provider_calls': 0, 'provider_quality': None, 'physical_isolation_verified': False}, indent=2) + '\n', encoding='utf-8')

    def test_dimension_order_and_horizon_selection_do_not_change_samples(self):
        spec = {**FULL, 'walkers': 40, 'steps': 20, 'horizons': list(range(1, 21))}
        result = walk.simulate(spec)
        reordered = walk.simulate({**spec, 'dimensions': [3, 2], 'horizons': [20]})
        for row, reverse in zip(result['results'], reversed(reordered['results'])):
            counts = [sample['returned_walkers'] for sample in row['horizons']]
            self.assertEqual(counts, sorted(counts))
            self.assertEqual(row['horizons'][-1], reverse['horizons'][0])
            for index in range(2, len(counts), 2):
                self.assertEqual(counts[index], counts[index - 1])

    def test_invalid_boundaries_are_rejected_before_allocating_rng(self):
        small = {**FULL, 'walkers': 2, 'steps': 2}
        variants = [{'dimensions': []}, {'dimensions': [2, 2]}, {'dimensions': [4]}, {'dimensions': [True]},
            {'seed': -1}, {'seed': 2 ** 64}, {'seed': True}, {'walkers': 0}, {'walkers': 20001},
            {'steps': 0}, {'steps': 10001}, {'horizons': []}, {'horizons': [0]}, {'horizons': [3]},
            {'horizons': [1, 1]}, {'horizons': [2, 1]}, {'horizons': [True]}, {'unknown': 1},
            {'walkers': 20000, 'steps': 10000}]
        with patch.object(np.random, 'PCG64', side_effect=AssertionError('Invalid spec reached RNG')):
            for changes in variants:
                with self.subTest(changes=changes), self.assertRaises(walk.SimulationError):
                    walk.simulate({**small, **changes})
        for timeout in (0, -1, 61, True, float('nan'), float('inf')):
            with self.subTest(timeout=timeout), self.assertRaises(walk.SimulationError):
                walk.simulate(small, timeout_seconds=timeout)

    def test_check_rejects_tampered_counts_environment_and_unrequested_results(self):
        original = walk.simulate({**FULL, 'walkers': 20, 'steps': 8, 'horizons': [1, 2, 3, 8]})
        altered = deepcopy(original)
        altered['results'][0]['horizons'][-1]['returned_walkers'] += 1
        altered['results'][0]['horizons'][-1]['fraction'] = altered['results'][0]['horizons'][-1]['returned_walkers'] / 20
        with self.assertRaisesRegex(walk.SimulationError, 'deterministic replay'):
            walk.check(altered)
        for mutate in (
                lambda x: x['rng'].update(numpy_version='uninstalled'),
                lambda x: x['results'].append(deepcopy(x['results'][0])),
                lambda x: x['results'][0]['horizons'][0].update(steps=True),
                lambda x: x['results'][0]['horizons'][0].update(fraction=float('nan')),
                lambda x: x.update(interpretation='asymptotic_proof')):
            altered = deepcopy(original)
            mutate(altered)
            with self.assertRaises(walk.SimulationError):
                walk.check(altered)

    def test_cancellation_and_timeout_stop_before_any_result_is_published(self):
        with self.assertRaisesRegex(walk.SimulationError, 'cancelled'):
            walk.simulate(FULL, cancelled=lambda: True)
        checks = 0
        def later():
            nonlocal checks
            checks += 1
            return checks >= 6
        with self.assertRaisesRegex(walk.SimulationError, 'cancelled'):
            walk.simulate(FULL, cancelled=later)
        with patch.object(walk.time, 'monotonic', side_effect=[1, 2]):
            with self.assertRaisesRegex(walk.SimulationError, 'time limit'):
                walk.simulate(FULL, timeout_seconds=.5)

    def test_cli_atomic_create_check_and_rejection_leave_existing_file_intact(self):
        with tempfile.TemporaryDirectory(prefix='regulai-p1-simulation-') as folder:
            directory = Path(folder)
            spec, output = directory / 'spec.json', directory / 'out.json'
            spec.write_text(json.dumps({**FULL, 'walkers': 10, 'steps': 20}), encoding='utf-8')
            command = ['rtk', 'proxy', sys.executable, str(SCRIPT)]
            run = subprocess.run([*command, 'run', '--spec', str(spec), '--out', str(output)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            before = output.read_bytes()
            self.assertEqual(json.loads(run.stdout)['status'], 'completed')
            check = subprocess.run([*command, 'check', str(output)], capture_output=True, text=True)
            self.assertEqual(check.returncode, 0, check.stdout + check.stderr)
            self.assertEqual(json.loads(check.stdout)['status'], 'verified')
            again = subprocess.run([*command, 'run', '--spec', str(spec), '--out', str(output)], capture_output=True, text=True)
            self.assertEqual(again.returncode, 2)
            self.assertEqual(json.loads(again.stdout)['code'], 'file_exists')
            self.assertEqual(output.read_bytes(), before)
            self.assertFalse(list(directory.glob('.random-walk-*')))
            spec.write_text('{"dimensions": [2], "dimensions": [3]}', encoding='utf-8')
            invalid = subprocess.run([*command, 'run', '--spec', str(spec), '--out', str(directory / 'bad.json')], capture_output=True, text=True)
            self.assertEqual(invalid.returncode, 2)
            self.assertEqual(json.loads(invalid.stdout)['code'], 'invalid_json')
            self.assertFalse((directory / 'bad.json').exists())

    def test_competing_publications_cannot_replace_each_other(self):
        with tempfile.TemporaryDirectory(prefix='regulai-p1-publish-') as folder:
            target = Path(folder) / 'result.json'
            def publish(index):
                try:
                    walk.write_exclusive(target, {'winner': index})
                    return 'created'
                except walk.SimulationError as error:
                    return error.code
            with ThreadPoolExecutor(max_workers=2) as executor:
                outcomes = list(executor.map(publish, (1, 2)))
            self.assertEqual(sorted(outcomes), ['created', 'file_exists'])
            self.assertIn(json.loads(target.read_bytes())['winner'], (1, 2))
            self.assertFalse(list(Path(folder).glob('.random-walk-*')))

    def test_cancellation_before_atomic_publish_leaves_no_partial_output(self):
        with tempfile.TemporaryDirectory(prefix='regulai-p1-cancel-') as folder:
            target = Path(folder) / 'result.json'
            with self.assertRaises(walk.SimulationError):
                walk.write_exclusive(target, {'completed': True},
                    before_publish=lambda: walk.deadline_guard(float('inf'), lambda: True))
            self.assertFalse(target.exists())
            self.assertFalse(list(Path(folder).iterdir()))

    def test_symlink_inputs_and_outputs_are_refused_without_changing_target(self):
        with tempfile.TemporaryDirectory(prefix='regulai-p1-symlink-') as folder:
            directory = Path(folder)
            original = directory / 'original.json'
            original.write_text('{}', encoding='utf-8')
            link = directory / 'link.json'
            try:
                link.symlink_to(original)
            except OSError:
                self.skipTest('This host cannot create symlinks; physical runner checks remain separate')
            with self.assertRaises(walk.SimulationError):
                walk.read_json(link, 8192)
            with self.assertRaises(walk.SimulationError):
                walk.write_exclusive(link, {'overwrite': True})
            self.assertEqual(original.read_text(encoding='utf-8'), '{}')


if __name__ == '__main__':
    unittest.main()
