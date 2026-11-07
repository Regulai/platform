"""Real installed CPU detector; no provider or downloaded test-time models."""
from concurrent.futures import ThreadPoolExecutor
import json
import sys
from unittest.mock import patch

from django.test import SimpleTestCase

from . import local_masking


SCHEDULING_PROMPT = (
    'Tengo tres tareas: A dura 3 horas, B dura 2 y depende de A; C dura 4 y puede ejecutarse '
    'en paralelo con A. Dispongo de dos trabajadores. Si dos tareas coinciden, cada una '
    'necesita un trabajador distinto. Encuentra el tiempo mínimo para completar las tres, '
    'propone un horario y demuestra que no existe uno más corto. Después recalcula la '
    'solución si C también debe terminar antes de empezar B.'
)
SCHEDULING_ANSWER = (
    'El mínimo es 5 horas: A de 0 a 3, B de 3 a 5 y C de 0 a 4. '
    'La cadena A → B exige al menos 3 + 2 = 5 horas. '
    'Si C también precede a B, el mínimo es 6 horas: A de 0 a 3, C de 0 a 4 y B de 4 a 6. '
    'La cadena C → B exige al menos 4 + 2 = 6 horas.\n'
    '| Tarea | Inicio | Fin |\n| --- | --- | --- |\n| A | 0 | 3 |\n| B | 4 | 6 |\n| C | 0 | 4 |'
)


class LocalMaskingTests(SimpleTestCase):
    def test_task_variables_prose_and_answer_are_preserved_exactly(self):
        texts = [SCHEDULING_PROMPT, SCHEDULING_ANSWER,
            'Tengo una pregunta. Después explica cuál es el único contrato.',
            'Compara Madrid con Londres y Microsoft con Apple.',
            'John Smith and María García are characters in this fictional story.']
        self.assertEqual(local_masking.mask_local_texts(texts, timeout=30), texts)

    def test_real_cpu_masks_structured_personal_data_and_secrets_without_network(self):
        samples = ['Correo: ana.perez@example.test', 'DNI: 12345678Z', 'NIE: X1234567L',
            'Cuenta: ES91 2100 0418 4502 0005 1332', 'Teléfono: +34 612 345 678',
            'Tarjeta: 4111 1111 1111 1111', 'api_key=sk_test_abcdefghijk123',
            'Bearer abcdefghijklmnop.123456789', 'Nombre: María García',
            'Full name: John Smith']
        forbidden = ['ana.perez@example.test', '12345678Z', 'X1234567L', 'ES91 2100 0418 4502 0005 1332',
            '+34 612 345 678', '4111 1111 1111 1111', 'sk_test_abcdefghijk123',
            'abcdefghijklmnop.123456789', 'María García', 'John Smith']
        with patch('socket.socket.connect', side_effect=AssertionError('No local detector network')) as network:
            result = local_masking.mask_local_texts(samples, timeout=30)
        self.assertEqual(len(result), len(samples))
        for original, masked in zip(forbidden, result):
            with self.subTest(value=original):
                self.assertNotIn(original, masked)
                self.assertIn('[[REGULAI_', masked)
        network.assert_not_called()

    def test_json_structure_numbers_aliases_and_duplicate_keys_are_preserved(self):
        value = '{"claims":[{"text":"Email ana@example.test","citations":[{"source_id":"F1","quote":"Email ana@example.test"}]}],"n":1.234567890123456789,"n":2,"password":123456}'
        masked = local_masking.mask_local_texts([value], timeout=30)[0]
        payload = json.loads(masked)
        self.assertEqual(payload['claims'][0]['citations'][0]['source_id'], 'F1')
        self.assertEqual(payload['claims'][0]['text'], payload['claims'][0]['citations'][0]['quote'])
        self.assertNotIn('ana@example.test', masked)
        self.assertEqual(payload['password'], '[[REGULAI_SECRET]]')
        self.assertIn('1.234567890123456789', masked)
        self.assertEqual(masked.count('"n":'), 2)
        actual = '{"claims":[{"text":"Email ana@example.test","citations":[{"id":"S1","quote":"Email ana@example.test"}]}]}'
        actual_result = json.loads(local_masking.mask_local_texts([actual], timeout=30)[0])
        self.assertEqual(actual_result['claims'][0]['citations'][0]['id'], 'S1')
        untrusted = '{"source_id":"ana@example.test","alias":"12345678Z","maria@example.test":"value"}'
        transformed = local_masking.mask_local_texts([untrusted], timeout=30)[0]
        for sensitive in ('ana@example.test', '12345678Z', 'maria@example.test'):
            self.assertNotIn(sensitive, transformed)

    def test_known_field_label_is_preserved_while_its_value_is_masked(self):
        result = local_masking.mask_local_texts(['Tarjeta: 4111 1111 1111 1111'], timeout=30)[0]
        self.assertTrue(result.startswith('Tarjeta: '))
        self.assertNotIn('4111', result)

    def test_json_numeric_pii_and_equivalent_exponents_are_transformed(self):
        cases = ['{"telefono":612345678,"tarjeta":4111111111111111}',
                 '[612345678,4111111111111111]',
                 '{"telefono":6.12345678e8,"tarjeta":4.111111111111111e15}',
                 '{"telefono":612345678.0,"tarjeta":4111111111111111.00}']
        for value in cases:
            with self.subTest(value=value):
                masked = local_masking.mask_local_texts([value], timeout=30)[0]
                payload = json.loads(masked)
                items = list(payload.values()) if isinstance(payload, dict) else payload
                self.assertEqual(len(items), 2)
                self.assertTrue(all(isinstance(item, str) and item.startswith('[[REGULAI_') for item in items), items)
                self.assertNotIn('612345678', masked)
                self.assertNotIn('4111111111111111', masked)

    def test_non_sensitive_json_numbers_keep_exact_precision_and_bounded_exponents(self):
        value = '[0,-7,17.005,1.234567890123456789,1e100000000,1e-100000000]'
        self.assertEqual(local_masking.mask_local_texts([value], timeout=30)[0], value)

    def test_detector_failure_never_returns_original(self):
        for error in (RuntimeError('Detector failed'), TimeoutError('Deadline exceeded')):
            with self.subTest(error=type(error).__name__), patch.object(local_masking, '_mask_segment', side_effect=error):
                with self.assertRaises(type(error)):
                    local_masking.mask_local_texts(['ana@example.test'])

    def test_statistical_models_are_not_needed_or_used(self):
        with patch.dict(sys.modules, {'spacy': None, 'xx_ent_wiki_sm': None}):
            self.assertEqual(local_masking.mask_local_texts(['ana@example.test', SCHEDULING_PROMPT]),
                ['[[REGULAI_EMAIL]]', SCHEDULING_PROMPT])
            self.assertEqual(local_masking.detector_metadata()['detection'], 'explicit_patterns')

    def test_limits_language_timeout_and_idempotence(self):
        for values in ([], ['ok', None], ['x' * (local_masking.MAX_BATCH_BYTES + 1)]):
            with self.subTest(values_type=type(values).__name__), self.assertRaises(ValueError):
                local_masking.mask_local_texts(values)
        with self.assertRaises(ValueError):
            local_masking.mask_local_texts(['bonjour'], language='fr')
        with self.assertRaises(TimeoutError):
            local_masking.mask_local_texts(['hola'], timeout=0)
        once = local_masking.mask_local_texts(['Correo ana@example.test y DNI 12345678Z'], timeout=30)
        self.assertEqual(local_masking.mask_local_texts(once, timeout=30), once)

    def test_concurrent_batches_do_not_retain_or_share_personal_values(self):
        with ThreadPoolExecutor(max_workers=3) as executor:
            results = list(executor.map(lambda text: local_masking.mask_local_texts([text], timeout=30),
                ['alpha@example.test', 'beta@example.test', 'gamma@example.test']))
        for result in results:
            self.assertEqual(result, ['[[REGULAI_EMAIL]]'])
