"""Pinned SDK runtime boundary tests; no host spreadsheet calculation."""
from pathlib import Path
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'regulai'))
from front.agents.sandbox_pool import CleanPool
from front.agents.worker import runtime_prompt


class PoolTests(unittest.TestCase):
    def test_exclusive_clean_slot_destroyed_then_replaced(self):
        ready = threading.Event()
        created, killed = [], []
        class Sandbox:
            def __init__(self):
                self.sandbox_id = len(created)
                created.append(self)
                ready.set()
            def set_timeout(self, seconds):
                pass
            def kill(self):
                killed.append(self)
        pool = CleanPool(Sandbox)
        try:
            self.assertTrue(ready.wait(5))
            with pool.lock:
                first = pool.ready
            # Wait for the factory to transfer ownership, not an arbitrary delay.
            for _ in range(100):
                leased = pool.take()
                if leased:
                    break
                threading.Event().wait(.01)
            self.assertIsNotNone(leased)
            self.assertIsNone(pool.take())
            self.assertEqual(len(created), 1)
            pool.return_unassigned(leased)
            self.assertIs(pool.take(), leased)
            ready.clear()
            pool.release(leased)
            self.assertTrue(ready.wait(5))
            self.assertIn(leased, killed)
            self.assertEqual(len(created), 2)
            self.assertIsNone(pool.ready) if pool.closed else None
        finally:
            pool.close()
        self.assertCountEqual(created, killed)

    def test_runtime_has_only_the_excel_procedure_and_its_notices(self):
        prompt = runtime_prompt(('build_excel', 'rename_excel'))
        self.assertIn('build_excel', prompt)
        self.assertIn('rename_excel', prompt)
        self.assertNotIn('## Word', prompt)
        self.assertNotIn('## PowerPoint', prompt)
        self.assertNotIn('## PDF', prompt)
        self.assertIn('no concede permisos', Path(__file__).resolve().parents[2].joinpath(
            'regulai/front/agents/runtime/NOTICE.md').read_text(encoding='utf-8'))

    def test_runtime_selects_document_procedures_from_authorized_tools(self):
        cases = [
            (('build_document',), ('name: docx', 'name: pdf'), ('name: regulay-pptx', '# Excel del laboratorio')),
            (('build_presentation',), ('name: regulay-pptx',), ('name: docx', 'name: pdf', '# Excel del laboratorio')),
            ((), (), ('name: docx', 'name: pdf', 'name: regulay-pptx', '# Excel del laboratorio')),
        ]
        for tools, present, absent in cases:
            with self.subTest(tools=tools):
                prompt = runtime_prompt(tools)
                for marker in present:
                    self.assertIn(marker, prompt)
                for marker in absent:
                    self.assertNotIn(marker, prompt)


if __name__ == '__main__':
    unittest.main()
