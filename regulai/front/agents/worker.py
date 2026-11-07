"""Separate pinned-SDK executor. No Django, database, aliases or provider keys."""
import argparse
import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import threading
import time
import uuid

import httpx
from langchain.tools import tool, ToolRuntime
from langchain_core.messages import HumanMessage
from langchain_e2b import E2BSandbox

from .adapter import InternalClient, InternalOperationError, build_agent
from .sandbox_pool import CleanPool, create_clean


def runtime_prompt(tools=(), *, skills=False):
    root = Path(__file__).with_name('runtime')
    names = ['system.md', 'documents.md', 'design.md']
    if not skills and any(name in tools for name in ('create_mock_excel', 'build_excel', 'rename_excel')):
        names += ['skills/excel/SKILL.md']
    if not skills and any(name in tools for name in ('build_document', 'edit_document', 'export_pdf')):
        names += ['skills/docx/SKILL.md', 'skills/pdf/SKILL.md']
    if not skills and any(name in tools for name in ('build_presentation', 'edit_presentation')):
        names += ['skills/pptx/SKILL.md']
    return '\n\n'.join((root / name).read_text(encoding='utf-8') for name in names)


class DocumentBackend(E2BSandbox):
    """No implicit SDK allocation; only the authorized document preparation attaches a VM."""
    def execute(self, command, *, timeout=None):
        if self._sandbox is None:
            raise InternalOperationError('Document runtime requires an authorized tool')
        return super().execute(command, timeout=timeout)

    def upload_files(self, files):
        if self._sandbox is None:
            raise InternalOperationError('Document runtime requires an authorized tool')
        return super().upload_files(files)

    def download_files(self, paths):
        if self._sandbox is None:
            raise InternalOperationError('Document runtime requires an authorized tool')
        return super().download_files(paths)

    async def aexecute(self, command, *, timeout=None):
        return await asyncio.to_thread(self.execute, command, timeout=timeout)

    async def aupload_files(self, files):
        return await asyncio.to_thread(self.upload_files, files)

    async def adownload_files(self, paths):
        return await asyncio.to_thread(self.download_files, paths)


class Lease:
    def __init__(self, internal, sandbox=None):
        self.internal, self.sandbox = internal, sandbox
        self.stop, self.lost = threading.Event(), threading.Event()
        self.lock = threading.Lock()
        self.on_renew, self.on_cancel, self.on_prepared = None, None, None
        self.thread = threading.Thread(target=self._renew, daemon=True)

    def attach(self, sandbox, *, on_renew=None, on_cancel=None, on_prepared=None):
        with self.lock:
            self.check()
            if self.sandbox is not None and self.sandbox is not sandbox:
                raise InternalOperationError('Execution already has a sandbox')
            self.sandbox = sandbox
            self.on_renew = on_renew or self.on_renew
            self.on_cancel = on_cancel or self.on_cancel
            self.on_prepared = on_prepared or self.on_prepared

    def cancel(self):
        self.lost.set()
        self.stop.set()
        if self.on_cancel:
            self.on_cancel()
        elif self.sandbox is not None:
            try:
                self.sandbox.kill()
            except Exception:
                pass  # No destruction claim: the server retains occupancy.

    def _renew(self):
        while not self.stop.wait(15):
            try:
                self.internal.operation('run/renew', {})
                if self.sandbox is not None:
                    self.sandbox.set_timeout(180)
                    if self.on_renew:
                        self.on_renew()
            except Exception:
                self.cancel()
                return

    def check(self):
        if self.lost.is_set():
            raise InternalOperationError('Execution lease lost')

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.stop.set()
        self.thread.join(timeout=1)


def run_job(internal, sandbox=None, *, acquire=None, started=None):
    with Lease(internal, sandbox) as lease:
        if started:
            started(lease)
        granted = internal.operation('run/bootstrap', {})
        internal.configure(granted)
        if granted['model_context']['operation'] == 'professional':
            from .professional_worker import run_professional
            return run_professional(internal, sandbox, lease, granted, acquire=acquire)
        if granted['model_context']['operation'] == 'export':
            if sandbox is None:
                if acquire is None:
                    raise InternalOperationError('Sandbox acquisition unavailable')
                sandbox = acquire(lease)
                lease.attach(sandbox)
            return run_export(internal, sandbox, lease, granted)
        backend = DocumentBackend(sandbox=None, workdir='/workspace/work', timeout=90)
        prepared, preparation_failed = False, False
        preparation_lock = threading.Lock()

        def ensure_document_runtime(call, grant):
            nonlocal sandbox, prepared, preparation_failed
            if call['name'] not in {'create_mock_excel', 'build_excel', 'rename_excel', 'build_document',
                    'edit_document', 'export_pdf', 'build_presentation', 'edit_presentation', 'save_revision'}:
                return
            with preparation_lock:
                lease.check()
                if prepared:
                    return
                if preparation_failed:
                    raise InternalOperationError('Document preparation outcome uncertain')
                try:
                    if sandbox is None:
                        if acquire is None:
                            raise InternalOperationError('Sandbox acquisition unavailable')
                        sandbox = acquire(lease)
                        lease.attach(sandbox)
                    if granted['input']:
                        data = base64.b64decode(granted['input']['base64'], validate=True)
                        if hashlib.sha256(data).hexdigest() != granted['input']['sha256']:
                            raise InternalOperationError('Input digest changed')
                        sandbox.files.write(granted['input']['path'], data, user='root')
                    if granted['base']:
                        sandbox.files.write('/workspace/input/base.' + granted.get('base_format', 'xlsx'), base64.b64decode(granted['base']), user='root')
                    if granted.get('base_docx'):
                        sandbox.files.write('/workspace/input/document.docx', base64.b64decode(granted['base_docx']), user='root')
                    sandbox.commands.run(('chmod 0444 /workspace/input/* && ' if granted['input'] else '') + 'chmod 0555 /workspace/input && '
                        'mount --bind /workspace/input /workspace/input && mount -o remount,bind,ro /workspace/input',
                        user='root', timeout=10)
                    lease.check()
                    internal.operation('run/renew', {})
                    backend._sandbox = sandbox
                    prepared = True
                except BaseException:
                    preparation_failed = True
                    raise
        tool_lock = threading.Lock()

        def operate(name, args, runtime):
            # Native parallel tool calls cannot race work/output or the local lease.
            with tool_lock:
                call = {'id': runtime.tool_call_id, 'name': name, 'args': args}
                lease.check()
                fields = internal.operation('run/local-fields', call)
                work = '/workspace/work/' + uuid.uuid4().hex
                logs = []

                def execute(phase, command):
                    lease.check()
                    internal.operation('run/step', {'call': call, 'phase': phase})
                    result = backend.execute(command, timeout=180 if name in ('build_presentation', 'edit_presentation') else 90)
                    logs.append({'phase': phase, 'output': result.output, 'exit_code': result.exit_code})
                    if result.exit_code:
                        raise RuntimeError(json.dumps({'local_operation_failed': logs}))
                    lease.check()

                execute('input', 'mkdir -p ' + work)
                sandbox.files.write(work + '/fields.json', json.dumps({'title': fields['title']}).encode())
                if name in ('build_document', 'edit_document', 'export_pdf', 'build_presentation', 'edit_presentation'):
                    sandbox.files.write(work + '/fields.json', json.dumps(fields).encode())
                    final_dir = work + '/final'
                    presenting = name in ('build_presentation', 'edit_presentation')
                    extension = 'pptx' if presenting else 'docx'
                    narrative = bool(fields.get('narrative'))
                    program = 'python -I /skills/' + ('narrative_program.py ' if narrative else
                        'presentation_program.py ' if presenting else 'document_program.py ')
                    common = ' --output ' + final_dir + (' --extension ' + extension if narrative else '')
                    if narrative and name == 'export_pdf':
                        execute('compose', 'mkdir -p ' + final_dir + ' && cp /workspace/input/document.docx ' + final_dir + '/final.docx')
                    elif narrative:
                        editing = name in ('edit_document', 'edit_presentation')
                        source = '/workspace/input/base.pptx' if presenting else '/workspace/input/document.docx'
                        execute('compose', program + ('edit' if editing else 'build') + common +
                            (' --source ' + shlex.quote(source) if editing else '') + ' --fields ' + work + '/fields.json')
                    elif presenting:
                        source = '/workspace/input/base.pptx' if name == 'edit_presentation' else granted['input']['path']
                        execute('compose', program + ('edit' if name == 'edit_presentation' else 'build') + common +
                            ' --source ' + shlex.quote(source) + ' --template /skills/corporate.pptx --fields ' + work + '/fields.json')
                    elif name == 'export_pdf':
                        execute('compose', 'mkdir -p ' + final_dir + ' && cp /workspace/input/document.docx ' + final_dir + '/final.docx')
                    else:
                        source = ('/workspace/input/document.docx' if name == 'edit_document' else
                            '/workspace/input/base.xlsx' if granted.get('base_format') == 'xlsx' else granted['input']['path'])
                        execute('compose', program + ('edit' if name == 'edit_document' else 'build') + common +
                            ' --source ' + shlex.quote(source) + ' --template /skills/corporate.docx --fields ' + work + '/fields.json')
                    try:
                        execute('render', program + 'render' + common)
                        execute('verify', program + 'seal' + common)
                        downloaded = backend.download_files([final_dir + '/candidate.zip'])[0]
                    except RuntimeError:
                        # Preserve the produced DOCX even when conversion fails.
                        downloaded = backend.download_files([final_dir + '/final.' + extension])[0]
                    if downloaded.error or not downloaded.content:
                        raise RuntimeError('Document candidate unavailable')
                    lease.check()
                    result = internal.operation('run/candidate', {'operation_id': str(uuid.uuid4()), 'call': call,
                        'document_bundle': base64.b64encode(downloaded.content).decode()})
                    from langchain_core.messages import ToolMessage
                    return ToolMessage(content=json.dumps({'reference': result['reference']}),
                        tool_call_id=call['id'], name=name, artifact={'raw_logs': logs})
                if name == 'create_mock_excel':
                    source_data = base64.b64decode(fields['source_base64'], validate=True)
                    if hashlib.sha256(source_data).hexdigest() != fields['source_sha256']:
                        raise InternalOperationError('Generated source digest changed')
                    source = work + '/mock.csv'
                    sandbox.files.write(source, source_data)
                else:
                    source = '/workspace/input/base.xlsx' if name == 'rename_excel' else granted['input']['path']
                mode = 'rename' if name == 'rename_excel' else 'build'
                final = work + '/final/candidate.xlsx'
                target = final if mode == 'rename' else work + '/candidate.xlsx'
                try:
                    execute('rename' if mode == 'rename' else 'calculate',
                        'mkdir -p ' + work + '/final && python -I /skills/spreadsheet_program.py ' + mode + ' ' +
                        shlex.quote(source) + ' --output ' + target + ' --fields ' + work + '/fields.json')
                    if mode == 'build':
                        execute('recalculate', 'libreoffice -env:UserInstallation=file://' + work + '/lo '
                            '--headless --convert-to xlsx --outdir ' + work + '/final ' + target)
                    execute('verify', 'python -I /skills/spreadsheet_program.py check ' + final)
                except RuntimeError:
                    lease.check()
                    # Retain any candidate, including one before failed recalc.
                    # Only the application verifier may authorize publication.
                    pass
                downloaded = backend.download_files([final])[0]
                if (downloaded.error or not downloaded.content) and target != final:
                    downloaded = backend.download_files([target])[0]
                if downloaded.error or not downloaded.content:
                    raise RuntimeError('Candidate download failed')
                lease.check()
                result = internal.operation('run/candidate', {'operation_id': str(uuid.uuid4()),
                    'call': call, 'base64': base64.b64encode(downloaded.content).decode()})
                # All diagnostics pass through 49's one gate; no raw values in content.
                from langchain_core.messages import ToolMessage
                return ToolMessage(content=json.dumps({'reference': result['reference']}),
                    tool_call_id=call['id'], name=name, artifact={'raw_logs': logs})

        @tool
        def build_presentation(input_reference: str, template: str, title: str, section: str, runtime: ToolRuntime,
                               content: list[dict] | None = None, language: str | None = None):
            """Build editable PPTX: narrative pages or an authorized tabular source."""
            return operate('build_presentation', {'input_reference': input_reference, 'template': template,
                'title': title, 'section': section, **({'content': content} if content is not None else {}),
                **({'language': language} if language is not None else {})}, runtime)

        @tool
        def edit_presentation(logical_id: str, base_revision: str, slide: int, field: str, value: str, runtime: ToolRuntime):
            """Change title or body on one authorized slide, preserving every other part."""
            return operate('edit_presentation', {'logical_id': logical_id, 'base_revision': base_revision,
                'slide': slide, 'field': field, 'value': value}, runtime)

        @tool
        def create_mock_excel(title: str, rows: list[dict], runtime: ToolRuntime):
            """Create a verified Excel from invented rows with item and integer amount_cents; no upload needed."""
            return operate('create_mock_excel', {'title': title, 'rows': rows}, runtime)

        @tool
        def build_excel(input_reference: str, title: str, runtime: ToolRuntime):
            """Build and verify XLSX from the authorized opaque input reference."""
            return operate('build_excel', {'input_reference': input_reference, 'title': title}, runtime)

        @tool
        def rename_excel(logical_id: str, base_revision: str, title: str, runtime: ToolRuntime):
            """Change only the title of the current immutable Excel revision."""
            return operate('rename_excel', {'logical_id': logical_id, 'base_revision': base_revision, 'title': title}, runtime)

        @tool
        def build_document(input_reference: str, format: str, title: str, section: str, runtime: ToolRuntime,
                           content: list[dict] | None = None, language: str | None = None):
            """Create DOCX/PDF from structured narrative pages or authorized local data."""
            return operate('build_document', {'input_reference': input_reference, 'format': format,
                'title': title, 'section': section, **({'content': content} if content is not None else {}),
                **({'language': language} if language is not None else {})}, runtime)

        @tool
        def edit_document(logical_id: str, base_revision: str, field: str, value: str, runtime: ToolRuntime):
            """Edit title, section or page:N:block:N; preserve the current document."""
            return operate('edit_document', {'logical_id': logical_id, 'base_revision': base_revision,
                'field': field, 'value': value}, runtime)

        @tool
        def export_pdf(logical_id: str, base_revision: str, runtime: ToolRuntime):
            """Convert the current verified document to PDF, preserving its content."""
            return operate('export_pdf', {'logical_id': logical_id, 'base_revision': base_revision}, runtime)

        @tool
        def research_sources(ids: list[str], runtime: ToolRuntime):
            """Consult only IDs from the server's authorized primary-source catalog."""
            from langchain_core.messages import ToolMessage
            with tool_lock:
                lease.check()
                call = {'id': runtime.tool_call_id, 'name': 'research_sources', 'args': {'ids': ids}}
                result = internal.operation('run/research', {'call': call})
                lease.check()
                return ToolMessage(content=json.dumps({'reference': result['reference']}),
                    tool_call_id=runtime.tool_call_id, name='research_sources')

        graph = build_agent(backend, internal, tools=[research_sources, create_mock_excel, build_excel, rename_excel, build_document, edit_document, export_pdf, build_presentation, edit_presentation],
            model_profile=granted.get('model_profile'),
            allowed_tools=granted['tools'], system_prompt=runtime_prompt(granted['tools'], skills=bool(granted.get('skills'))),
            prepare_tool=ensure_document_runtime)
        result = graph.invoke({'messages': [HumanMessage(content=granted['message']),
            HumanMessage(content=json.dumps(granted['model_context']), additional_kwargs={'regulay_context': 'bootstrap'})]},
            config={'recursion_limit': 12})
        lease.check()
        while internal.operation('run/review-status', {})['pending']:
            lease.check()
            time.sleep(1)
        internal.operation('run/complete', {})
        return {'status': 'completed', 'message_count': len(result['messages'])}


def run_export(internal, sandbox, lease, granted):
    """Official HITL + SQLite checkpointer; only protected graph state on disk."""
    from langgraph.checkpoint.sqlite import SqliteSaver
    from langgraph.types import Command
    from langchain_core.messages import ToolMessage
    state = Path('/state/checkpoints.sqlite')
    if not state.parent.is_dir():
        raise InternalOperationError('Private durable checkpoint directory required')

    @tool
    def save_revision(artifact_reference: str, sha256: str, name: str, runtime: ToolRuntime):
        """Create the exact verified revision in the configured authorized Drive folder."""
        lease.check()
        call = {'id': runtime.tool_call_id, 'name': 'save_revision',
            'args': {'artifact_reference': artifact_reference, 'sha256': sha256, 'name': name}}
        response = internal.operation('run/save-revision', call)
        return ToolMessage(content=json.dumps({'reference': response['reference']}),
            tool_call_id=runtime.tool_call_id, name='save_revision')

    with SqliteSaver.from_conn_string(str(state)) as checkpointer:
        graph = build_agent(E2BSandbox(sandbox=sandbox, workdir='/workspace/work'), internal,
            tools=[save_revision], allowed_tools=['save_revision'], checkpointer=checkpointer,
            interrupt_on={'save_revision': {'allowed_decisions': ['approve', 'reject']}},
            model_profile=granted.get('model_profile'),
            system_prompt='Use save_revision exactly once with the authorized references. Never change content or destination.')
        config = {'configurable': {'thread_id': granted['execution']}, 'recursion_limit': 8}
        snapshot = graph.get_state(config)
        if not snapshot.values:
            if granted.get('checkpoint_ready'):
                raise InternalOperationError('Durable export checkpoint missing; manual recovery required')
            result = graph.invoke({'messages': [HumanMessage(content=granted['message']),
                HumanMessage(content='Referencias autorizadas del servidor: ' + json.dumps(granted['model_context']))]}, config=config)
            if not result.get('__interrupt__'):
                raise InternalOperationError('Official export interrupt required')
            snapshot = graph.get_state(config)
        calls = [call for message in snapshot.values['messages'] if hasattr(message, 'tool_calls') for call in message.tool_calls]
        if len(calls) != 1 or calls[0]['name'] != 'save_revision':
            raise InternalOperationError('Exactly one export proposal required')
        internal.operation('run/propose-export', {k: calls[0][k] for k in ('id', 'name', 'args')})
        while True:
            lease.check()
            decision = internal.operation('run/approval-state', {})['decision']
            if decision in ('intent', 'uncertain', 'completed'):
                response = internal.operation('run/reconcile-export', {})
                if response['status'] != 'approved':
                    raise InternalOperationError('Export outcome requires reconciliation')
                break
            if decision == 'approved':
                if not snapshot.next:
                    raise InternalOperationError('Approval requires an interrupted checkpoint')
                graph.invoke(Command(resume={'decisions': [{'type': 'approve'}]}), config=config)
                break
            if decision == 'rejected':
                graph.invoke(Command(resume={'decisions': [{'type': 'reject', 'message': 'Rejected by authorized user'}]}), config=config)
                raise InternalOperationError('Export rejected')
            time.sleep(1)
        lease.check()
        internal.operation('run/export-complete', {})
        return {'status': 'completed'}


def prune_checkpoints(client, endpoint, token):
    state = Path('/state/checkpoints.sqlite')
    if not state.is_file():
        return
    response = client.post(endpoint + 'checkpoints/', json={}, headers={'Authorization': 'Bearer ' + token})
    response.raise_for_status()
    keep = set(response.json()['keep'])
    from langgraph.checkpoint.sqlite import SqliteSaver
    with SqliteSaver.from_conn_string(str(state)) as saver:
        threads = {item.config['configurable']['thread_id'] for item in saver.list(None)}
        for thread_id in threads - keep:
            saver.delete_thread(thread_id)


class WorkerResource:
    """Per-execution resource identity; cleanup uses only the worker credential."""
    def __init__(self, internal, pool, endpoint, worker_token, worker_id, claimed):
        self.internal, self.pool, self.endpoint = internal, pool, endpoint
        self.worker_token, self.worker_id, self.claimed = worker_token, worker_id, claimed
        self.reservation_id = str(uuid.uuid4())
        self.sandbox, self.lease = None, None
        self.destroyed = False
        self.lock = threading.RLock()

    def acquire(self, lease):
        self.lease = lease
        while True:
            lease.check()
            reservation = self.internal.operation('run/sandbox', {
                'action': 'reserve', 'reservation_id': self.reservation_id})
            if reservation.get('available'):
                break
            lease.stop.wait(0.5)
        with self.lock:
            lease.check()
            if self.sandbox is None:
                started_at = time.monotonic()
                self.sandbox = self.pool.take()
                if self.sandbox is None:
                    raise InternalOperationError('Reserved sandbox unavailable locally')
                # Attach cancellation before reporting the resource, so a lost
                # response still causes destruction of the exact created VM.
                lease.attach(self.sandbox, on_renew=self.renew, on_cancel=self.close, on_prepared=self.prepared)
                self.internal.operation('run/sandbox', {'action': 'attach',
                    'reservation_id': self.reservation_id, 'sandbox_id': self.sandbox.sandbox_id,
                    'ttl_seconds': 180, 'duration_ms': round((time.monotonic() - started_at) * 1000)})
            lease.check()
            return self.sandbox

    def renew(self):
        self.internal.operation('run/sandbox', {'action': 'renew',
            'reservation_id': self.reservation_id, 'sandbox_id': self.sandbox.sandbox_id,
            'ttl_seconds': 180})

    def prepared(self, duration_ms):
        self.internal.operation('run/sandbox', {'action': 'prepared',
            'reservation_id': self.reservation_id, 'sandbox_id': self.sandbox.sandbox_id,
            'duration_ms': duration_ms})

    def close(self):
        with self.lock:
            if self.sandbox is None:
                return
            if not self.destroyed:
                self.destroyed = self.pool.release(self.sandbox)
            if not self.destroyed:
                return
            payload = {key: self.claimed[key] for key in ('execution', 'attempt')}
            payload.update(worker_id=self.worker_id, reservation_id=self.reservation_id,
                sandbox_id=self.sandbox.sandbox_id, destroyed=True)
            # A separate client avoids reuse of an execution token revoked while
            # a tool ran. A missing cleanup response leaves occupancy conservative.
            try:
                with httpx.Client(follow_redirects=False, trust_env=False, timeout=10) as client:
                    response = client.post(self.endpoint + 'sandbox-cleanup/', json=payload,
                        headers={'Authorization': 'Bearer ' + self.worker_token})
                    response.raise_for_status()
            except Exception:
                pass  # The durable reservation remains until confirmed cleanup.


def run(config, *, once=False, stop_event=None):
    worker_id = str(uuid.uuid4())
    token = Path(config['worker_token_file']).read_text().strip()
    endpoint = config['internal_endpoint'].rstrip('/') + '/'
    concurrency = int(config.get('concurrency', 2))
    if not 1 <= concurrency <= 2:
        raise ValueError('Worker concurrency must be 1 or 2')
    stop_event = stop_event or threading.Event()
    pool = CleanPool(lambda: create_clean(config))
    executor = ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix='regulay-job')
    futures, controls = set(), {}
    control_lock = threading.Lock()

    def execute(claimed):
        internal = InternalClient(endpoint, claimed['token'], claimed['attempt'])
        resource = WorkerResource(internal, pool, endpoint, token, worker_id, claimed)
        def started(lease):
            with control_lock:
                controls[claimed['execution']] = lease
            if stop_event.is_set():
                lease.cancel()
                lease.check()
        started_at = time.monotonic()
        try:
            result = run_job(internal, acquire=resource.acquire, started=started)
            print(json.dumps({'execution': claimed['execution'],
                'sandbox_id': resource.sandbox.sandbox_id if resource.sandbox else None,
                'seconds': time.monotonic() - started_at, 'status': result['status']}), flush=True)
            return {**result, 'pool': list(pool.metrics)}
        except Exception as error:
            # Exception text/tracebacks may contain private tool data or tokens.
            # Correlate a failure without copying that content into worker logs.
            print(json.dumps({'execution': claimed['execution'], 'status': 'failed',
                'error_type': type(error).__name__, 'seconds': time.monotonic() - started_at,
                'sandbox_id': resource.sandbox.sandbox_id if resource.sandbox else None}), flush=True)
            try:
                internal.operation('run/fail', {})
            except Exception:
                pass  # Expiry/revocation/cancellation retains server authority.
            raise InternalOperationError('Execution interrupted; inspect authorized run state') from None
        finally:
            resource.close()
            with control_lock:
                controls.pop(claimed['execution'], None)
            internal.close()

    try:
        with httpx.Client(follow_redirects=False, trust_env=False, timeout=15) as client:
            prune_checkpoints(client, endpoint, token)
            while not stop_event.is_set():
                done = {future for future in futures if future.done()}
                futures -= done
                for future in done:
                    try:
                        result = future.result()
                        if once:
                            return result
                    except Exception:
                        if once:
                            raise
                if len(futures) >= (1 if once else concurrency):
                    wait(futures, timeout=0.25, return_when=FIRST_COMPLETED)
                    continue
                # Claims do not depend on a VM and only consume a free task slot.
                claim_id = str(uuid.uuid4())
                for retry in range(2):
                    try:
                        response = client.post(endpoint + 'claim/', json={
                            'worker_id': worker_id, 'claim_id': claim_id, 'worker_protocol': 2},
                            headers={'Authorization': 'Bearer ' + token})
                        break
                    except httpx.TransportError:
                        if retry:
                            raise InternalOperationError('Claim transport uncertain') from None
                response.raise_for_status()
                claimed = response.json()
                if claimed['status'] == 'idle':
                    if once and not futures:
                        return {'status': 'idle'}
                    stop_event.wait(0.5)
                    continue
                futures.add(executor.submit(execute, claimed))
    finally:
        stop_event.set()
        with control_lock:
            leases = list(controls.values())
        # Cleanup transport may itself stall. Never block the signal-handling
        # dispatcher on it; the supervisor also enforces the 35 second bound.
        for lease in leases:
            lease.lost.set()
            threading.Thread(target=lease.cancel, daemon=True).start()
        executor.shutdown(wait=False, cancel_futures=True)
        if futures:
            wait(futures, timeout=min(30, max(0, float(config.get('shutdown_grace_seconds', 30)))))
        threading.Thread(target=pool.close, daemon=True).start()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    stop_event = threading.Event()
    def stop(*_):
        if stop_event.is_set():
            return
        stop_event.set()
        # ThreadPoolExecutor threads block Python interpreter exit even after
        # shutdown(wait=False). Force termination at the documented upper bound.
        timer = threading.Timer(34, lambda: os._exit(143))
        timer.daemon = True
        timer.start()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print(json.dumps(run(json.loads(args.config.read_text()), once=args.once, stop_event=stop_event)))


if __name__ == '__main__':
    main()
