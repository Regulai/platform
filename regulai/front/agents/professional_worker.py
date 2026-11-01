"""General Deep Agents tools. This module never imports Django or credentials."""
import base64
import hashlib
import importlib.metadata
import json
from pathlib import Path
import shlex
import time
import uuid

from langchain.tools import ToolRuntime, tool
from langchain_core.messages import HumanMessage, ToolMessage, messages_to_dict, messages_from_dict
from langchain.agents.middleware import AgentMiddleware

from .adapter import InternalOperationError, build_agent, _wire
from .workspace_backend import WorkspaceSandbox
from .runtime_contract import canonical_digest


def runtime_identity():
    versions = {name: importlib.metadata.version(name) for name in
        ('deepagents', 'langgraph', 'langchain', 'langchain-e2b')}
    root = Path(__file__).parent
    return canonical_digest({'versions': versions, 'files': {name: hashlib.sha256(
        root.joinpath(name).read_bytes()).hexdigest() for name in
        ('sandbox_runner.py', 'checkpoint_runner.py', 'runtime/professional.md', 'adapter.py', 'protocol.py', 'skill_backend.py')}})


def run_professional(internal, sandbox, lease, granted, *, acquire=None):
    if granted.get('reconcile_final_call_id'):
        lease.check()
        result = internal.operation('run/complete', {'final_call_id': granted['reconcile_final_call_id']})
        if not result.get('completed'):
            raise InternalOperationError('Recorded final delivery remains incomplete')
        return {'status': 'completed', 'message_count': 0, 'reconciled': True}
    budget = granted['limits']
    runtime_hash, workspace_hash = runtime_identity(), None
    restored = granted.get('checkpoint')
    if restored and restored.get('version', 1) == 2:
        if restored['runtime_sha256'] != runtime_hash:
            raise InternalOperationError('Checkpoint runtime changed')

    def prepare(backend):
        nonlocal sandbox, workspace_hash
        lease.check()
        if sandbox is None:
            if acquire is None:
                raise InternalOperationError('Sandbox acquisition unavailable')
            sandbox = acquire(lease)
        lease.attach(sandbox)
        backend._sandbox = sandbox
        preparation_started = time.monotonic()
        # Fixed-size private workspace; only trusted bootstrap bytes are mounted.
        sandbox.commands.run('mount -t tmpfs -o size=' + str(budget['workspace_bytes']) + ',nosuid,nodev tmpfs /workspace && '
            'mkdir -p /workspace/input /workspace/work /workspace/output && chown user:user /workspace/work /workspace/output',
            user='root', timeout=10)
        assets = ([granted['input']] if granted.get('input') else []) + granted.get('workspace_inputs', [])
        for asset in assets:
            from .workspace_backend import valid_path
            path = valid_path(asset['path'])
            if not path.startswith('/workspace/input/'):
                raise InternalOperationError('Input path denied')
            data = base64.b64decode(asset['base64'], validate=True)
            if hashlib.sha256(data).hexdigest() != asset['sha256']:
                raise InternalOperationError('Input digest changed')
            sandbox.files.write(path, data, user='root')
        sandbox.commands.run('chmod -R a-w /workspace/input && mount --bind /workspace/input /workspace/input && '
            'mount -o remount,bind,ro /workspace/input', user='root', timeout=10)
        probe = json.loads(backend.execute('python -c "import os; assert os.getuid()==1000; assert not os.path.exists(\'/run\')"').output)
        if probe['exit_code']:
            raise InternalOperationError('Workspace isolation unavailable')
        workspace_hash = hashlib.sha256(backend._file('/skills/runtime-versions.txt')).hexdigest()
        if restored and restored.get('archive'):
            expected = restored.get('workspace_runtime_sha256') if restored.get('version', 1) == 2 else restored['runtime_sha256']
            if expected != workspace_hash:
                raise InternalOperationError('Checkpoint workspace runtime changed')
            archive = base64.b64decode(restored['archive'], validate=True)
            if backend.upload_files([('/workspace/work/.regulay-checkpoint.zip', archive)])[0].error:
                raise InternalOperationError('Checkpoint transfer failed')
            if backend.execute('python -I /skills/checkpoint_runner.py restore ' + str(budget['workspace_bytes']) + ' ' + str(budget['file_bytes'])).exit_code:
                raise InternalOperationError('Checkpoint restore failed')
        else:
            for asset in assets:
                if asset.get('work_path'):
                    data = base64.b64decode(asset['base64'], validate=True)
                    if backend.upload_files([(asset['work_path'], data)])[0].error:
                        raise InternalOperationError('Revision working copy unavailable')
        lease.check()
        # Permission is checked again after waiting for capacity and preparing.
        internal.operation('run/renew', {})
        if lease.on_prepared:
            lease.on_prepared(round((time.monotonic() - preparation_started) * 1000))

    backend = WorkspaceSandbox(limits=budget, lease=lease, prepare=prepare)
    sandbox_tools = set(granted.get('sandbox_tools', granted['tools']))

    def prepare_tool(call, grant):
        path = call['args'].get('file_path', call['args'].get('path', ''))
        if path == '/skills' or path.startswith('/skills/'):
            return
        if call['name'] in sandbox_tools:
            backend.prepare_authorized()
            if getattr(internal, 'skill_backend', None):
                internal.skill_backend.materialize(call, sandbox)

    def call(runtime, name, args):
        # Preserve omitted optional arguments exactly as issued by the provider;
        # Python's function defaults are not a different authorized tool call.
        for message in reversed(runtime.state.get('messages', [])):
            for issued in getattr(message, 'tool_calls', []):
                if issued['id'] == runtime.tool_call_id and issued['name'] == name:
                    return {key: issued[key] for key in ('id', 'name', 'args')}
        raise InternalOperationError('Issued tool call unavailable')

    def recorded(runtime, name):
        return ToolMessage(content='Recorded by Regulay.', tool_call_id=runtime.tool_call_id, name=name)

    def web(runtime, name, args):
        result = internal.operation('run/web', {'call': call(runtime, name, args)})
        if result.get('base64'):
            content = base64.b64decode(result['base64'], validate=True)
            uploaded = backend.upload_files([(result['file_path'], content)])[0]
            if uploaded.error:
                raise InternalOperationError('Downloaded file could not be stored')
        return recorded(runtime, name)

    @tool
    def web_search(query: str, runtime: ToolRuntime, max_results: int = 5, language: str = '', time_range: str = ''):
        """Search public web, then open sources to read evidence."""
        return web(runtime, 'web_search', {'query': query, 'max_results': max_results,
            **({'language': language} if language else {}), **({'time_range': time_range} if time_range else {})})

    @tool
    def web_open(url: str, runtime: ToolRuntime, offset: int = 0, limit: int = 12000):
        """Read public HTML, text or PDF with stable references and explicit coverage."""
        return web(runtime, 'web_open', {'url': url, 'offset': offset, 'limit': limit})

    @tool
    def web_find(reference: str, term: str, runtime: ToolRuntime):
        """Find literal text in opened source evidence."""
        return web(runtime, 'web_find', {'reference': reference, 'term': term})

    @tool
    def web_download(url: str, file_path: str, runtime: ToolRuntime):
        """Download a public file through the broker into this workspace."""
        return web(runtime, 'web_download', {'url': url, 'file_path': file_path})

    @tool
    def web_browse(url: str, runtime: ToolRuntime):
        """Read a JavaScript page using an isolated browser without private files."""
        from .browser_worker import browse
        selected = call(runtime, 'web_browse', {'url': url})
        browse(internal, sandbox, lease, selected, budget)
        return recorded(runtime, 'web_browse')

    @tool
    def read_output(call_id: str, runtime: ToolRuntime, offset: int = 0):
        """Read more of an earlier command's protected output."""
        internal.operation('run/output', {'call': call(runtime, 'read_output', {'call_id': call_id, 'offset': offset})})
        return recorded(runtime, 'read_output')

    @tool
    def install_packages(ecosystem: str, packages: list[str], runtime: ToolRuntime):
        """Install pinned packages offline into this job's Python/Node environment."""
        result = internal.operation('run/packages', {'call': call(runtime, 'install_packages', {'ecosystem': ecosystem, 'packages': packages})})
        if result.get('succeeded') is False:
            return recorded(runtime, 'install_packages')
        backend.execute('mkdir -p /workspace/work/.packages')
        for asset in result['files']:
            raw = base64.b64decode(asset['base64'], validate=True)
            if hashlib.sha256(raw).hexdigest() != asset['sha256']:
                raise InternalOperationError('Package digest changed')
            if backend.upload_files([(asset['path'], raw)])[0].error:
                raise InternalOperationError('Package transfer failed')
        if ecosystem == 'pip':
            requirements = '\n'.join(f"{p['name']}=={p['version']} --hash=sha256:{p['sha256']}" for p in result['manifest'])
            if backend.upload_files([('/workspace/work/.packages/requirements.lock', requirements.encode())])[0].error:
                raise InternalOperationError('Package lock unavailable')
            command = ('python -m venv --system-site-packages /workspace/work/.venv && '
                '/workspace/work/.venv/bin/python -m pip install --no-index --no-deps --require-hashes '
                '--find-links /workspace/work/.packages -r /workspace/work/.packages/requirements.lock && '
                '/workspace/work/.venv/bin/python -m pip check')
        else:
            paths = [shlex.quote(p['path']) for p in result['files']]
            cache = ' && '.join('npm cache add --offline --ignore-scripts ' + path for path in paths)
            command = cache + ' && npm install --offline --ignore-scripts --no-audit --no-fund --prefix /workspace/work ' + ' '.join(paths)
        response = backend.execute(command, timeout=budget['command_seconds'])
        return ToolMessage(content=json.dumps({'installed': response.exit_code == 0, 'manifest': result['manifest'],
            'diagnostics': json.loads(response.output)}), tool_call_id=runtime.tool_call_id, name='install_packages')

    def files(paths):
        result = {}
        for path in dict.fromkeys(paths):
            downloaded = backend.download_files([path])[0]
            if downloaded.error or downloaded.content is None:
                raise ValueError('Workspace file unavailable: ' + path)
            result[path] = base64.b64encode(downloaded.content).decode()
        return result

    @tool
    def publish_artifact(file_path: str, title: str, runtime: ToolRuntime, pdf_path: str = '',
                         page_paths: list[str] | None = None, sources: list[str] | None = None,
                         base_revision: str = '', synthetic: bool = False, related_paths: list[str] | None = None):
        """Submit an output, its rendered pages and provenance for server verification."""
        args = {'file_path': file_path, 'title': title, 'synthetic': synthetic,
            **({'pdf_path': pdf_path} if pdf_path else {}), **({'page_paths': page_paths} if page_paths else {}),
            **({'sources': sources} if sources else {}), **({'base_revision': base_revision} if base_revision else {})}
        if related_paths:
            args['related_paths'] = related_paths
        paths = [file_path, *(page_paths or []), *([pdf_path] if pdf_path else []), *(related_paths or [])]
        rendering = None
        if Path(file_path).suffix.lower() in ('.docx', '.pptx', '.pdf'):
            target = '/workspace/output/.render-' + uuid.uuid4().hex
            rendered = json.loads(backend.execute('python -I /skills/artifact_render.py ' + shlex.quote(file_path)
                + ' ' + target + ' ' + str(budget['pdf_pages'])).output)
            if rendered['exit_code'] or rendered['truncated']:
                raise InternalOperationError('Rendering failed: ' + rendered['stderr'][:2000])
            rendering = json.loads(rendered['stdout'])
            paths = [file_path, rendering['pdf_path'], *rendering['page_paths'], *(related_paths or [])]
        internal.operation('run/publish', {'call': call(runtime, 'publish_artifact', args), 'files': files(paths),
            **({'render': rendering} if rendering else {})})
        return recorded(runtime, 'publish_artifact')

    @tool
    def inspect_image(file_path: str, question: str, runtime: ToolRuntime):
        """Send actual authorized pixels through the vision gateway for review."""
        internal.operation('run/image', {'call': call(runtime, 'inspect_image', {'file_path': file_path, 'question': question}),
            'base64': files([file_path])[file_path]})
        return recorded(runtime, 'inspect_image')

    @tool
    def replace_file(file_path: str, expected_sha256: str, content: str):
        """Replace a file atomically only when its SHA-256 still matches."""
        return json.dumps(backend.replace(file_path, expected_sha256, content), ensure_ascii=False)

    @tool
    def edit_file(file_path: str, old_string: str, new_string: str, replace_all: bool = False,
                  expected_sha256: str | None = None):
        """Edit exact text, optionally requiring the expected file SHA-256."""
        result = backend.edit(file_path, old_string, new_string, replace_all, expected_sha256)
        if result.error:
            try:
                return json.dumps(json.loads(result.error), ensure_ascii=False)
            except ValueError:
                return json.dumps({'succeeded': False, 'code': 'file_operation_denied', 'summary': result.error})
        return json.dumps({'succeeded': True, 'code': 'file_edited', 'path': file_path, 'occurrences': result.occurrences})

    tools = [web_search, web_open, web_find, web_download, web_browse, install_packages,
        publish_artifact, inspect_image, read_output, replace_file, edit_file]
    tools = [t for t in tools if t.name in granted['tools']]
    recovered_event = None
    class SafeBoundary(AgentMiddleware):
        def before_model(self, state, runtime):
            lease.check()
            # The pinned SDK intentionally omits PrivateStateAttr fields from
            # graph input. Restore the server-verified event through middleware
            # state updates, not graph.invoke's public input schema.
            restore_update = ({'_summarization_event': recovered_event}
                if recovered_event and not state.get('_summarization_event') else None)
            archive = restored.get('archive') if restored else None
            retained_hash = (restored.get('workspace_runtime_sha256') if restored.get('version', 1) == 2
                else restored['runtime_sha256']) if restored and archive else None
            if backend.prepared:
                response = backend.execute('python -I /skills/checkpoint_runner.py save ' + str(budget['workspace_bytes']) + ' ' + str(budget['file_bytes']))
                if response.exit_code:
                    return restore_update
                try:
                    archive = base64.b64encode(backend._file('/workspace/work/.regulay-checkpoint.zip')).decode()
                except ValueError:
                    return restore_update
            summary = None
            if event := state.get('_summarization_event') or recovered_event:
                reference = internal.compactions.get(canonical_digest(event['summary_message'].content))
                if reference is None:
                    raise InternalOperationError('Compaction receipt unavailable')
                summary = {'cutoff_index': event['cutoff_index'], **reference}
            internal.operation('run/checkpoint', {'version': 2, 'messages': messages_to_dict(state['messages']),
                'wire_messages': [_wire(m) for m in state['messages']],
                'archive': archive, 'runtime_sha256': runtime_hash,
                'workspace_runtime_sha256': workspace_hash or retained_hash, 'summarization': summary,
                **({'skills': {'version': 1, 'digest': granted['skills']['digest'], 'revisions': [
                    {'revision_id': entry['revision_id'], 'folder_sha256': entry['folder_sha256']}
                    for entry in granted['skills']['catalog']]}} if granted.get('skills') else {})})
            return restore_update

        def after_model(self, state, runtime):
            nonlocal recovered_event
            if state.get('_summarization_event'):
                recovered_event = state['_summarization_event']
            return None
    prompt = Path(__file__).with_name('runtime').joinpath('professional.md').read_text(encoding='utf-8')
    graph = build_agent(backend, internal, tools=tools, allowed_tools=granted['tools'],
        model_profile=granted.get('model_profile'), system_prompt=prompt,
        middleware=[SafeBoundary()], prepare_tool=prepare_tool)
    messages = messages_from_dict(restored['messages']) if restored else [HumanMessage(content=granted['message']),
        HumanMessage(content=json.dumps(granted['model_context'], ensure_ascii=False),
            additional_kwargs={'regulay_context': 'bootstrap'})]
    graph_input = {'messages': messages}
    if restored and restored.get('_summarization_event'):
        event = dict(restored['_summarization_event'])
        event['summary_message'] = messages_from_dict([event['summary_message']])[0]
        recovered_event = event
        internal.compactions[canonical_digest(event['summary_message'].content)] = {
            key: restored['summarization'][key] for key in ('compaction_call_id', 'summary_digest')}
    # Final-delivery repairs are separate from the graph's normal tool loop.
    for final_attempt in range(2):
        result = graph.invoke(graph_input, config={'recursion_limit': budget['tool_calls'] * 3 + 10})
        lease.check()
        last = result['messages'][-1]
        receipt = last.response_metadata.get('regulay', {})
        while internal.operation('run/review-status', {})['pending']:
            lease.check()
            time.sleep(1)
        completion = internal.operation('run/complete', {'final_call_id': receipt['call_id']})
        if completion.get('completed'):
            return {'status': 'completed', 'message_count': len(result['messages'])}
        graph_input = {**result, 'messages': [*result['messages'], HumanMessage(content='Comprobación de entrega de Regulay: ' +
            json.dumps(completion['problems']) + '. Corrige lo pendiente sin inventar evidencia.')]}
    raise InternalOperationError('Final delivery remains incomplete')
