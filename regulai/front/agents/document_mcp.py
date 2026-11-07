"""One managed MCP connector. All external IDs/bytes/credentials stay here.

The official SDK runs the reviewed server over memory streams. No subprocess,
remote tool discovery, sampling, roots, prompts or model backend is installed.
Only Drive HTTPS is used by the server; the executor has no external transport.
"""
import base64
from contextlib import asynccontextmanager
from datetime import timedelta
import json
import hashlib
import re
import uuid
from urllib.parse import quote

import httpx
from asgiref.sync import async_to_sync
from django.conf import settings
from django.utils import timezone
import anyio
from mcp import ClientSession, types
from mcp.server import Server
from mcp.shared.memory import create_client_server_memory_streams

from front.models import AgentDocumentConnection, AgentDocumentReference, Profile
from front.policy import digest
from .excel_contract import MAX_BYTES, input_rows
from .service import AgentDenied

SERVER = 'regulay-drive-v1'
VERSION = '1'
MIMES = {'text/csv': 'csv',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx'}
SCHEMAS = {
    'search': {'type': 'object', 'properties': {'query': {'type': 'string'}},
        'required': ['query'], 'additionalProperties': False},
    'download': {'type': 'object', 'properties': {'document': {'type': 'string'}},
        'required': ['document'], 'additionalProperties': False},
}
EXPORT_SCHEMAS = {
    'reserve': {'type': 'object', 'properties': {}, 'additionalProperties': False},
    'save_revision': {'type': 'object', 'properties': {key: {'type': 'string'} for key in
        ('document', 'name', 'mime', 'base64', 'sha256')},
        'required': ['document', 'name', 'mime', 'base64', 'sha256'], 'additionalProperties': False},
    'reconcile': {'type': 'object', 'properties': {'document': {'type': 'string'}, 'sha256': {'type': 'string'}},
        'required': ['document', 'sha256'], 'additionalProperties': False},
}
ID = re.compile(r'^[a-zA-Z0-9_-]{1,200}$')


def account(actor):
    if not getattr(settings, 'REGULAY_AGENT_MCP_ENABLED', False):
        raise AgentDenied('document_connector_disabled')
    from .jobs import development_profile
    development_profile(actor)
    profile = Profile.objects.get(user=actor)
    connection = AgentDocumentConnection.objects.filter(user=actor, company_id=profile.company_id,
        enabled=True, expires_at__gt=timezone.now()).first()
    if not connection:
        raise AgentDenied('document_account_unavailable')
    try:
        private = json.loads(connection.private_config)
        if (set(private) not in ({'token', 'identity', 'folders'},
                {'token', 'identity', 'folders', 'write_folder', 'account_label', 'folder_label'})
                or not isinstance(private['token'], str)
                or not private['token'] or not ID.fullmatch(private['identity'])
                or not isinstance(private['folders'], list) or not 1 <= len(private['folders']) <= 10
                or any(not isinstance(f, str) or not ID.fullmatch(f) for f in private['folders'])):
            raise ValueError()
    except (ValueError, TypeError, KeyError):
        raise AgentDenied('document_account_invalid') from None
    binding = digest([str(connection.pk), connection.company_id, connection.user_id,
        connection.version, connection.expires_at.isoformat(), private, connection.write_enabled])
    return connection, private, binding


class Drive:
    """No redirects, proxies, arbitrary hosts/paths, downloads or SDK retries."""
    def __init__(self, private, *, transport=None):
        self.private = private
        self.client = httpx.AsyncClient(base_url='https://www.googleapis.com/drive/v3/',
            headers={'Authorization': 'Bearer ' + private['token']}, transport=transport,
            trust_env=False, follow_redirects=False, timeout=15)

    async def get(self, path, params, *, allow_missing=False, limit=MAX_BYTES):
        async with self.client.stream('GET', path, params=params) as response:
            if allow_missing and response.status_code == 404:
                return None
            if response.status_code != 200:
                raise AgentDenied('document_remote_denied')
            data = bytearray()
            async for chunk in response.aiter_bytes():
                data.extend(chunk)
                if len(data) > limit:
                    raise AgentDenied('document_too_large')
            return bytes(data)

    async def identity(self):
        data = json.loads(await self.get('about', {'fields': 'user(permissionId)'}))
        if data.get('user', {}).get('permissionId') != self.private['identity']:
            raise AgentDenied('document_identity_changed')

    async def metadata(self, document):
        if not isinstance(document, str) or not ID.fullmatch(document):
            raise AgentDenied('document_scope_denied')
        data = json.loads(await self.get('files/' + quote(document, safe=''),
            {'fields': 'id,mimeType,parents,trashed,capabilities(canDownload)'}))
        if (data.get('id') != document or data.get('trashed') is not False
                or not set(data.get('parents', [])) & set(self.private['folders'])
                or data.get('mimeType') not in MIMES
                or data.get('capabilities', {}).get('canDownload') is not True):
            raise AgentDenied('document_scope_denied')
        return data

    async def search(self, query):
        if not isinstance(query, str) or not 1 <= len(query.strip()) <= 160:
            raise AgentDenied('document_query_invalid')
        await self.identity()
        escaped = query.replace('\\', '\\\\').replace("'", "\\'")
        folders = ' or '.join("'" + f + "' in parents" for f in self.private['folders'])
        data = json.loads(await self.get('files', {'q': f"trashed = false and ({folders}) and name contains '{escaped}'",
            'pageSize': 10, 'fields': 'files(id)'}))
        result = []
        for item in data.get('files', [])[:10]:
            await self.metadata(item['id'])  # Search listings never grant authority.
            result.append(item['id'])
        return {'documents': result}

    async def download(self, document):
        await self.identity()
        metadata = await self.metadata(document)
        raw = await self.get('files/' + quote(document, safe=''), {'alt': 'media'})
        # Revocation/move during the transfer withholds delivery.
        await self.identity()
        await self.metadata(document)
        kind = MIMES[metadata['mimeType']]
        input_rows(raw, kind)
        return {'kind': kind, 'base64': base64.b64encode(raw).decode()}

    async def folder(self):
        await self.identity()
        folder = self.private.get('write_folder')
        if not isinstance(folder, str) or not ID.fullmatch(folder):
            raise AgentDenied('export_folder_invalid')
        value = json.loads(await self.get('files/' + folder,
            {'fields': 'id,mimeType,trashed,capabilities(canAddChildren)'}))
        if (value.get('id') != folder or value.get('mimeType') != 'application/vnd.google-apps.folder'
                or value.get('trashed') is not False or value.get('capabilities', {}).get('canAddChildren') is not True):
            raise AgentDenied('export_folder_denied')
        return folder

    async def reserve(self):
        await self.folder()
        value = json.loads(await self.get('files/generateIds', {'count': 1, 'space': 'drive', 'type': 'files'}))
        ids = value.get('ids')
        if not isinstance(ids, list) or len(ids) != 1 or not ID.fullmatch(ids[0]):
            raise AgentDenied('export_reservation_failed')
        return {'document': ids[0]}

    async def reconcile(self, document, sha256):
        folder = await self.folder()
        if not ID.fullmatch(document):
            raise AgentDenied('export_id_invalid')
        raw = await self.get('files/' + document,
            {'fields': 'id,parents,trashed,appProperties'}, allow_missing=True)
        if raw is None:
            return {'matched': False}
        value = json.loads(raw)
        if (value.get('id') != document or value.get('parents') != [folder] or value.get('trashed') is not False
                or value.get('appProperties', {}).get('regulay_sha256') != sha256):
            raise AgentDenied('export_reconciliation_conflict')
        content = await self.get('files/' + document, {'alt': 'media'}, limit=20_000_000)
        if hashlib.sha256(content).hexdigest() != sha256:
            raise AgentDenied('export_reconciliation_conflict')
        return {'matched': True}

    async def save_revision(self, document, name, mime, base64, sha256):
        folder = await self.folder()
        if not ID.fullmatch(document):
            raise AgentDenied('export_id_invalid')
        import base64 as encoding
        content = encoding.b64decode(base64, validate=True)
        if len(content) > 20_000_000 or hashlib.sha256(content).hexdigest() != sha256:
            raise AgentDenied('export_content_changed')
        boundary = 'regulay-' + uuid.uuid4().hex
        metadata = json.dumps({'id': document, 'name': name, 'parents': [folder],
            'appProperties': {'regulay_sha256': sha256}}, ensure_ascii=False).encode()
        body = (f'--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n'.encode() + metadata +
            f'\r\n--{boundary}\r\nContent-Type: {mime}\r\n\r\n'.encode() + content + f'\r\n--{boundary}--\r\n'.encode())
        response = await self.client.post('https://www.googleapis.com/upload/drive/v3/files',
            params={'uploadType': 'multipart', 'fields': 'id'}, content=body,
            headers={'Content-Type': 'multipart/related; boundary=' + boundary})
        if response.status_code not in (200, 201) or response.json().get('id') != document:
            raise AgentDenied('export_outcome_unknown')
        return await self.reconcile(document, sha256)


def server(drive, *, writing=False):
    app = Server(SERVER, version=VERSION)

    @app.list_tools()
    async def tools():
        catalog = {**SCHEMAS, **(EXPORT_SCHEMAS if writing else {})}
        return [types.Tool(name=name, inputSchema=schema) for name, schema in catalog.items()]

    @app.call_tool()
    async def invoke(name, arguments):
        try:
            if name == 'search' and set(arguments) == {'query'}:
                value = await drive.search(arguments['query'])
            elif name == 'download' and set(arguments) == {'document'}:
                value = await drive.download(arguments['document'])
            elif writing and name in EXPORT_SCHEMAS and set(arguments) == set(EXPORT_SCHEMAS[name].get('required', [])):
                value = await getattr(drive, name)(**arguments)
            else:
                raise AgentDenied('document_operation_denied')
            return types.CallToolResult(content=[], structuredContent=value)
        except Exception:
            # SDK diagnostics must not contain a provider response or token.
            return types.CallToolResult(content=[], isError=True)
    return app


async def _call(private, operation, arguments, *, transport=None):
    drive = Drive(private, transport=transport)
    try:
        writing = operation in EXPORT_SCHEMAS
        async with session(server(drive, writing=writing)) as client:
            # Pin the whole catalog. An extra tool or changed schema closes access.
            catalog = await client.list_tools()
            expected = {**SCHEMAS, **(EXPORT_SCHEMAS if writing else {})}
            if {t.name: t.inputSchema for t in catalog.tools} != expected or catalog.nextCursor:
                raise AgentDenied('document_catalog_changed')
            result = await client.call_tool(operation, arguments)
            if result.isError or result.content or not isinstance(result.structuredContent, dict):
                raise AgentDenied('document_operation_failed')
            return result.structuredContent
    except Exception:
        raise AgentDenied('document_operation_failed') from None
    finally:
        await drive.client.aclose()


@asynccontextmanager
async def session(app):
    async with create_client_server_memory_streams() as (client_streams, server_streams):
        async with anyio.create_task_group() as group:
            group.start_soon(app.run, *server_streams, app.create_initialization_options())
            try:
                # No sampling/elicitation/roots callback; no capabilities granted.
                async with ClientSession(*client_streams, read_timeout_seconds=timedelta(seconds=30)) as client:
                    initialized = await client.initialize()
                    if initialized.serverInfo.name != SERVER or initialized.serverInfo.version != VERSION:
                        raise AgentDenied('document_server_changed')
                    yield client
            finally:
                group.cancel_scope.cancel()


def call(private, operation, arguments):
    # Only application-owned code calls this; neither a model nor request chooses
    # transport/server/path. Tests replace the external transport only.
    return async_to_sync(_call)(private, operation, arguments)


def search(actor, query):
    connection, private, binding = account(actor)
    value = call(private, 'search', {'query': query})
    if account(actor)[2] != binding:
        raise AgentDenied('document_authorization_changed')
    if set(value) != {'documents'} or not isinstance(value['documents'], list) or len(value['documents']) > 10:
        raise AgentDenied('document_result_invalid')
    results = []
    for index, original in enumerate(value['documents']):
        if not isinstance(original, str) or not ID.fullmatch(original):
            raise AgentDenied('document_result_invalid')
        reference = AgentDocumentReference.objects.create(connection=connection, original_id=original,
            binding=binding, expires_at=min(connection.expires_at, timezone.now() + timedelta(minutes=10)))
        results.append({'reference': str(reference.pk), 'label': f'Documento autorizado {index + 1}'})
    return {'status': 'authorized', 'documents': results}


def obtain(actor, reference):
    connection, private, binding = account(actor)
    try:
        row = AgentDocumentReference.objects.get(pk=reference, connection=connection,
            binding=binding, expires_at__gt=timezone.now())
    except (ValueError, AgentDocumentReference.DoesNotExist):
        raise AgentDenied('document_reference_denied') from None
    value = call(private, 'download', {'document': row.original_id})
    if account(actor)[2] != binding:
        raise AgentDenied('document_authorization_changed')
    if set(value) != {'kind', 'base64'} or value['kind'] not in ('csv', 'xlsx'):
        raise AgentDenied('document_result_invalid')
    try:
        raw = base64.b64decode(value['base64'], validate=True)
        input_rows(raw, value['kind'])
    except (ValueError, TypeError):
        raise AgentDenied('document_result_invalid') from None
    return raw, value['kind']
