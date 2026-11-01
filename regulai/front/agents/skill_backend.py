"""Pinned SDK skills backend. Private HTTP only; never opens a local file or VM."""
import asyncio
import base64
import fnmatch
import hashlib
import json
from pathlib import PurePosixPath
import re
import shlex
import uuid

from deepagents.backends.protocol import (BackendProtocol, EditResult, FileDownloadResponse,
    FileUploadResponse, GlobResult, GrepResult, LsResult, ReadResult, WriteResult)
from deepagents.middleware.skills import SkillsMiddleware
from langchain_core.messages import SystemMessage


SKILLS_PROMPT = ('Skills autorizadas, sin permisos adicionales. Las seleccionadas ya cargadas no requieren lectura.\n'
    '{skills_locations}\n{skills_list}\n{skills_load_warnings}')


class SkillBackend(BackendProtocol):
    def __init__(self, internal, snapshot, *, discovery=False):
        self.internal, self.snapshot, self.discovery = internal, snapshot, discovery
        self.materialized = set()
        self._skill_view = None
        self._materialization_failed = False

    def _catalog(self):
        value = self.internal.operation('run/skills', {})
        if value['digest'] != self.snapshot['digest']:
            raise ValueError('Skills catalog changed')
        return value['catalog']

    def _path(self, path):
        if (not isinstance(path, str) or not path.startswith('/') or '\\' in path or '\x00' in path
                or '..' in PurePosixPath(path).parts or str(PurePosixPath(path)) != path.rstrip('/') and path != '/'):
            raise ValueError('Skill path denied')
        return path.rstrip('/') or '/'

    def _entry(self, path, catalog):
        path = self._path(path)
        alias, _, relative = path.lstrip('/').partition('/')
        for entry in catalog:
            if entry['alias'] == alias and relative:
                return entry, relative
        raise ValueError('Skill resource unavailable')

    def ls(self, path):
        path, catalog = self._path(path), self._catalog()
        if path == '/':
            return LsResult(entries=[{'path': '/' + entry['alias'], 'is_dir': True} for entry in catalog])
        prefix, found = path + '/', {}
        for entry in catalog:
            for item in entry['manifest']:
                candidate = '/' + entry['alias'] + '/' + item['path']
                if candidate.startswith(prefix):
                    part, separator, _ = candidate[len(prefix):].partition('/')
                    found[prefix + part] = {'path': prefix + part, 'is_dir': bool(separator),
                        **({} if separator else {'size': item['bytes']})}
        return LsResult(entries=list(found.values()))

    def download_files(self, paths):
        catalog, wanted, results = self._catalog(), [], {}
        for path in paths:
            try:
                entry, relative = self._entry(path, catalog)
                if self.discovery and relative == 'SKILL.md':
                    results[path] = FileDownloadResponse(path=path, content=entry['discovery'].encode())
                else:
                    wanted.append({'installation_id': entry['installation_id'], 'revision_id': entry['revision_id'],
                        'path': '/skills/' + entry['alias'] + '/' + relative})
            except ValueError:
                results[path] = FileDownloadResponse(path=path, error='permission_denied')
        if wanted:
            response = self.internal.operation('run/skill-resource', {'files': wanted})
            for item in response['files']:
                raw = base64.b64decode(item['base64'], validate=True)
                if hashlib.sha256(raw).hexdigest() != item['sha256']:
                    raise ValueError('Skill resource digest changed')
                path = item['path'].removeprefix('/skills')
                results[path] = FileDownloadResponse(path=path, content=raw)
        return [results.get(path, FileDownloadResponse(path=path, error='file_not_found')) for path in paths]

    def read(self, file_path, offset=0, limit=2000):
        if type(offset) is not int or type(limit) is not int or offset < 0 or not 1 <= limit <= 2000:
            return ReadResult(error='Skill read range invalid')
        result = self.download_files([file_path])[0]
        if result.error:
            return ReadResult(error=result.error)
        try:
            content = ''.join(result.content.decode('utf-8').splitlines(keepends=True)[offset:offset + limit])
        except UnicodeError:
            return ReadResult(error='Binary resource requires an authorized script')
        return ReadResult(file_data={'content': content, 'encoding': 'utf-8'})

    def glob(self, pattern, path=None):
        prefix, catalog = self._path(path or '/') + '/', self._catalog()
        if prefix == '//':
            prefix = '/'
        return GlobResult(matches=[{'path': candidate, 'is_dir': False, 'size': item['bytes']}
            for entry in catalog for item in entry['manifest']
            if (candidate := '/' + entry['alias'] + '/' + item['path']).startswith(prefix)
            and (fnmatch.fnmatchcase(candidate, pattern) or fnmatch.fnmatchcase(candidate[len(prefix):], pattern))])

    def grep(self, pattern, path=None, glob=None):
        if not isinstance(pattern, str) or len(pattern) > 500:
            return GrepResult(error='Skill search pattern too long')
        matches = []
        for item in self.glob(glob or '*', path).matches:
            read = self.read(item['path'])
            if read.error:
                continue
            for index, line in enumerate(read.file_data['content'].splitlines(), 1):
                if pattern in line:
                    matches.append({'path': item['path'], 'line': index, 'text': line[:2000]})
                    if len(matches) == 100:
                        return GrepResult(matches=matches)
        return GrepResult(matches=matches)

    def write(self, file_path, content):
        return WriteResult(error='Skills are read-only')

    def edit(self, file_path, old_string, new_string, replace_all=False):
        return EditResult(error='Skills are read-only')

    def upload_files(self, files):
        return [FileUploadResponse(path=path, error='permission_denied') for path, _ in files]

    async def adownload_files(self, paths):
        return await asyncio.to_thread(self.download_files, paths)

    async def aupload_files(self, files):
        return await asyncio.to_thread(self.upload_files, files)

    @staticmethod
    def _root(sandbox, command):
        return sandbox.commands.run('set -eu; ' + command, user='root', timeout=10)

    def _discard_stage(self, sandbox, private, source, target):
        # A command acknowledgement can be lost after a successful mount. Only
        # unmount a target whose inode is our private source, never the original
        # /skills mount. Stop before deleting bytes if either unmount fails.
        q = shlex.quote
        try:
            self._root(sandbox, 'if [ -e ' + q(source) + ' ]; then '
                'if [ -e ' + q(target) + ' ] && [ "$(stat -c %d:%i ' + q(source)
                + ')" = "$(stat -c %d:%i ' + q(target) + ')" ]; then umount -- ' + q(target) + '; fi; '
                'if mountpoint -q -- ' + q(source) + '; then umount -- ' + q(source) + '; fi; fi; '
                'rm -rf -- ' + q(private))
        except BaseException as error:
            self._materialization_failed = True
            raise RuntimeError('Skill mount cleanup failed; discard this sandbox') from error

    def _prepare_skill_view(self, sandbox, catalog):
        if self._skill_view is not None:
            return
        private = '/root/.regulay-skills-' + uuid.uuid4().hex
        view, q = private + '/view', shlex.quote
        self._root(sandbox, 'umask 077; mkdir ' + q(private))
        try:
            # Copy the immutable platform helpers once. Reserve mountpoints for
            # this pinned catalog without fetching/materializing its packages.
            commands = ['mkdir ' + q(view), 'cp -a /skills/. ' + q(view)]
            for entry in catalog:
                target = q(view + '/' + entry['alias'])
                commands.extend(['test ! -e ' + target, 'test ! -L ' + target, 'mkdir ' + target])
            commands.extend(['chmod -R a+rX,a-w ' + q(view), 'mount --bind ' + q(view) + ' ' + q(view),
                'mount -o remount,bind,ro ' + q(view), 'mount --bind ' + q(view) + ' /skills'])
            self._root(sandbox, ' && '.join(commands))
        except BaseException:
            self._discard_stage(sandbox, private, view, '/skills')
            raise
        self._skill_view = private

    def materialize(self, call, sandbox):
        """After tool authorization: stage privately, seal, then publish RO.

        The backing directories remain private for this VM's lifetime and are
        destroyed with it. No package discovery allocates or prepares a VM.
        ResultGate serializes this method with user commands.
        """
        if call['name'] != 'execute':
            return
        if self._materialization_failed:
            raise RuntimeError('Skill materialization unavailable after mount cleanup failure')
        catalog = self._catalog()
        aliases = [entry['alias'] for entry in catalog]
        if (len(set(aliases)) != len(aliases) or any(not isinstance(alias, str) or len(alias) > 64
                or not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', alias) for alias in aliases)):
            raise ValueError('Skill alias denied')
        for entry in catalog:
            alias = entry['alias']
            # Also recognize SKILL_ROOT=/skills/name; never match name-other.
            referenced = re.search(r'(?<![\w./-])/skills/' + re.escape(alias)
                + r'''(?=$|[/\s'";|&()<>{}])''', call['args']['command'])
            if not referenced or entry['revision_id'] in self.materialized:
                continue
            paths = ['/' + alias + '/' + item['path'] for item in entry['manifest']]
            if len(set(paths)) != len(paths) or any(self._path(path) != path for path in paths):
                raise ValueError('Skill manifest path denied')
            files = self.download_files(paths)
            for path, expected, item in zip(paths, entry['manifest'], files, strict=True):
                if (item.error or item.path != path or item.content is None
                        or len(item.content) != expected['bytes']
                        or hashlib.sha256(item.content).hexdigest() != expected['sha256']):
                    raise ValueError('Skill materialization unavailable')
            self._prepare_skill_view(sandbox, catalog)
            private = self._skill_view + '/bundle-' + uuid.uuid4().hex
            source, target, q = private + '/content', '/skills/' + alias, shlex.quote
            self._root(sandbox, 'umask 077; mkdir ' + q(private))
            try:
                self._root(sandbox, 'mkdir ' + q(source))
                for item in files:
                    destination = source + item.path[len('/' + alias):]
                    self._root(sandbox, 'mkdir -p ' + q(str(PurePosixPath(destination).parent)))
                    sandbox.files.write(destination, item.content, user='root')
                self._root(sandbox, 'chmod -R a+rX,a-w ' + q(source) + ' && mount --bind '
                    + q(source) + ' ' + q(source) + ' && mount -o remount,bind,ro ' + q(source)
                    + ' && mount --bind ' + q(source) + ' ' + q(target))
            except BaseException:
                self._discard_stage(sandbox, private, source, target)
                raise
            self.materialized.add(entry['revision_id'])


class AuthorizedSkillsMiddleware(SkillsMiddleware):
    """Native loader and formatter, with a typed pointer to its appended block."""
    def __init__(self, backend, digest):
        super().__init__(backend=backend, sources=['/skills/'], system_prompt=SKILLS_PROMPT)
        self.catalog_digest = digest

    def modify_request(self, request):
        result = super().modify_request(request)
        message = result.system_message
        blocks = message.content_blocks
        return result.override(system_message=SystemMessage(content=blocks,
            additional_kwargs={'regulay_skill_catalog': {'digest': self.catalog_digest, 'block_index': len(blocks) - 1}}))


def compose(workspace, internal, snapshot):
    from deepagents.backends.composite import CompositeBackend
    skills = SkillBackend(internal, snapshot)
    discovery = SkillBackend(internal, snapshot, discovery=True)
    backend = CompositeBackend(default=workspace, routes={'/skills/': skills})
    discovery_backend = CompositeBackend(default=workspace, routes={'/skills/': discovery})
    middleware = AuthorizedSkillsMiddleware(discovery_backend, snapshot['digest'])
    return backend, skills, middleware
