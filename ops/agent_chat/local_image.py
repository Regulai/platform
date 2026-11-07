"""Read-only loopback registry for one locally built Docker-save archive.

No push, cloud upload or mutable registry. E2B's image importer reads this OCI
manifest and blobs only while building its Firecracker template.
"""
import gzip
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tarfile


def serve(archive_path):
    root = Path(archive_path).parent / 'image-blobs'
    root.mkdir(exist_ok=True)
    def blob(data):
        digest = hashlib.sha256(data).hexdigest()
        (root / digest).write_bytes(data)
        return {'digest': 'sha256:' + digest, 'size': len(data)}
    with tarfile.open(archive_path) as archive:
        manifest = json.load(archive.extractfile('manifest.json'))[0]
        config = blob(archive.extractfile(manifest['Config']).read())
        config['mediaType'] = 'application/vnd.docker.container.image.v1+json'
        layers = []
        for name in manifest['Layers']:
            data = archive.extractfile(name).read()
            if data[:2] != b'\x1f\x8b':
                data = gzip.compress(data, compresslevel=1, mtime=0)
            layers.append({**blob(data), 'mediaType': 'application/vnd.docker.image.rootfs.diff.tar.gzip'})
    raw = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.docker.distribution.manifest.v2+json',
                      'config': config, 'layers': layers}).encode()
    (root.parent / 'image-manifest.sha256').write_text(hashlib.sha256(raw).hexdigest())
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/v2/':
                data, mime = b'{}', 'application/json'
            elif self.path.startswith('/v2/task50-sheet/manifests/'):
                data, mime = raw, 'application/vnd.docker.distribution.manifest.v2+json'
            elif self.path.startswith('/v2/task50-sheet/blobs/sha256:'):
                name = self.path.rsplit(':', 1)[1]
                if len(name) != 64 or any(c not in '0123456789abcdef' for c in name) or not (root / name).exists():
                    self.send_error(404)
                    return
                data, mime = (root / name).read_bytes(), 'application/octet-stream'
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Content-Type', mime)
            self.send_header('Docker-Content-Digest', 'sha256:' + hashlib.sha256(data).hexdigest())
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(data)
        do_HEAD = do_GET
        def log_message(self, *args):
            pass
    print('Loopback image ready', flush=True)
    ThreadingHTTPServer(('127.0.0.1', 5000), Handler).serve_forever()


if __name__ == '__main__':
    import sys
    serve(sys.argv[1])
