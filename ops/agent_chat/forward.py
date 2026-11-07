"""Local-only raw TCP tunnel to the ASGI service in the existing private VM.

Uses the VM's existing private SSH key in its own container; never exports keys.
No public listener is created. The destination service controls authentication.
"""
import argparse
import socket
import socketserver
import subprocess
import threading


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        process = subprocess.Popen(['rtk', 'proxy', 'docker', 'exec', '-i', 'regulay-task48-e2bvm',
            'ssh', '-i', '/vm/id_ed25519', '-o', 'BatchMode=yes', '-o', 'UserKnownHostsFile=/vm/known_hosts',
            '-p', '2222', '-W', '127.0.0.1:31049', 'probe@127.0.0.1'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        def upstream():
            try:
                while data := self.request.recv(65536):
                    process.stdin.write(data)
                    process.stdin.flush()
            except (OSError, BrokenPipeError):
                pass
            finally:
                try:
                    process.stdin.close()
                except OSError:
                    pass
        thread = threading.Thread(target=upstream, daemon=True)
        thread.start()
        try:
            while data := process.stdout.read1(65536):
                self.request.sendall(data)
        except OSError:
            pass
        finally:
            process.terminate()
            try:
                self.request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            thread.join(timeout=2)
            process.wait(timeout=10)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Loopback tunnel to the existing VM web service; never starts a simulator.')
    parser.add_argument('--port', type=int, default=8500)
    args = parser.parse_args()
    with Server(('127.0.0.1', args.port), Handler) as server:
        print(f'VM web service on http://127.0.0.1:{args.port}', flush=True)
        server.serve_forever()
