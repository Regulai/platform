"""Sandbox-side Playwright driver. Browser requests are data for Regulay's broker."""
import base64
import json
from pathlib import Path
import sys
import time

from playwright.sync_api import sync_playwright


def main():
    job = json.loads(base64.b64decode(sys.argv[1]))
    inbox = Path('/tmp/regulay-browser-' + job['nonce'])
    inbox.mkdir(mode=0o700)
    limit = time.monotonic() + job['seconds']
    with sync_playwright() as p:
        print('browser:launch', file=sys.stderr, flush=True)
        browser = p.chromium.launch(executable_path='/skills/browser_chromium.sh', headless=True, timeout=job['seconds'] * 1000,
            args=['--disable-background-networking', '--disable-component-update', '--disable-sync',
                '--disable-extensions', '--no-first-run', '--disable-features=WebRtcHideLocalIpsWithMdns'])
        context = browser.new_context(service_workers='block', accept_downloads=False, java_script_enabled=True)
        print('browser:context_ready', file=sys.stderr, flush=True)
        count, limitations = 0, []
        def route(request):
            nonlocal count
            if request.request.method != 'GET' or not request.request.url.startswith(('http://', 'https://')) or count >= 50:
                limitations.append('blocked_method_protocol_or_resource_limit')
                request.abort()
                return
            identity = count
            count += 1
            print(json.dumps({'request_id': identity, 'url': request.request.url}), flush=True)
            response = inbox / (str(identity) + '.json')
            reply = None
            while time.monotonic() < limit:
                try:
                    reply = json.loads(response.read_text())
                    break
                except (FileNotFoundError, json.JSONDecodeError):
                    time.sleep(0.05)
            if reply is None:
                request.abort()
                limitations.append('broker_timeout')
                return
            if not reply.get('succeeded'):
                request.abort()
                limitations.append(reply.get('code', 'resource_unavailable'))
            elif reply['final_url'] != request.request.url:
                request.fulfill(status=302, headers={'location': reply['final_url']})
            else:
                request.fulfill(status=200, content_type=reply['media_type'] or 'application/octet-stream',
                    headers=reply.get('headers', {}),
                    body=base64.b64decode(reply['body']))
            print('browser:resource_settled', file=sys.stderr, flush=True)
        context.route('**/*', route)
        def websocket_unavailable(socket):
            # An intercepted route never connects upstream unless connect_to_server
            # is called. Closing synchronously inside Chromium's constructor can
            # deadlock navigation; retain no upstream connection or frames.
            limitations.append('websocket_unavailable')
        context.route_web_socket('**/*', websocket_unavailable)
        page = context.new_page()
        print('browser:page_ready', file=sys.stderr, flush=True)
        try:
            page.goto(job['url'], wait_until='networkidle', timeout=job['seconds'] * 1000)
        except Exception:
            limitations.append('navigation_partial_or_timeout')
        print('browser:navigation_done', file=sys.stderr, flush=True)
        result = {'url': page.url, 'html': page.content(), 'limitations': sorted(set(limitations))}
        print('browser:rendered', file=sys.stderr, flush=True)
        print(json.dumps({'result': result}), flush=True)
        context.close()
        browser.close()


if __name__ == '__main__':
    main()
