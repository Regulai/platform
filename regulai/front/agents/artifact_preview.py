"""Authenticated static projection; original artifact bytes are never HTML responses."""
from html import escape
from html.parser import HTMLParser
import re

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_GET

from .file_continuity import authorize_artifact
from .service import AgentDenied

MAX_PREVIEW_BYTES = 512_000
TEXT_FORMATS = {'html', 'svg', 'css', 'js', 'json', 'txt', 'md', 'csv', 'py'}
CSP = "default-src 'none'; img-src data: blob:; style-src 'unsafe-inline'; font-src 'none'; base-uri 'none'; form-action 'none'; connect-src 'none'"
ALLOWED = frozenset(('html head body title style main section article header footer nav aside div span '
    'p h1 h2 h3 h4 h5 h6 br hr strong em b i u s small sub sup blockquote pre code '
    'ul ol li dl dt dd table thead tbody tfoot tr td th caption colgroup col figure figcaption '
    'a img button details summary svg g path rect circle ellipse line polyline polygon text tspan '
    'defs lineargradient radialgradient stop clippath mask pattern symbol use').split())
DROP_CONTENT = frozenset({'script', 'iframe', 'object', 'embed', 'template', 'noscript', 'foreignobject'})
VOID = frozenset({'br', 'hr', 'img', 'col'})
ATTRS = frozenset(('class id style title lang dir role width height colspan rowspan scope span start '
    'alt viewbox xmlns d fill fill-rule stroke stroke-width stroke-linecap stroke-linejoin '
    'cx cy r rx ry x y x1 x2 y1 y2 points transform opacity fill-opacity stroke-opacity '
    'offset stop-color stop-opacity gradientunits gradienttransform clip-path preserveaspectratio '
    'font-size font-family font-weight text-anchor dominant-baseline').split())


def safe_css(value):
    # CSP is the network boundary; stripping these also avoids pointless blocked
    # fetches in ordinary authored pages. Escaped CSS cannot bypass the CSP.
    return re.sub(r'url\s*\([^)]*\)|@import[^;]*;?|expression\s*\([^)]*\)', '', value, flags=re.I)


class StaticProjection(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.dropped, self.style = [], [], False

    def handle_starttag(self, tag, attrs):
        if tag in DROP_CONTENT:
            self.dropped.append(tag)
            return
        if self.dropped or tag not in ALLOWED:
            return
        self.style = tag == 'style'
        clean = []
        for name, value in attrs:
            value = value or ''
            if name == 'src' and tag == 'img' and re.fullmatch(r'data:image/(?:png|jpeg|gif|webp);base64,[a-zA-Z0-9+/=\s]+', value):
                clean.append((name, value))
            elif name in ('href', 'xlink:href') and tag == 'use' and re.fullmatch(r'#[A-Za-z_][\w.-]*', value):
                clean.append(('href', value))
            elif name in ATTRS or name.startswith('aria-'):
                if name in ('style', 'fill', 'stroke', 'clip-path'):
                    value = safe_css(value)
                clean.append((name, value))
        attributes = ''.join(f' {name}="{escape(value, quote=True)}"' for name, value in clean)
        self.parts.append(f'<{tag}{attributes}>')

    def handle_endtag(self, tag):
        if self.dropped:
            if tag == self.dropped[-1]:
                self.dropped.pop()
            return
        if tag in ALLOWED and tag not in VOID:
            self.parts.append(f'</{tag}>')
        if tag == 'style':
            self.style = False

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, value):
        if not self.dropped:
            self.parts.append(safe_css(value).replace('<', '&lt;') if self.style else escape(value))


def static_html(source):
    parser = StaticProjection()
    parser.feed(source)
    parser.close()
    return ('<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="'
        + escape(CSP, quote=True) + '"><meta name="referrer" content="no-referrer">'
        + ''.join(parser.parts))


@login_required
@require_GET
def preview(request, artifact_id):
    try:
        if not getattr(settings, 'REGULAY_ARTIFACT_PREVIEW', False):
            raise AgentDenied('artifact_preview_disabled')
        artifact, raw = authorize_artifact(request.user, artifact_id)
        if artifact.format not in TEXT_FORMATS:
            raise AgentDenied('artifact_preview_unavailable')
        if len(raw) > MAX_PREVIEW_BYTES:
            response = JsonResponse({'error': 'artifact_preview_too_large',
                'message': 'El archivo supera el límite de vista previa. Descárgalo para abrirlo completo.'}, status=413)
        else:
            source = raw.decode('utf-8-sig')
            response = JsonResponse({'artifact_id': str(artifact.pk), 'revision': artifact.revision,
                'sha256': artifact.sha256, 'filename': artifact.filename, 'format': artifact.format,
                'size_bytes': len(raw), 'code': source,
                'html': static_html(source) if artifact.format in ('html', 'svg') else None,
                'notice': 'Vista estática aislada. El JavaScript y los recursos externos están desactivados.',
                'download_url': f'/chat/agent/artifacts/{artifact.pk}/download/'})
    except (AgentDenied, UnicodeError, ValueError):
        response = JsonResponse({'error': 'artifact_preview_unavailable',
            'message': 'La vista previa no está disponible con los permisos y la revisión actuales.'}, status=404)
    response['Cache-Control'] = 'private, no-store'
    response['X-Content-Type-Options'] = 'nosniff'
    return response
