from django import template
from django.utils.html import format_html, format_html_join

from front.chat_assets import assets

register = template.Library()


@register.simple_tag
def chat_app_assets():
    """Stylesheets, module preloads and the entry module from the Vite manifest."""
    value = assets()
    return format_html('{}{}<script type="module" src="{}"></script>',
                       format_html_join('', '<link rel="stylesheet" href="{}">', ((url,) for url in value['css'])),
                       format_html_join('', '<link rel="modulepreload" href="{}">', ((url,) for url in value['preload'])),
                       value['script'])
