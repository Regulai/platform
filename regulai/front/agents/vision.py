"""Actual image references, admitted only for a public-data workspace."""
import base64
import io
import json

from PIL import Image
from front.models import AgentInput
from front.policy import digest
from .general_tools import operation, store_result
from .service import AgentDenied


def submit(token, attempt, payload):
    from .data_views import authorize_tool
    if set(payload) != {'call', 'base64'}:
        raise ValueError('Invalid image submission')
    run, context, call = authorize_tool(token, attempt, payload['call'])
    row = operation(run, call)
    if (call.name != 'inspect_image' or not context[2].vision or not context[5].supports_vision
            or not context[3].limits.provider_managed):
        raise AgentDenied('agent_vision_unavailable')
    # Required text masking cannot claim to redact arbitrary original pixels.
    if run.job.get('private_data'):
        raise AgentDenied('private_image_policy_unavailable')
    raw = base64.b64decode(payload['base64'], validate=True)
    if len(raw) > 5000000:
        raise ValueError('Image byte limit')
    with Image.open(io.BytesIO(raw)) as image:
        if image.format not in ('PNG', 'JPEG') or image.width * image.height > 16000000:
            raise ValueError('Image dimensions or format')
        mime = 'image/png' if image.format == 'PNG' else 'image/jpeg'
        image.verify()
    packed = json.dumps({'mime': mime, 'base64': payload['base64']})
    asset = AgentInput.objects.create(execution=run, kind='model_image', path='vision/' + digest(call.id),
        original=packed, digest=digest(packed))
    store_result(row, {'status': 'approved', 'image_reference': str(asset.pk), 'question': call.args['question'],
        'visual_review': 'pending_model', 'scope': 'actual_public_workspace_pixels'})
    return {'status': 'completed'}
