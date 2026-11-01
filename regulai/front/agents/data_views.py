"""One trusted result gate. Raw arbitrary-code output never becomes model data."""
import csv
import base64
import io
import json
import re
from pathlib import PurePosixPath

from front.models import AgentArtifact, AgentInference, AgentInput, AgentToolResult
from front.policy import digest
from .aliases import alias_value
from .protocol import ToolCall, ToolResultRequest, validate_arguments
from .service import AgentDenied, authenticate


def authorize_tool(token, attempt, payload):
    call = ToolCall.model_validate(payload)
    execution, context = authenticate(token, attempt)
    if call.name not in context[2].tools:
        raise AgentDenied('tool_not_allowed')
    if call.name == 'install_packages' and (execution.job.get('skills') or {}).get('catalog'):
        raise AgentDenied('skill_package_install_not_authorized')
    validate_arguments(call)
    if context[2].professional:
        from .capabilities import execution_limits, remaining_seconds
        budget = execution_limits(execution, context[2])
        if remaining_seconds(execution, context[2]) <= 0:
            raise AgentDenied('execution_deadline')
        if call.name == 'execute' and not 1 <= call.args.get('timeout', budget['command_seconds']) <= budget['command_seconds']:
            raise AgentDenied('command_timeout_limit')
        if len(json.dumps(call.args, ensure_ascii=False).encode()) > 250000:
            raise AgentDenied('tool_argument_size_limit')
        for path in [*call.args.get('page_paths', []), *([call.args['pdf_path']] if call.args.get('pdf_path') else [])]:
            if not path.startswith(('/workspace/work/', '/workspace/output/')) or '..' in PurePosixPath(path).parts or '\\' in path:
                raise AgentDenied('tool_path_denied')
    if call.name == 'save_revision':
        from .exports import bound
        bound(execution, call.model_dump())
    issued = [c for row in AgentInference.objects.filter(execution=execution, status='completed')
              for c in row.response.get('tool_calls', [])]
    if call.model_dump() not in issued:
        raise AgentDenied('unissued_tool_call')
    if execution.job.get('request') and call.name in ('create_mock_excel', 'build_excel', 'rename_excel',
            'build_document', 'edit_document', 'export_pdf', 'build_presentation', 'edit_presentation'):
        from .request_contract import allowed_tools
        base = AgentArtifact.objects.filter(pk=execution.job.get('base')).first() if execution.job.get('base') else None
        allowed = allowed_tools(execution.job['request'], context[2].tools,
            base=bool(base), source=bool(execution.job.get('source')) and execution.job.get('kind') != 'mock',
            narrative=bool(base and base.verification.get('narrative')))
        if call.name not in allowed:
            raise AgentDenied('tool_does_not_match_request')
    if call.name == 'create_mock_excel':
        from .excel_contract import mock_source, mock_title, sha256
        raw = mock_source(call.args['rows'])
        mock_title(call.args['title'])
        if execution.job.get('kind') != 'mock':
            raise AgentDenied('artifact_reference_denied')
        if execution.job.get('source'):
            asset = AgentInput.objects.get(pk=execution.job['source'], execution=execution)
            if asset.digest != sha256(raw):
                raise AgentDenied('mock_source_immutable')
    elif call.name in ('build_excel', 'rename_excel'):
        from .excel_contract import valid_title
        valid_title(call.args['title'])
        job = execution.job
        if ((call.name == 'build_excel' and (job.get('kind') != 'build'
                or call.args['input_reference'] != job.get('source')))
                or (call.name == 'rename_excel' and (job.get('kind') != 'rename'
                or call.args['logical_id'] != job.get('logical_id')
                or call.args['base_revision'] != job.get('base')))):
            raise AgentDenied('artifact_reference_denied')
    elif call.name in ('build_presentation', 'edit_presentation'):
        from .presentation_contract import valid_text
        job = execution.job
        if call.name == 'build_presentation':
            if call.args.get('content'):
                from .report_contract import text
                text(call.args['title'], 160)
            else:
                valid_text(call.args['title'], 'title')
            valid_text(call.args['section'], 'body')
            if call.args['template'] not in ('new', 'corporate') or call.args['input_reference'] != (job.get('source') or ''):
                raise AgentDenied('artifact_reference_denied')
            if not job.get('source') and not call.args.get('content'):
                raise AgentDenied('report_content_required')
        else:
            if (not job.get('base') or call.args['logical_id'] != job.get('logical_id')
                    or call.args['base_revision'] != job['base'] or not 1 <= call.args['slide'] <= 20):
                raise AgentDenied('artifact_reference_denied')
            base = AgentArtifact.objects.get(pk=job['base'])
            if base.format != 'pptx':
                raise AgentDenied('presentation_base_required')
            if base.verification.get('narrative'):
                from .report_contract import text
                text(call.args['value'], 110 if call.args['field'] == 'title' else 2000)
            else:
                if call.args['slide'] > 3:
                    raise AgentDenied('artifact_reference_denied')
                valid_text(call.args['value'], call.args['field'])
    elif call.name in ('build_document', 'edit_document', 'export_pdf'):
        from .document_contract import valid_section
        from .excel_contract import valid_title
        job = execution.job
        if call.name == 'build_document':
            if call.args.get('content'):
                from .report_contract import text
                text(call.args['title'], 160)
            else:
                valid_title(call.args['title'])
            valid_section(call.args['section'])
            if call.args['format'] not in ('docx', 'pdf') or call.args['input_reference'] != (job.get('source') or ''):
                raise AgentDenied('artifact_reference_denied')
            if call.args['format'] not in job.get('request', {}).get('formats', ('docx', 'pdf')):
                raise AgentDenied('deliverable_format_mismatch')
            if not job.get('source') and not call.args.get('content'):
                raise AgentDenied('report_content_required')
        else:
            if (not job.get('base') or call.args['logical_id'] != job.get('logical_id')
                    or call.args['base_revision'] != job['base']):
                raise AgentDenied('artifact_reference_denied')
            base = AgentArtifact.objects.get(pk=job['base'])
            if base.format not in ('docx', 'pdf'):
                raise AgentDenied('document_base_required')
            if call.name == 'edit_document':
                if call.args['field'] not in ('title', 'section') and not (
                        base.verification.get('narrative') and re.fullmatch(r'page:[1-9]\d*:block:[1-9]\d*', call.args['field'])):
                    raise AgentDenied('document_field_denied')
                if base.verification.get('narrative'):
                    from .report_contract import text
                    text(call.args['value'], 160 if call.args['field'] == 'title' else 2000)
                else:
                    (valid_title if call.args['field'] == 'title' else valid_section)(call.args['value'])
    for key in ('input_path', 'file_path', 'path'):
        if key not in call.args:
            continue
        if call.args[key] == '/skills' or call.args[key].startswith('/skills/'):
            from .skill_context import authorize_path
            authorize_path(execution, call)
            continue
        if (call.name == 'read_file' and not context[2].professional
                and execution.prompt.conversation and execution.prompt.conversation.mode == 'agent'):
            raise AgentDenied('tool_path_denied')
        path = PurePosixPath(call.args[key])
        if not path.is_absolute() or '..' in path.parts or not (str(path) + '/').startswith('/workspace/') or '\\' in call.args[key]:
            raise AgentDenied('tool_path_denied')
        if call.name in ('write_file', 'edit_file', 'replace_file', 'web_download') and not str(path).startswith(('/workspace/work/', '/workspace/output/')):
            raise AgentDenied('tool_path_denied')
    return execution, context, call


def grant_csv(execution, *, path, content):
    """Trusted application grant; no executor-facing upload/originals endpoint."""
    if not path.startswith('/workspace/input/') or '..' in PurePosixPath(path).parts:
        raise AgentDenied('invalid_input_path')
    if not isinstance(content, str) or len(content.encode()) > 512_000:
        raise AgentDenied('invalid_input')
    return AgentInput.objects.create(execution=execution, kind='csv', path=path,
        original=content, digest=digest(content))


def render_approved_view(execution, result):
    """Trusted vision input derived only from an already approved result view.

    Raw table renders and user previews are deliberately not accepted here.
    Later document work must supply its own reviewed projection before rendering.
    """
    from PIL import Image, ImageDraw
    result = AgentToolResult.objects.get(pk=result.pk, execution=execution)
    if result.view.get('status') != 'approved':
        raise AgentDenied('unapproved_model_image')
    lines = json.dumps(result.view, sort_keys=True, indent=2, ensure_ascii=True).splitlines()
    if len(lines) > 80 or any(len(line) > 180 for line in lines):
        raise AgentDenied('model_image_too_large')
    image = Image.new('RGB', (1200, max(40, len(lines) * 16 + 20)), 'white')
    draw = ImageDraw.Draw(image)
    for index, line in enumerate(lines):
        draw.text((10, 10 + index * 16), line, fill='black')
    output = io.BytesIO()
    image.save(output, format='PNG')
    content = json.dumps({'mime': 'image/png', 'base64': base64.b64encode(output.getvalue()).decode()})
    row, _ = AgentInput.objects.get_or_create(execution=execution, kind='model_image',
        path=f'approved-view-{result.pk}', defaults={'original': content, 'digest': digest(content)})
    return row


def _csv_view(execution, agent, call, raw):
    asset = AgentInput.objects.filter(execution=execution, kind='csv', path=call.args['input_path']).first()
    if not asset or not asset.original or digest(asset.original) != asset.digest:
        raise AgentDenied('input_unavailable')
    reader = csv.DictReader(io.StringIO(asset.original))
    rows = list(reader)
    # The query and grouping are fixed. The model cannot choose individuals or
    # use repeated predicates to extract values via differences between totals.
    if len(rows) < agent.min_group_size:
        return {'status': 'withheld', 'code': 'aggregate_group_too_small'}
    if call.name == 'inspect_csv':
        return {'status': 'approved', 'reference': str(asset.pk), 'rows': len(rows),
            'columns': [{'reference': alias_value(execution, 'FIELD', name),
                         'type': 'integer' if name == 'amount_cents' else 'string'} for name in reader.fieldnames],
            'synthetic_example': {'amount_cents': 100, 'item': 'example'}}
    expected = {'rows': len(rows), 'total_cents': sum(int(row['amount_cents']) for row in rows)}
    # ToolMessage, Command, stdout, stderr, artifact and error are all archived,
    # but only the exact reviewed tool's content is eligible for verification.
    try:
        candidate = json.loads(raw['content'])
    except (ValueError, TypeError, KeyError):
        return {'status': 'withheld', 'code': 'aggregate_not_verified'}
    if (type(candidate) is not dict or set(candidate) != set(expected)
            or any(type(candidate[k]) is not int or candidate[k] != expected[k] for k in expected)):
        return {'status': 'withheld', 'code': 'aggregate_not_verified'}
    return {'status': 'approved', **expected}


def tool_result(token, attempt, payload):
    request = ToolResultRequest.model_validate(payload)
    execution, context, call = authorize_tool(token, attempt, request.call.model_dump())
    path = call.args.get('file_path', call.args.get('path', ''))
    if path == '/skills' or path.startswith('/skills/'):
        from .skill_context import finish_tool
        return finish_tool(execution, context, call, request)
    fingerprint = digest(request.model_dump())
    previous = AgentToolResult.objects.filter(execution=execution, call_id=call.id).first()
    if previous:
        if previous.request_digest != fingerprint:
            raise AgentDenied('tool_result_id_conflict')
        from .general_tools import result_view
        return result_view(previous)
    if context[2].professional:
        from .general_tools import finish
        return finish(execution, context, call, request)
    # Fixed views are intentionally unable to encode arbitrary output. Do not
    # replace this with a regex or a model-generated "safe summary" of raw logs.
    view = {'status': 'withheld', 'code': 'raw_tool_output_withheld'}
    if request.failed:
        view = {'status': 'withheld', 'code': 'tool_failed'}
    elif call.name in ('csv_totals', 'inspect_csv'):
        try:
            view = _csv_view(execution, context[2], call, request.raw)
        except (ValueError, TypeError, KeyError, csv.Error):
            view = {'status': 'withheld', 'code': 'aggregate_not_verified'}
    elif call.name == 'save_revision':
        from front.models import AgentExport
        row = AgentExport.objects.filter(execution=execution).first()
        view = ({'status': 'approved', 'reference': str(row.pk), 'sha256': row.artifact.sha256}
            if row and row.call == call.model_dump() and row.status == 'completed'
            else {'status': 'withheld', 'code': 'export_not_confirmed'})
    elif call.name == 'research_sources':
        from .research import approved_view
        view = approved_view(execution, call, request.raw)
    elif call.name in ('create_mock_excel', 'build_excel', 'rename_excel', 'build_document', 'edit_document', 'export_pdf', 'build_presentation', 'edit_presentation'):
        # The executor returns an opaque candidate reference. Approval and the
        # aggregate come only from the independent application verifier.
        try:
            reference = json.loads(request.raw['content'])['reference']
            artifact = AgentArtifact.objects.get(pk=reference, execution=execution, verification__call_id=call.id)
            from .jobs import _bytes
            _bytes(artifact)
            if artifact.status != 'verified':
                view = {'status': 'withheld', 'code': 'visual_review_required' if artifact.verification.get('automated_passed') else 'document_not_verified'}
            else:
                view = {'status': 'approved', 'reference': str(artifact.pk),
                'logical_id': str(artifact.logical_id), 'revision': artifact.revision, 'format': artifact.format,
                **{key: artifact.verification[key] for key in ('rows', 'total_cents', 'pages') if key in artifact.verification}}
        except (ValueError, TypeError, KeyError, AgentArtifact.DoesNotExist):
            view = {'status': 'withheld', 'code': 'excel_not_verified'}
    authenticate(token, attempt)
    record, created = AgentToolResult.objects.get_or_create(execution=execution, call_id=call.id,
        defaults={'request_digest': fingerprint, 'view': view,
                  'raw': json.dumps(request.raw, ensure_ascii=False, allow_nan=False)})
    if not created and record.request_digest != fingerprint:
        raise AgentDenied('tool_result_id_conflict')
    return record.view
