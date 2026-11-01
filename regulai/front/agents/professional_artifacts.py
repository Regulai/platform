"""Format-independent delivery with separate integrity, layout and factual checks."""
import base64
import io
import json
from pathlib import PurePosixPath
import re
import uuid
import zipfile
import xml.etree.ElementTree as ET

from PIL import Image
from pypdf import PdfReader

from front.models import AgentArtifact, AgentInput, AgentInference
from .capabilities import execution_limits
from .excel_contract import sha256
from .general_tools import operation, store_result
from .service import AgentDenied

from .artifact_formats import MIMES, canonical, inspect_file, safe_filename
UNSAFE_FORMULA = re.compile(r'(?i)\b(WEBSERVICE|RTD|DDE|CALL|REGISTER\.ID|EXEC|HYPERLINK)\s*\(|\|[^!]*!|\[[^]]+\].*!')


def office_parts(raw):
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        items = archive.infolist()
        if (len(items) > 2000 or len(set(x.filename for x in items)) != len(items)
                or sum(x.file_size for x in items) > 64 * 1024 * 1024
                or any(x.flag_bits & 1 or x.filename.startswith('/') or '..' in x.filename.split('/')
                    or x.file_size > max(1, x.compress_size) * 200 for x in items)):
            raise ValueError('office_archive_limit')
        parts = {x.filename: archive.read(x) for x in items}
    for name, data in parts.items():
        if any(token in name.lower() for token in ('vbaproject', 'activex', 'embeddings/', 'externallinks/',
                'connections.xml', 'macrosheets/', 'dialogsheets/')):
            raise ValueError('office_active_content')
        if name.endswith(('.xml', '.rels')):
            if b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
                raise ValueError('office_xml_entities')
            root = ET.fromstring(data)
            for node in root.iter():
                if name.startswith('xl/') and node.tag.rsplit('}', 1)[-1] in ('f', 'definedName') and UNSAFE_FORMULA.search(node.text or ''):
                    raise ValueError('office_active_formula')
                if node.get('TargetMode', '').lower() == 'external':
                    from .public_web import public_url
                    if not node.get('Type', '').endswith('/hyperlink'):
                        raise ValueError('office_external_content')
                    public_url(node.get('Target', ''))
                if node.tag.endswith(('}instrText', '}fldSimple')):
                    field = node.get('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}instr', node.text or '').strip()
                    if field.split(' ', 1)[0] not in ('PAGE', 'NUMPAGES', 'TOC', 'REF', 'PAGEREF', ''):
                        raise ValueError('office_active_field')
    return parts


def pdf_info(raw):
    reader = PdfReader(io.BytesIO(raw), strict=True)
    if reader.is_encrypted or not 1 <= len(reader.pages) <= 200:
        raise ValueError('pdf_pages_or_encryption')
    # Traverse reachable objects to reject scripts/actions/embedded executables,
    # including annotations; ordinary public reference links are permitted.
    seen = set()
    def inspect(value, depth=0):
        if depth > 80 or len(seen) > 100000:
            raise ValueError('pdf_object_limit')
        value = value.get_object() if hasattr(value, 'get_object') else value
        key = id(value)
        if key in seen:
            return
        seen.add(key)
        if isinstance(value, dict):
            if any(k in value for k in ('/JS', '/JavaScript', '/Launch', '/EmbeddedFiles', '/RichMedia', '/AA', '/XFA')):
                raise ValueError('pdf_active_content')
            if '/S' in value and str(value['/S']) in ('/Launch', '/JavaScript', '/SubmitForm', '/ImportData', '/GoToR'):
                raise ValueError('pdf_external_action')
            if '/URI' in value:
                from .public_web import public_url
                public_url(str(value['/URI']))
            for item in value.values():
                inspect(item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                inspect(item, depth + 1)
    inspect(reader.trailer['/Root'])
    texts = [page.extract_text() or '' for page in reader.pages]
    return {'pages': len(texts), 'text': '\n'.join(texts), 'blank_pages': [i + 1 for i, text in enumerate(texts) if not text.strip()]}


def _worksheet_extent(xml):
    """Bound the actual cells even when a streaming writer omits dimension."""
    from openpyxl.utils.cell import coordinate_to_tuple
    root = ET.fromstring(xml)
    data = root.find('{*}sheetData')
    max_row = max_column = row_number = 0
    for row in data if data is not None else ():
        if row.tag.rsplit('}', 1)[-1] != 'row':
            continue
        row_number = int(row.get('r', row_number + 1))
        if not 1 <= row_number <= 100000:
            raise ValueError('workbook_cell_limit')
        max_row = max(max_row, row_number)
        column_number = 0
        for cell in row:
            if cell.tag.rsplit('}', 1)[-1] != 'c':
                continue
            if cell.get('r'):
                cell_row, column_number = coordinate_to_tuple(cell.attrib['r'])
            else:
                cell_row, column_number = row_number, column_number + 1
            if cell_row < 1 or column_number < 1:
                raise ValueError('workbook_cell_limit')
            max_row, max_column = max(max_row, cell_row), max(max_column, column_number)
            if max_row * max_column > 100000:
                raise ValueError('workbook_cell_limit')
    return max(1, max_row), max(1, max_column)


def _inspect_legacy_file(raw, kind):
    proof = {'format': kind, 'sha256': sha256(raw), 'bytes': len(raw)}
    text, preview = '', {}
    if kind in ('docx', 'xlsx', 'pptx'):
        parts = office_parts(raw)
        proof['part_hashes'] = {name: sha256(data) for name, data in parts.items()}
        if kind == 'docx':
            from docx import Document
            document = Document(io.BytesIO(raw))
            text = '\n'.join([p.text for p in document.paragraphs] + [
                ' | '.join(cell.text for cell in row.cells) for table in document.tables for row in table.rows])
            preview['paragraphs'] = len(document.paragraphs)
        elif kind == 'xlsx':
            from openpyxl import load_workbook
            book = load_workbook(io.BytesIO(raw), data_only=False, read_only=True, keep_links=False)
            sheets, texts, cells = [], [], 0
            try:
                extents, total_cells = [], 0
                for sheet in book:
                    # Inspect already validated XML before any row padding. Also
                    # avoid trusting a stale/understated dimension to hide data.
                    xml_row, xml_column = _worksheet_extent(parts[sheet._worksheet_path.lstrip('/')])
                    max_row = max(xml_row, sheet.max_row or 1)
                    max_column = max(xml_column, sheet.max_column or 1)
                    total_cells += max_row * max_column
                    if max_row * max_column > 100000 or total_cells > 200000:
                        raise ValueError('workbook_cell_limit')
                    extents.append((sheet, max_row, max_column))
                for sheet, max_row, max_column in extents:
                    rows = []
                    for row in sheet.iter_rows(max_row=max_row, max_col=max_column):
                        values = []
                        for cell in row:
                            value = cell.value
                            if cell.data_type == 'e' or cell.data_type == 'f' and (UNSAFE_FORMULA.search(value) or '#REF!' in value):
                                raise ValueError('workbook_formula_error_or_external')
                            values.append(str(value) if value is not None else '')
                            cells += 1
                            if cells > 200000:
                                raise ValueError('workbook_cell_limit')
                        if len(rows) < 10:
                            rows.append(values[:20])
                        texts.append(' | '.join(values))
                    sheets.append({'name': sheet.title, 'rows': max_row, 'columns': max_column, 'preview': rows})
                if cells > 200000:
                    raise ValueError('workbook_cell_limit')
                preview.update(sheet_count=len(sheets), sheets=sheets)
                text = '\n'.join(texts)
                proof['formulas'] = 'syntax_and_error_cells_checked; recalculation_requires_runtime'
            finally:
                book.close()
        else:
            from pptx import Presentation
            presentation = Presentation(io.BytesIO(raw))
            texts, overflow = [], []
            for index, slide in enumerate(presentation.slides, 1):
                for shape in slide.shapes:
                    if shape.left < 0 or shape.top < 0 or shape.left + shape.width > presentation.slide_width or shape.top + shape.height > presentation.slide_height:
                        overflow.append(index)
                    if shape.has_text_frame:
                        texts.append(shape.text)
            if overflow:
                raise ValueError('presentation_shapes_outside_canvas')
            proof['slides'] = len(presentation.slides)
            text = '\n'.join(texts)
    elif kind == 'pdf':
        info = pdf_info(raw)
        text = info.pop('text')
        proof.update(info)
    elif kind in ('png', 'jpg', 'jpeg'):
        with Image.open(io.BytesIO(raw)) as image:
            if image.width * image.height > 25000000 or image.format not in ('PNG', 'JPEG'):
                raise ValueError('image_limit')
            image.verify()
            proof.update(width=image.width, height=image.height)
    elif kind in MIMES:
        text = raw.decode('utf-8-sig')
        if kind == 'json':
            json.loads(text)
    else:
        raise ValueError('artifact_format_unsupported')
    return proof, text, preview


def candidate(token, attempt, payload):
    from .data_views import authorize_tool
    from . import jobs
    from .web_tools import consulted_sources
    if set(payload) not in ({'call', 'files'}, {'call', 'files', 'render'}) or not isinstance(payload['files'], dict):
        raise ValueError('Invalid artifact submission')
    run, context, call = authorize_tool(token, attempt, payload['call'])
    row = operation(run, call)
    if call.name != 'publish_artifact':
        raise AgentDenied('candidate_denied')
    from front.policy import digest
    publication_digest = digest({'files': payload['files'], 'render': payload.get('render')})
    if row.result:
        previous_result = json.loads(row.result)
        if previous_result.get('reference'):
            if previous_result.get('publication_digest') != publication_digest:
                raise AgentDenied('artifact_publication_conflict')
            return {'status': 'completed', 'reference': previous_result['reference']}
    previous = AgentArtifact.objects.filter(execution=run, operation_id=uuid.uuid5(run.pk, call.id)).first()
    if previous:
        if previous.verification.get('publication_digest') != publication_digest:
            raise AgentDenied('artifact_publication_conflict')
        return {'status': 'completed', 'reference': str(previous.pk)}
    args, budget = dict(call.args), execution_limits(run, context[2])
    if 'render' in payload:
        rendering = payload['render']
        if (set(rendering) != {'pdf_path', 'page_paths', 'source_sha256', 'engine', 'pages'}
                or rendering['engine'] != 'libreoffice-poppler'):
            raise ValueError('Invalid trusted rendering')
        args.update(pdf_path=rendering['pdf_path'], page_paths=rendering['page_paths'])
    related_paths = args.get('related_paths', [])
    if len(related_paths) > 31 or len(set(related_paths)) != len(related_paths):
        raise ValueError('artifact_dependency_limit')
    expected = {args['file_path'], *args.get('page_paths', []), *related_paths}
    if args.get('pdf_path'):
        expected.add(args['pdf_path'])
    if set(payload['files']) != expected or len(expected) > budget['pdf_pages'] + 33:
        raise ValueError('Artifact file set mismatch')
    decoded = {path: base64.b64decode(value, validate=True) for path, value in payload['files'].items()}
    if sum(len(value) for value in decoded.values()) > budget['file_bytes']:
        raise ValueError('Artifact size limit')
    raw = decoded[args['file_path']]
    if 'render' in payload and sha256(raw) != payload['render']['source_sha256']:
        raise ValueError('Rendered source digest mismatch')
    kind = canonical(PurePosixPath(args['file_path']).suffix)
    proof, text, preview = inspect_file(raw, kind, budget=budget)
    if proof['coverage']['status'] != 'complete' and kind not in ('png', 'jpg'):
        raise AgentDenied('artifact_policy_coverage_incomplete')
    sources = consulted_sources(run)
    if set(args.get('sources', [])) - set(sources):
        raise AgentDenied('artifact_source_not_opened')
    if args.get('synthetic') and not run.job['request']['allow_mock']:
        raise AgentDenied('invented_data_not_requested')
    # Policy sees all extracted artifact text before delivery. Images never feed
    # a model implicitly; the separate vision gate applies its own data policy.
    from front.policy import evaluate_policy
    if evaluate_policy(context[0], context[8] + [('files', text)], destinations=context[7]).status != 'allow':
        raise AgentDenied('artifact_policy_denied')
    render = {}
    if kind in ('docx', 'pptx', 'pdf'):
        pdf = raw if kind == 'pdf' else decoded.get(args.get('pdf_path'))
        if not pdf:
            raise ValueError('artifact_rendered_pdf_required')
        info = pdf_info(pdf)
        if info['blank_pages']:
            raise ValueError('artifact_blank_pages')
        if kind == 'pptx' and info['pages'] != proof['slides']:
            raise ValueError('artifact_slide_render_mismatch')
        # Text coherence is a separate check from visual inspection. Compare
        # normalized word coverage; do not label it a semantic/visual judgment.
        words = set(re.findall(r'\w+', text.casefold()))
        rendered = set(re.findall(r'\w+', info['text'].casefold()))
        if words and len(words - rendered) / len(words) > 0.05:
            raise ValueError('artifact_render_text_mismatch')
        paths = args.get('page_paths', [])
        if len(paths) != info['pages']:
            raise ValueError('artifact_page_images_required')
        for n, path in enumerate(paths, 1):
            inspect_file(decoded[path], 'png')
            render[f'page-{n}.png'] = base64.b64encode(decoded[path]).decode()
        proof.update(pages=info['pages'], pdf_sha256=sha256(pdf),
            page_sha256=[sha256(decoded[path]) for path in paths], text_coherence='word_coverage_checked')
        render['final.pdf'] = base64.b64encode(pdf).decode()
        if kind == 'docx':
            proof['docx_sha256'] = sha256(raw)
            render['final.docx'] = base64.b64encode(raw).decode()
    reviewed = {}
    for inference in AgentInference.objects.filter(execution=run, status='completed'):
        for image_hash in inference.response.get('image_sha256', []):
            reviewed[image_hash] = str(inference.call_id)
    proof['visual_inferences'] = {key: reviewed[key] for key in proof.get('page_sha256', []) if key in reviewed}
    base = None
    if args.get('base_revision'):
        if args['base_revision'] != run.job.get('base'):
            raise AgentDenied('artifact_revision_stale')
        base = jobs._base(run.conversation, run.job['logical_id'], run.job['base'])
        if base.format != kind:
            raise AgentDenied('artifact_edit_format_mismatch')
        old = base.verification.get('part_hashes', {})
        proof['changed_parts'] = sorted(name for name in old.keys() | proof.get('part_hashes', {}).keys()
            if old.get(name) != proof.get('part_hashes', {}).get(name))
        proof['preservation_review'] = 'changed_parts_recorded; semantic_scope_not_automatically_verified'
    elif run.job.get('base') and run.job['request']['operation'] == 'edit':
        raise AgentDenied('artifact_base_revision_required')
    with jobs.locked(token, attempt) as (run, _):
        if base:
            jobs._base(run.conversation, run.job['logical_id'], run.job['base'])
        from .file_continuity import publication_files, persist_revision, write_manifest
        dependencies = publication_files(run, context, decoded, args['file_path'], related_paths)
        proof.update(contract='professional-v2', purpose='deliverable', title=args['title'][:200], automated_passed=True,
            publication_digest=publication_digest,
            call_id=call.id, source_ids=args.get('sources', []), preview=preview,
            data_origin='invented_sample_data' if args.get('synthetic') or run.job['request']['allow_mock'] else 'task_inputs_and_research',
            human_review_required=budget['human_review'],
            visual_automatic='reviewed' if proof.get('page_sha256') and all(key in reviewed for key in proof['page_sha256']) else 'not_performed',
            factual='not_performed')
        artifact = persist_revision(run, args['file_path'], raw, proof, base=base,
            operation_id=uuid.uuid5(run.pk, call.id), purpose='deliverable',
            status='draft' if budget['human_review'] and proof.get('pages') else 'verified', render=render)
        write_manifest(run, [(artifact, args['file_path'], dependencies)] + [(item, path, []) for item, path in dependencies])
        published = run.job.setdefault('published_artifacts', [])
        if str(artifact.pk) not in published:
            published.append(str(artifact.pk))
            run.save(update_fields=['job'])
        jobs.event(run, 'visual_pending' if artifact.status == 'draft' else 'verified', reference=str(artifact.pk))
        result = {'status': 'approved', 'reference': str(artifact.pk), 'sha256': artifact.sha256,
            'publication_digest': publication_digest,
            'revision': artifact.revision, 'format': kind, 'pages': proof.get('pages'),
            'preview_paths': args.get('page_paths', []),
            'checks': checks(artifact), 'human_review_required': artifact.status == 'draft'}
        store_result(row, result)
        return {'status': 'completed', 'reference': str(artifact.pk)}


def record_visual_receipts(run):
    """Attach actual pixel-dispatch receipts, without claiming a passing judgment."""
    seen = {}
    for inference in AgentInference.objects.filter(execution=run, status='completed'):
        for value in inference.response.get('image_sha256', []):
            seen[value] = str(inference.call_id)
    for artifact in run.artifacts.filter(verification__contract__in=('professional-v1', 'professional-v2')):
        hashes = artifact.verification.get('page_sha256', [])
        if not hashes:
            continue
        artifact.verification['visual_inferences'] = {key: seen[key] for key in hashes if key in seen}
        artifact.verification['visual_automatic'] = 'reviewed' if all(key in seen for key in hashes) else 'not_performed'
        artifact.save(update_fields=['verification'])


def current_artifacts(run):
    """Keep revision history, but only deliver/review each file's latest bytes."""
    latest = {}
    from django.db.models import Q
    for artifact in AgentArtifact.objects.filter(Q(execution=run) | Q(pk__in=run.job.get('published_artifacts', []))).order_by('revision'):
        if artifact.verification.get('purpose', 'deliverable') != 'deliverable':
            continue
        latest[artifact.logical_id] = artifact
    return list(latest.values())


def checks(artifact):
    proof = artifact.verification
    return {'integrity': {'status': 'passed', 'detail': 'Reapertura, hashes y estructura del archivo comprobados.'},
        'instructions': {'status': 'not_performed', 'detail': 'Formato y páginas se comprueban al entregar; contenido semántico sin garantía.'},
        'layout': {'status': 'passed' if proof.get('visual_review') else proof.get('visual_automatic', 'not_performed'),
            'detail': 'Revisión humana registrada.' if proof.get('visual_review') else
                'Todas las imágenes exactas se enviaron al modelo visual; consulta su evaluación en la respuesta.' if proof.get('visual_automatic') == 'reviewed' else
                'Sin revisión visual registrada. Las comprobaciones de estructura no garantizan la maquetación.'},
        'sources': {'status': 'not_performed', 'detail': 'Procedencia y lecturas registradas; respaldo de cada afirmación no verificado automáticamente.'},
        'security': {'status': 'passed' if proof.get('coverage', {}).get('status', 'complete') == 'complete' else 'partial',
            'detail': 'Permisos, política y estructura comprobados con la cobertura indicada. No acredita OCR ni seguridad al ejecutar código.'},
        'coverage': proof.get('coverage', {'status': 'legacy', 'scope': 'historical_reader'})}


def artifact_data(artifact):
    from .jobs import _bytes
    _bytes(artifact)
    proof = artifact.verification
    count = proof.get('pages', 0)
    result = {'id': str(artifact.pk), 'logical_id': str(artifact.logical_id), 'revision': artifact.revision,
        'filename': artifact.filename or safe_filename('archivo', artifact.format), 'size_bytes': artifact.size_bytes if artifact.size_bytes is not None else len(_bytes(artifact)),
        'sha256': artifact.sha256, 'format': artifact.format, 'status': artifact.status,
        'verification_checks': checks(artifact), 'preview': {'title': proof.get('title', ''),
            **proof.get('preview', {}), 'page_count': count,
            'pages': [f'/chat/agent/artifacts/{artifact.pk}/pages/{n}/' for n in range(1, count + 1)]},
        'download_url': f'/chat/agent/artifacts/{artifact.pk}/download/', 'page_sha256': proof.get('page_sha256', []),
        'data_mode': 'mock' if proof.get('data_origin') == 'invented_sample_data' else 'source',
        'changed_parts': proof.get('changed_parts', [])}
    if artifact.format == 'docx' and proof.get('pdf_sha256'):
        result['downloads'] = [{'format': 'pdf', 'url': f'/chat/agent/artifacts/{artifact.pk}/download/?format=pdf'}]
    if proof.get('human_review_required'):
        from .document_jobs import VISUAL_CHECKS
        result.update(review_url=f'/chat/agent/artifacts/{artifact.pk}/review/', review_checks=VISUAL_CHECKS)
    return result
