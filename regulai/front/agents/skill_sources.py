"""Credential-free, pinned GitHub imports through the existing public HTTP broker."""
import json
import re
import time
from urllib.parse import quote, urlsplit

from front.models import Profile
from front.policy import AIConfig, evaluate_policy
from front.local_masking import detect_spans
from .public_web import fetch, public_url, WebError
from .skill_bundles import SkillError, MAX_COMPRESSED, unpack, valid_path

HOSTS = {'github.com', 'api.github.com', 'codeload.github.com', 'raw.githubusercontent.com'}


def github_bundle(actor, value, *, subpath, deadline, operation):
    try:
        url = public_url(value)
        parsed = urlsplit(url)
        parts = parsed.path.strip('/').split('/')
        if (parsed.scheme != 'https' or parsed.hostname != 'github.com' or parsed.query or parsed.fragment
                or len(parts) < 5 or parts[2] != 'tree'
                or not re.fullmatch(r'[A-Za-z0-9_.-]+', parts[0])
                or not re.fullmatch(r'[A-Za-z0-9_.-]+', parts[1]) or parts[1].endswith('.git')):
            raise SkillError('skill_github_path_required')
        owner, repo, _, ref, *folder = parts
        folder = '/'.join(folder)
        valid_path(folder)
        if subpath and subpath != folder:
            raise SkillError('skill_github_path_required')
        account = Profile.objects.select_related('company').get(user=actor)
        cfg = AIConfig.model_validate(account.company.ai_config)
        if cfg.classification != 'local':
            raise SkillError('skill_network_local_policy_required')

        def authorized(target):
            target = public_url(target)
            p = urlsplit(target)
            if p.scheme != 'https' or p.hostname not in HOSTS or p.query:
                raise SkillError('skill_download_destination_denied')
            # No remote classifiers/masks and no undisclosed API charges for installation.
            if detect_spans(target):
                raise SkillError('skill_sensitive_source_denied')
            decision = evaluate_policy(actor, [('prompts', target)], destinations=['research:packages'])
            if decision.status != 'allow':
                raise SkillError('skill_download_policy_denied')

        def get(target, limit):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SkillError('skill_download_timeout')
            authorized(target)
            result = fetch(target, max_bytes=limit, timeout=remaining, authorize=authorized)
            from .skill_installation import audit
            audit(actor, 'download', operation_id=str(operation.pk), destination=urlsplit(target).hostname,
                  bytes=result['bytes'], result='completed', cost_kind='no_api_charge')
            return result['raw']

        if re.fullmatch(r'[0-9a-f]{40}', ref):
            commit = ref
        else:
            resolved = json.loads(get(f'https://api.github.com/repos/{owner}/{repo}/commits/{quote(ref, safe="")}', 256000))
            commit = resolved.get('sha')
            if not isinstance(commit, str) or not re.fullmatch(r'[0-9a-f]{40}', commit):
                raise SkillError('skill_commit_unresolved')
        archive_url = f'https://codeload.github.com/{owner}/{repo}/zip/{commit}'
        raw = get(archive_url, MAX_COMPRESSED)
        files = unpack(raw, deadline=deadline + 5)
        roots = {p.split('/')[0] for p in files}
        if len(roots) != 1:
            raise SkillError('invalid_skill_archive')
        selected = roots.pop() + '/' + folder
        if selected + '/SKILL.md' not in files:
            raise SkillError('skill_folder_not_found')
        return raw, f'https://github.com/{owner}/{repo}/tree/{commit}/{folder}', commit, (
            f'github:{owner.casefold()}/{repo.casefold()}/{folder}'), selected
    except SkillError:
        raise
    except WebError as error:
        raise SkillError(str(error)) from None
    except (ValueError, KeyError, TypeError):
        raise SkillError('skill_source_invalid') from None
