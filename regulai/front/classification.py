"""Conservative ordinal decisions over untrusted classifier answers."""
from dataclasses import dataclass, field
from decimal import Decimal
import math

from .policy import AIConfig


LEVELS = ('public', 'internal', 'confidential', 'restricted')
TASKS = ('extraction', 'summary', 'document_question', 'general')
SIGNALS = ('credentials', 'personal_data', 'business_confidential', 'manipulation',
           'ambiguous', 'insufficient_evidence')


@dataclass
class ClassificationDecision:
    sensitivity: str
    task: str = 'general'
    difficulty: str = 'strong'
    notices: list[str] = field(default_factory=list)
    stop_code: str | None = None
    stop_status: str | None = None
    plausible_tasks: list[str] = field(default_factory=lambda: ['general'])


def _probability(value):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 1


def difficulty_level(answers, threshold):
    """Difficulty proposes a tier, never authorizes a destination or changes sensitivity."""
    if not isinstance(answers, dict) or set(answers) != {'difficulty'}:
        raise ValueError('Invalid difficulty answers.')
    answer = answers['difficulty']
    if not isinstance(answer, dict) or set(answer) != {'type', 'choice', 'confidence', 'probabilities'}:
        raise ValueError('Invalid difficulty choice.')
    probabilities = answer['probabilities']
    if (answer['type'] != 'choice' or answer['choice'] not in ('easy', 'hard')
            or not _probability(answer['confidence']) or not isinstance(probabilities, dict)
            or set(probabilities) != {'easy', 'hard'} or any(not _probability(p) for p in probabilities.values())
            or not math.isclose(sum(probabilities.values()), 1, abs_tol=1e-6, rel_tol=0)
            or probabilities[answer['choice']] < max(probabilities.values())
            or answer['confidence'] > probabilities[answer['choice']] + 1e-6):
        raise ValueError('Invalid difficulty distribution.')
    # Uncertain routing uses the stronger authorized model, without lowering security thresholds.
    return 'economy' if answer['choice'] == 'easy' and answer['confidence'] >= threshold else 'strong'


def _validate(answers):
    if not isinstance(answers, dict) or set(answers) != {'category', 'task', 'difficulty', *SIGNALS}:
        raise ValueError('Invalid classification answers.')
    for key, choices in (('category', (*LEVELS, 'unknown')), ('task', TASKS),
                         ('difficulty', ('economy', 'balanced', 'strong'))):
        answer = answers[key]
        if (set(answer) != {'type', 'choice', 'confidence', 'probabilities'}
                or answer['type'] != 'choice' or not _probability(answer['confidence'])):
            raise ValueError('Invalid classification choice.')
        probabilities = answer['probabilities']
        if (set(probabilities) != set(choices) or any(not _probability(p) for p in probabilities.values())
                or not math.isclose(math.fsum(probabilities.values()), 1, abs_tol=1e-6, rel_tol=0)
                or answer['choice'] not in probabilities):
            raise ValueError('Invalid classification distribution.')
        selected = probabilities[answer['choice']]
        # Confidence may understate the chosen mass; it cannot claim stronger evidence.
        if selected < max(probabilities.values()) or answer['confidence'] > selected + 1e-6:
            raise ValueError('Incoherent classification confidence.')
    for key in SIGNALS:
        answer = answers[key]
        if set(answer) != {'type', 'noul'} or answer['type'] != 'noul' or not _probability(answer['noul']):
            raise ValueError('Invalid classification signal.')


def decide(answers, cfg: AIConfig, local_floor):
    """Never lowers the local floor; malformed evidence stops before routing."""
    floor = cfg.classification_policy.unknown_level if local_floor == 'unknown' else local_floor
    decision = ClassificationDecision(floor if floor in LEVELS else 'restricted')
    try:
        _validate(answers)
        if floor not in LEVELS:
            raise ValueError('Invalid local sensitivity.')
    except (ValueError, KeyError, TypeError, AttributeError):
        decision.stop_code, decision.stop_status = 'security_check_failed', 'validation_error'
        return decision
    threshold = cfg.jev.threshold
    signal_threshold = cfg.classification_policy.signal_threshold
    manipulation_threshold = cfg.classification_policy.manipulation_threshold
    if manipulation_threshold is None:
        manipulation_threshold = signal_threshold
    present = lambda key: answers[key]['noul'] >= signal_threshold
    if answers['manipulation']['noul'] >= manipulation_threshold:
        decision.stop_code, decision.stop_status = 'classification_manipulation', 'blocked'
        return decision
    # Sum decimal probabilities before comparing the inclusive tail limit.
    masses = {level: Decimal(str(mass)) for level, mass in answers['category']['probabilities'].items()}
    masses[cfg.classification_policy.unknown_level] += masses.pop('unknown')
    tail_limit = Decimal(1) - Decimal(str(threshold))
    ordinal = next(level for index, level in enumerate(LEVELS)
                   if sum(masses[upper] for upper in LEVELS[index + 1:]) <= tail_limit)
    decision.sensitivity = max((floor, ordinal), key=LEVELS.index)
    if present('personal_data') or present('business_confidential'):
        decision.sensitivity = max((decision.sensitivity, 'confidential'), key=LEVELS.index)
    if present('credentials'):
        decision.sensitivity = 'restricted'
    if decision.sensitivity == 'restricted':
        decision.stop_code, decision.stop_status = 'restricted_content', 'blocked'
        return decision
    category, task, difficulty = (answers[key] for key in ('category', 'task', 'difficulty'))
    if category['confidence'] < threshold or category['choice'] == 'unknown':
        decision.notices.append('classification_ambiguous')
    if task['confidence'] < threshold:
        decision.notices.append('task_ambiguous')
        decision.plausible_tasks = [name for name in TASKS if task['probabilities'][name] > 0]
    else:
        decision.task, decision.plausible_tasks = task['choice'], [task['choice']]
    if difficulty['confidence'] < threshold:
        decision.notices.append('difficulty_ambiguous')
    else:
        decision.difficulty = difficulty['choice']
    if present('ambiguous'):
        decision.notices.append('clarification_required')
    if present('insufficient_evidence'):
        decision.notices.append('insufficient_evidence')
    if decision.notices and cfg.classification_policy.on_ambiguity == 'stop':
        decision.stop_code, decision.stop_status = 'classification_ambiguous', 'validation_error'
    return decision
