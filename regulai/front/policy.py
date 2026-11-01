"""Local, side-effect-free policy decisions. Failure never grants egress."""
from dataclasses import asdict, dataclass, field
from hashlib import sha256
import json
from typing import Literal

from django.core.exceptions import ValidationError
from django.db.models import Q
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from decimal import Decimal, InvalidOperation
import yara

Sensitivity = Literal['public', 'internal', 'confidential', 'restricted', 'unknown']


class StrictConfig(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, allow_inf_nan=False)


class JevConfig(StrictConfig):
    transport: Literal['vercel', 'typesafe'] = 'vercel'
    model: str = 'typesafe-ai/jev'
    input_price: str | None = Field(default=None, description='USD per million input tokens.')
    output_price: str | None = Field(default=None, description='USD per million output tokens.')
    currency: Literal['USD'] = 'USD'
    price_date: str | None = None
    # A provider/account contractual ceiling, not a response-size estimate.
    max_call_cost: str | None = None
    threshold: float = Field(default=0.8, ge=0, le=1)
    rubric_version: str = 'sensitivity-v2'

    @field_validator('input_price', 'output_price', 'max_call_cost')
    @classmethod
    def money(cls, value):
        try:
            if value is not None and (not Decimal(value).is_finite() or Decimal(value) < 0):
                raise ValueError('Invalid nonnegative decimal.')
        except InvalidOperation:
            raise ValueError('Invalid nonnegative decimal.') from None
        return value

    @field_validator('input_price', 'output_price')
    @classmethod
    def per_million_price(cls, value):
        if value is not None and 0 < Decimal(value) < Decimal('0.0001'):
            raise ValueError('Configure prices per million tokens, not per token.')
        return value

    @model_validator(mode='after')
    def pinned_model(self):
        import re
        if ((self.transport == 'vercel' and self.model != 'typesafe-ai/jev')
                or (self.transport == 'typesafe' and not re.fullmatch(r'jev-\d+\.\d+\.\d+', self.model))):
            raise ValueError('Invalid Jev model for transport.')
        return self


class CandidateConfig(StrictConfig):
    company_engine_id: int = Field(gt=0)
    model_id: int = Field(gt=0)
    level: Literal['economy', 'balanced', 'strong']
    quality: dict[Literal['general', 'extraction', 'summary', 'document_question'], float]

    @field_validator('quality')
    @classmethod
    def quality_range(cls, value):
        if any(not 0 <= score <= 1 for score in value.values()):
            raise ValueError('Invalid quality.')
        return value


class RoutingConfig(StrictConfig):
    mode: Literal['manual', 'auto'] = 'manual'
    strategy: Literal['quality', 'difficulty'] = 'quality'
    allow_cross_engine_fallback: bool = False
    candidates: list[CandidateConfig] = Field(default_factory=list, max_length=64)
    min_quality: dict[Literal['economy', 'balanced', 'strong'], float] = Field(
        default_factory=lambda: {'economy': 0.0, 'balanced': 0.0, 'strong': 0.0})
    max_output_tokens: int = Field(default=1000, gt=0, le=32000)
    # Optional visible-text cap, independent of tokens spent on internal reasoning.
    # Omission preserves the existing token-derived acceptance limit.
    max_response_bytes: int | None = Field(default=None, gt=0, le=128000)

    @model_validator(mode='after')
    def difficulty_is_not_a_quality_measurement(self):
        if self.strategy == 'difficulty' and any(self.min_quality.values()):
            raise ValueError('Difficulty routing cannot replace a configured minimum quality requirement.')
        return self

    @field_validator('min_quality')
    @classmethod
    def quality_range(cls, value):
        if set(value) != {'economy', 'balanced', 'strong'} or any(not 0 <= score <= 1 for score in value.values()):
            raise ValueError('Configure all quality levels.')
        return value


class VerificationConfig(StrictConfig):
    mode: Literal['local', 'advisory', 'enforce'] = 'local'
    threshold: float = Field(default=0.8, ge=0, le=1)
    rubric_version: str = 'verification-v1'
    min_quote_chars: int = Field(default=12, ge=1, le=10000)
    min_quote_words: int = Field(default=3, ge=1, le=1000)


class LimitsConfig(StrictConfig):
    provider_managed: bool = False
    budget: str | None = None
    deadline_seconds: int = Field(default=90, ge=1, le=180)
    call_timeout_seconds: int = Field(default=30, ge=1, le=180)

    @field_validator('budget')
    @classmethod
    def money(cls, value):
        return JevConfig.money(value)

    @model_validator(mode='after')
    def coherent_timeout(self):
        if self.provider_managed and self.budget is not None:
            raise ValueError('A local cost ceiling requires bounded generation.')
        if self.call_timeout_seconds > self.deadline_seconds:
            if 'call_timeout_seconds' in self.model_fields_set:
                raise ValueError('Call timeout cannot exceed the request deadline.')
            self.call_timeout_seconds = self.deadline_seconds
        return self


class ClassificationPolicyConfig(StrictConfig):
    unknown_level: Literal['public', 'internal', 'confidential', 'restricted'] = 'confidential'
    signal_threshold: float = Field(default=0.2, gt=0, le=1)
    # Omission preserves existing policies; sensitivity signals keep their own limit.
    manipulation_threshold: float | None = Field(default=None, gt=0, le=1)
    on_ambiguity: Literal['warn', 'stop'] = 'warn'


class MaskingConfig(StrictConfig):
    # Masking is mandatory at every sending boundary; configuration cannot disable it.
    max_call_cost: str | None = None

    @field_validator('max_call_cost')
    @classmethod
    def money(cls, value):
        return JevConfig.money(value)


class HistoryConfig(StrictConfig):
    max_turns: int = Field(default=20, ge=0, le=1000)
    max_bytes: int = Field(default=32768, ge=0, le=1048576)


class AIConfig(StrictConfig):
    version: Literal[1] = 1
    revision: int = Field(default=1, ge=1)
    classification: Literal['local', 'required'] = 'local'
    classification_policy: ClassificationPolicyConfig = Field(default_factory=ClassificationPolicyConfig)
    masking: MaskingConfig = Field(default_factory=MaskingConfig)
    history: HistoryConfig = Field(default_factory=HistoryConfig)
    local_sensitivity: Sensitivity = 'unknown'
    allow_empty_rules: bool = False
    destinations: dict[Sensitivity, list[str]] = Field(default_factory=dict)
    jev: JevConfig = Field(default_factory=JevConfig)
    routing: RoutingConfig = Field(default_factory=RoutingConfig)
    verification: VerificationConfig = Field(default_factory=VerificationConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)

    @field_validator('destinations')
    @classmethod
    def validate_destinations(cls, value):
        import re
        if any(not re.fullmatch(r'(engine|obfuscation):[1-9][0-9]*|jev|research:[a-z][a-z0-9_-]{0,63}', item)
               for items in value.values() for item in items):
            raise ValueError('Use explicit engine/obfuscation IDs, jev or reviewed research source IDs.')
        return value

    @model_validator(mode='after')
    def bounded_masking(self):
        if (self.limits.budget is not None and self.masking.max_call_cost is None
                and any(destination.startswith('obfuscation:')
                        for items in self.destinations.values() for destination in items)):
            raise ValueError('Budgeted masking requires max_call_cost.')
        return self


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()


def validate_ai_config(value):
    if value == {}:
        return  # Unconfigured means no egress, not implicit permission.
    try:
        AIConfig.model_validate(value)
    except (ValueError, TypeError) as error:
        raise ValidationError('Invalid AI policy configuration.') from error


def validate_yara(source):
    try:
        yara.compile(source=source, includes=False)
    except Exception as error:
        raise ValidationError('Invalid YARA rule; compilation failed.') from error


@dataclass
class PolicyDecision:
    status: str
    reason_codes: list[str]
    sensitivity: str = 'unknown'
    allowed_destinations: list[str] = field(default_factory=list)
    rules: list[dict] = field(default_factory=list)
    fingerprint: str = ''

    def as_dict(self):
        return asdict(self)


def active_rules(actor):
    from .models import Rule
    company = actor.profile.company
    return list(Rule.objects.filter(
        Q(rules_group__company=company) | Q(rules_group__company__isnull=True, rules_group__user=actor),
        active=True,
    ).order_by('pk'))


def scan_rules(rules, texts):
    if not rules:
        return [], []
    compiled = yara.compile(sources={f'rule_{r.pk}': r.yara_rule for r in rules}, includes=False)
    matches, matched = [], {}
    by_namespace = {f'rule_{r.pk}': r for r in rules}
    for content_type, text in texts:
        for match in compiled.match(data=text, timeout=2):
            rule = by_namespace[match.namespace]
            if rule.applies_to not in (content_type, 'both'):
                continue
            if rule.action not in ('block', 'consent'):
                raise ValueError('Invalid rule action')
            matches.append(match)
            matched[rule.pk] = {'id': rule.pk, 'name': rule.name, 'severity': rule.severity,
                                'description': rule.description or '', 'action': rule.action}
    return matches, list(matched.values())


def evaluate_policy(actor, texts, *, config=None, destinations=(), sensitivity=None, rules=None):
    try:
        rules = active_rules(actor) if rules is None else rules
        _, matched = scan_rules(rules, texts)
    except Exception:
        return PolicyDecision('unavailable', ['security_check_failed'])
    # Local prohibitions apply even when configuration/semantic services fail.
    if any(r['action'] == 'block' for r in matched):
        return PolicyDecision('block', ['local_rule_block'], rules=matched)
    try:
        raw = actor.profile.company.ai_config if config is None else config
        if not raw:
            return PolicyDecision('unavailable', ['policy_configuration_invalid'])
        cfg = AIConfig.model_validate(raw)
        fingerprint = digest({'config': cfg.model_dump(), 'rules': [
            [r.pk, r.yara_rule, r.action, r.applies_to, r.active] for r in rules]})
        if not rules and not cfg.allow_empty_rules:
            return PolicyDecision('unavailable', ['empty_policy_not_authorized'], fingerprint=fingerprint)
        sensitivity = sensitivity or cfg.local_sensitivity
        if sensitivity not in ('public', 'internal', 'confidential', 'restricted', 'unknown'):
            raise ValueError('Invalid sensitivity')
        if sensitivity == 'unknown':
            sensitivity = cfg.classification_policy.unknown_level
        allowed = sorted(set(cfg.destinations.get(sensitivity, [])))
        result = PolicyDecision('allow', ['local_policy_allowed'], sensitivity, allowed, matched, fingerprint)
        if sensitivity == 'restricted':
            result.status, result.reason_codes = 'block', ['restricted_content']
        elif not allowed or any(dest not in allowed for dest in destinations):
            result.status, result.reason_codes = 'block', ['destination_not_allowed']
        elif matched:
            result.status, result.reason_codes = 'consent_required', ['local_rule_consent']
        return result
    except (ValueError, TypeError, AttributeError):
        return PolicyDecision('unavailable', ['policy_configuration_invalid'])
