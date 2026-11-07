"""Opt-in, model-bound inference settings; never infer support from model names."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class InferenceConfiguration(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    dialect: Literal['unknown', 'deepseek', 'openai', 'vercel_gateway'] = 'unknown'
    model_id: str = Field(default='', max_length=100)
    profiles: list[Literal['legacy', 'quick', 'reasoned']] = Field(default_factory=lambda: ['legacy'])
    thinking_modes: list[Literal['off', 'on']] = Field(default_factory=list)
    efforts: list[Literal['none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max']] = Field(default_factory=list)
    max_output_tokens: int | None = Field(default=None, ge=1, le=1000000)
    profile_version: int = Field(default=1, ge=1)

    @model_validator(mode='after')
    def supported_configuration(self):
        if len(self.profiles) != len(set(self.profiles)) or 'legacy' not in self.profiles:
            raise ValueError('inference_profiles_require_legacy')
        if set(self.profiles) - {'legacy'}:
            if self.dialect == 'unknown' or not self.model_id or 'off' not in self.thinking_modes:
                raise ValueError('inference_capability_unavailable')
        if 'reasoned' in self.profiles and 'on' not in self.thinking_modes:
            raise ValueError('inference_thinking_unavailable')
        if self.dialect == 'deepseek' and set(self.efforts) - {'low', 'high', 'max'}:
            raise ValueError('inference_effort_unavailable')
        if self.dialect == 'vercel_gateway' and set(self.efforts) - {'minimal', 'low', 'medium', 'high', 'xhigh'}:
            raise ValueError('inference_effort_unavailable')
        if self.dialect == 'openai' and 'on' in self.thinking_modes:
            if 'none' not in self.efforts or 'high' not in self.efforts:
                raise ValueError('inference_effort_unavailable')
        return self


class InferenceOptions(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    dialect: Literal['unknown', 'deepseek', 'openai', 'vercel_gateway']
    model_id: str = Field(min_length=1, max_length=100)
    thinking_mode: Literal['provider_default', 'off', 'on']
    effort: Literal['none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max'] | None = None
    max_output_tokens: int | None = Field(default=None, ge=1, le=1000000)
    profile_version: int = Field(default=1, ge=1)
    selection_source: Literal['legacy_default', 'user_selected', 'tool_phase']

    @model_validator(mode='after')
    def explicit_is_bounded(self):
        if self.thinking_mode != 'provider_default' and (self.dialect == 'unknown' or self.max_output_tokens is None):
            raise ValueError('inference_capability_unavailable')
        if self.thinking_mode == 'provider_default' and self.effort is not None:
            raise ValueError('inference_effort_unavailable')
        if self.thinking_mode == 'off' and self.effort not in (None, 'none'):
            raise ValueError('inference_effort_unavailable')
        if self.thinking_mode == 'on' and self.effort == 'none':
            raise ValueError('inference_effort_unavailable')
        if self.dialect == 'deepseek' and self.effort not in (None, 'low', 'high', 'max'):
            raise ValueError('inference_effort_unavailable')
        if self.dialect == 'vercel_gateway' and self.effort not in (None, 'minimal', 'low', 'medium', 'high', 'xhigh'):
            raise ValueError('inference_effort_unavailable')
        return self


def configuration(profile):
    return InferenceConfiguration.model_validate(profile.limits.get('inference', {}))


def available_profiles(profile):
    return configuration(profile).profiles


def resolve_inference(profile, model, cfg, selection='legacy'):
    """Snapshot one authorized choice. No account preference or catalogue mutation."""
    from .service import AgentDenied
    config = configuration(profile)
    if selection not in config.profiles:
        raise AgentDenied('inference_profile_not_allowed')
    if selection == 'legacy':
        options = InferenceOptions(dialect='unknown', model_id=model.model_id,
            thinking_mode='provider_default', selection_source='legacy_default',
            max_output_tokens=None if cfg.limits.provider_managed else cfg.routing.max_output_tokens)
        return {'version': 1, 'profile': 'legacy', 'options': options.model_dump()}
    connector = profile.connection.engine.connector_type
    expected = {'deepseek': 'openai_compatible', 'openai': 'openai', 'vercel_gateway': 'vercel_gateway'}
    if config.model_id != model.model_id or connector != expected.get(config.dialect):
        raise AgentDenied('inference_capability_unavailable')
    if type(model.max_tokens) is not int or model.max_tokens <= 0:
        raise AgentDenied('unknown_capacity')
    maxima = [4096 if selection == 'quick' else 8192, model.max_tokens, cfg.routing.max_output_tokens]
    if config.max_output_tokens is not None:
        maxima.append(config.max_output_tokens)
    effort = ('none' if config.dialect == 'openai' and 'on' in config.thinking_modes else None) if selection == 'quick' else (
        'high' if 'high' in config.efforts else None)
    options = InferenceOptions(dialect=config.dialect, model_id=model.model_id,
        thinking_mode='off' if selection == 'quick' else 'on', effort=effort,
        max_output_tokens=min(maxima), profile_version=config.profile_version, selection_source='user_selected')
    # Tool phases deliberately stay quick. The bound remains the chosen cap.
    quick = options.model_copy(update={'thinking_mode': 'off', 'effort':
        'none' if config.dialect == 'openai' and 'on' in config.thinking_modes else None,
        'max_output_tokens': min(4096, options.max_output_tokens), 'selection_source': 'tool_phase'})
    return {'version': 1, 'profile': selection, 'options': options.model_dump(), 'tool_options': quick.model_dump()}


def options_for_call(snapshot, *, tools=False):
    """A reasoned selection permits reasoning only for the final tool-free answer."""
    if not snapshot or snapshot.get('profile') == 'legacy':
        return None
    value = snapshot['tool_options'] if tools and snapshot['profile'] == 'reasoned' else snapshot['options']
    return InferenceOptions.model_validate(value).model_dump()


def wire_options(options, *, model, tools=False):
    """Only this allowlisted translation may produce new provider-specific fields."""
    option = InferenceOptions.model_validate(options)
    if option.model_id != model:
        raise ValueError('inference_model_changed')
    if option.thinking_mode == 'provider_default':
        raise ValueError('explicit_inference_options_required')
    if tools and option.thinking_mode == 'on':
        raise ValueError('reasoning_tool_continuity_unavailable')
    result = {'max_completion_tokens' if option.dialect == 'openai' else 'max_tokens': option.max_output_tokens}
    if option.dialect == 'deepseek':
        result['extra_body'] = {'thinking': {'type': 'enabled' if option.thinking_mode == 'on' else 'disabled'}}
        if option.effort:
            result['reasoning_effort'] = option.effort
    elif option.dialect == 'openai':
        if option.effort:
            result['reasoning_effort'] = option.effort
    elif option.dialect == 'vercel_gateway':
        result['extra_body'] = {'reasoning': {'enabled': option.thinking_mode == 'on', 'exclude': True}}
        if option.effort:
            result['extra_body']['reasoning']['effort'] = option.effort
    else:
        raise ValueError('inference_capability_unavailable')
    return result
