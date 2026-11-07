"""Small shared contracts for the pinned worker; no Django or provider client."""
import hashlib
import json
import uuid

from .protocol import WireMessage


def canonical_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
        separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def compaction_call_id(execution, messages, options, tools=()):
    # Normalize optional wire fields identically on both sides of HTTP.
    wire = [WireMessage.model_validate(message).model_dump() for message in messages]
    value = {'messages': wire, 'options': options, 'tools': list(tools)}
    return str(uuid.uuid5(uuid.UUID(str(execution)), 'compaction:' + canonical_digest(value)))


def summary_content(summary):
    # Deep Agents 0.6.12, _build_new_messages_with_path(..., file_path=None).
    return 'Here is a summary of the conversation to date:\n\n' + summary.strip()
