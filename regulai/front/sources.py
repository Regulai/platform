"""Short source aliases for already-authorized, already-masked fragments."""
from dataclasses import dataclass
import json


@dataclass(frozen=True)
class SourcesView:
    prompt_json: str
    alias_to_id: dict[str, str]


def build_sources(fragments):
    sources, aliases, identifiers = [], {}, set()
    for index, fragment in enumerate(fragments, 1):
        if (not isinstance(fragment, dict)
                or any(not isinstance(fragment.get(key), str) for key in ("id", "locator", "text"))
                or not fragment["id"] or fragment["id"] in identifiers):
            raise ValueError("invalid_sources")
        alias = f"S{index}"
        identifiers.add(fragment["id"])
        aliases[alias] = fragment["id"]
        sources.append({"id": alias, "locator": fragment["locator"], "text": fragment["text"]})
    return SourcesView(json.dumps(sources, ensure_ascii=False, allow_nan=False, separators=(",", ":")), aliases)
