"""Local response/citation checks; these cannot establish semantic truth."""
import json
import re


MAX_CLAIMS = 30


def normalize_finish_reason(finish_reason):
    if not isinstance(finish_reason, str):
        return "unknown"
    reason = finish_reason.strip().lower()
    if reason in {"stop", "end_turn", "stop_sequence", "complete", "completed"}:
        return "complete"
    if reason in {"length", "max_tokens", "max_output_tokens", "truncated", "incomplete"}:
        return "truncated"
    if reason in {"content_filter", "refusal", "refused", "safety", "blocked"}:
        return "refused"
    return "unknown"


def _normalize_quote(text):
    # Only whitespace is normalized: punctuation, case, and Unicode are literal.
    return " ".join(text.split())


def _unique_fields(pairs):
    fields = {}
    for key, value in pairs:
        if key in fields:
            raise ValueError("duplicate_json_field")
        fields[key] = value
    return fields


def _document_claims(content, fragments, alias_to_id, min_quote_chars, min_quote_words):
    """Resolve only request-supplied fragment IDs; no URL/path/HTML interpretation."""
    sources = {}
    for fragment in fragments:
        if (not isinstance(fragment, dict)
                or any(not isinstance(fragment.get(key), str) for key in ("id", "locator", "text"))
                or not fragment["id"] or fragment["id"] in sources):
            raise ValueError("invalid_sources")
        sources[fragment["id"]] = fragment
    aliases = alias_to_id if alias_to_id is not None else {
        f"S{index}": identifier for index, identifier in enumerate(sources, 1)}
    if (not isinstance(aliases, dict) or any(
            not isinstance(alias, str) or not re.fullmatch(r"S[1-9][0-9]*", alias)
            or not isinstance(identifier, str) or identifier not in sources
            for alias, identifier in aliases.items()) or len(set(aliases.values())) != len(aliases)):
        raise ValueError("invalid_source_aliases")
    source_aliases = {identifier: alias for alias, identifier in aliases.items()}
    try:
        fence = re.fullmatch(r"```json[ \t]*\r?\n([\s\S]*?)\r?\n```", content.strip())
        if fence:
            content = fence[1]
        document = json.loads(content, object_pairs_hook=_unique_fields)
    except (ValueError, RecursionError):
        raise ValueError("invalid_document_json") from None
    if not isinstance(document, dict) or set(document) != {"claims"}:
        raise ValueError("invalid_document_structure")
    claims = document["claims"]
    if not isinstance(claims, list) or not 1 <= len(claims) <= MAX_CLAIMS:
        raise ValueError("invalid_claims")
    evidence, evidence_chars = [], 0
    for index, claim in enumerate(claims, 1):
        if (not isinstance(claim, dict) or set(claim) != {"text", "citations"}
                or not isinstance(claim["text"], str) or not claim["text"].strip()
                or len(claim["text"]) > 4000):
            raise ValueError("invalid_claim")
        citations = claim["citations"]
        if not isinstance(citations, list) or not 1 <= len(citations) <= 8:
            raise ValueError("missing_citations")
        for citation in citations:
            if (not isinstance(citation, dict) or set(citation) != {"id", "quote"}
                    or not isinstance(citation["id"], str)
                    or not isinstance(citation["quote"], str)):
                raise ValueError("invalid_citation")
            identifier = aliases.get(citation["id"]) if alias_to_id is not None else citation["id"]
            source = sources.get(identifier)
            if source is None:
                raise ValueError("unknown_citation")
            quote = _normalize_quote(citation["quote"])
            words = quote.split()
            quote_chars = sum(len(word) for word in words)
            if (quote_chars <= 1 or len(quote) > 1600
                    or (quote_chars < min_quote_chars and len(words) < min_quote_words)):
                raise ValueError("invalid_quote")
            source_text = _normalize_quote(source["text"])
            position = source_text.find(quote)
            if position < 0:
                raise ValueError("quote_not_found")
            # Extract from the server source, never accept model locator/excerpt.
            excerpt = source_text[position:position + len(quote)]
            evidence_chars += len(excerpt)
            if evidence_chars > 16000:
                raise ValueError("evidence_limit")
            evidence.append({"claim_index": index, "alias": source_aliases[source["id"]],
                             "fragment_id": source["id"], "id": source["id"],
                             "locator": source["locator"], "excerpt": excerpt})
    return claims, evidence


def verify_response(content, finish_reason, *, fragments=None, require_semantic=True,
                    alias_to_id=None, min_quote_chars=12, min_quote_words=3):
    """Return serializable checks. A semantic judge is required by default.

    fragments=None checks prose; a list requires the exact document JSON contract.
    Document mode always needs semantic judgment. Returned strings are plain
    text and must be escaped/textContent in the UI.
    alias_to_id resolves only this request's server-owned source aliases; None
    keeps compatibility with callers still sending stable IDs. Missing provider
    finish reasons cannot prove completeness and remain unknown.
    """
    checks, claims, evidence = [], [], []
    valid_content = isinstance(content, str) and bool(content.strip())
    checks.append({"code": "nonempty", "status": "passed" if valid_content else "failed"})
    completion = normalize_finish_reason(finish_reason)
    checks.append({"code": "completion", "status": "passed" if completion == "complete" else "failed",
                   "reason": completion})
    if valid_content:
        try:
            if len(content.encode("utf-8")) > 128000:
                checks.append({"code": "response_limit", "status": "failed"})
        except UnicodeEncodeError:
            checks.append({"code": "response_encoding", "status": "failed"})
    if fragments is not None and all(check["status"] == "passed" for check in checks):
        try:
            if any(type(value) is not int or value < 1 for value in (min_quote_chars, min_quote_words)):
                raise ValueError("invalid_quote_limits")
            claims, evidence = _document_claims(content, fragments, alias_to_id, min_quote_chars, min_quote_words)
            checks.append({"code": "citations", "status": "passed"})
        except ValueError as error:
            checks.append({"code": "citations", "status": "failed", "reason": str(error)})
    local_status = "failed" if any(check["status"] == "failed" for check in checks) else "passed"
    require_semantic = require_semantic or fragments is not None
    if require_semantic:
        checks.append({"code": "semantic", "status": "not_verified"})
    status = "failed" if local_status == "failed" else ("not_verified" if require_semantic else "passed")
    return {"status": status, "local_status": local_status, "finish_reason": completion,
            "checks": checks, "claims": claims, "evidence": evidence}
