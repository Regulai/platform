import json

from django.test import SimpleTestCase

from .verification import normalize_finish_reason, verify_response


class VerificationTests(SimpleTestCase):
    fragments = [{"id": "current-document:1", "locator": "paragraph:1",
                  "text": "The contract states: revenue is 10 euros.\nNo refund is available."}]

    def document(self, text="Revenue is 10 euros.", identifier="current-document:1",
                 quote="revenue is 10 euros."):
        return json.dumps({"claims": [{"text": text,
                                      "citations": [{"id": identifier, "quote": quote}]}]})

    def test_local_checks_never_claim_semantic_truth(self):
        result = verify_response("A plausible answer.", "stop")
        self.assertEqual(result["local_status"], "passed")
        self.assertEqual(result["status"], "not_verified")
        self.assertEqual(result["checks"][-1], {"code": "semantic", "status": "not_verified"})

    def test_completion_reasons_and_empty_content_fail_before_any_judgment(self):
        for content, reason, expected in [("answer", "length", "truncated"),
                                           ("answer", "max_tokens", "truncated"),
                                           ("answer", "content_filter", "refused"),
                                           ("answer", "new_finish_reason", "unknown"),
                                           ("", "stop", "complete")]:
            with self.subTest(reason=reason):
                result = verify_response(content, reason, require_semantic=False)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["finish_reason"], expected)
        self.assertEqual(normalize_finish_reason("end_turn"), "complete")

    def test_literal_citation_resolves_server_evidence_but_does_not_prove_claim(self):
        result = verify_response(self.document(text="Revenue is 900 euros."), "stop",
                                 fragments=self.fragments)
        self.assertEqual(result["local_status"], "passed")
        self.assertEqual(result["status"], "not_verified")
        self.assertEqual(result["evidence"], [{"claim_index": 1, "alias": "S1",
                                              "fragment_id": "current-document:1", "id": "current-document:1",
                                              "locator": "paragraph:1",
                                              "excerpt": "revenue is 10 euros."}])

    def test_forged_external_and_previous_document_ids_are_not_sources(self):
        for identifier in ["previous-document:1", "https://example.test/source",
                           "C:/private.txt", "<img src=x onerror=alert(1)>"]:
            with self.subTest(identifier=identifier):
                result = verify_response(self.document(identifier=identifier), "stop",
                                         fragments=self.fragments)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["checks"][-2]["reason"], "unknown_citation")
                self.assertEqual(result["evidence"], [])

    def test_literal_normalization_only_allows_whitespace_changes(self):
        whitespace = verify_response(self.document(quote="revenue\n is  10 euros."), "stop",
                                     fragments=self.fragments)
        self.assertEqual(whitespace["local_status"], "passed")
        for quote in ["Revenue is 10 euros.", "revenue is 10 euros!", "revenue is 100 euros."]:
            with self.subTest(quote=quote):
                result = verify_response(self.document(quote=quote), "stop", fragments=self.fragments)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["checks"][-2]["reason"], "quote_not_found")

    def test_invalid_json_missing_citations_and_forged_locator_fail(self):
        forged = json.loads(self.document())
        forged["claims"][0]["citations"][0]["locator"] = "page:999"
        for content in ["```json\n{}\n```", '{"claims": []}',
                        '{"claims": [{"text": "claim", "citations": []}]}', json.dumps(forged)]:
            with self.subTest(content=content):
                result = verify_response(content, "stop", fragments=self.fragments)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["evidence"], [])

    def test_html_in_current_source_is_plain_evidence_text(self):
        literal = "<script>alert('not executed')</script>"
        result = verify_response(self.document(quote=literal), "stop",
                                 fragments=[{**self.fragments[0], "text": literal}])
        self.assertEqual(result["status"], "not_verified")
        self.assertEqual(result["evidence"][0]["excerpt"], literal)

    def test_evidence_is_bounded_and_never_copies_full_document(self):
        long_source = [{**self.fragments[0], "text": "x" * 10000 + "revenue is 10 euros." + "z" * 10000}]
        result = verify_response(self.document(), "stop", fragments=long_source)
        self.assertEqual(result["evidence"][0]["excerpt"], "revenue is 10 euros.")
        overlong = verify_response(self.document(quote="x" * 1601), "stop", fragments=long_source)
        self.assertEqual(overlong["status"], "failed")
        self.assertEqual(overlong["checks"][-2]["reason"], "invalid_quote")

    def test_document_citations_always_need_semantic_judgment(self):
        result = verify_response(self.document(), "stop", fragments=self.fragments,
                                 require_semantic=False)
        self.assertEqual(result["status"], "not_verified")

    def test_invalid_unicode_and_duplicate_json_fields_fail_safely(self):
        invalid_unicode = verify_response("\ud800", "stop")
        self.assertEqual(invalid_unicode["status"], "failed")
        duplicate = self.document().replace('"claims":', '"claims": [], "claims":')
        result = verify_response(duplicate, "stop", fragments=self.fragments)
        self.assertEqual(result["status"], "failed")

    def test_quotes_need_twelve_nonspace_characters_or_three_words(self):
        for quote in ("e", "10 euros.", "   e   "):
            with self.subTest(quote=quote):
                result = verify_response(self.document(quote=quote), "stop", fragments=self.fragments)
                self.assertEqual(result["local_status"], "failed")
                self.assertEqual(result["checks"][-2]["reason"], "invalid_quote")
        short_words = [{**self.fragments[0], "text": "a b c"}]
        result = verify_response(self.document(quote="a b c"), "stop", fragments=short_words)
        self.assertEqual(result["local_status"], "passed")

    def test_configurable_quote_limits_cannot_accept_a_single_character(self):
        for quote, chars, words, expected in [("10 euros.", 8, 3, "passed"),
                                               ("revenue is 10 euros.", 40, 5, "failed"),
                                               ("e", 1, 1, "failed")]:
            with self.subTest(quote=quote):
                result = verify_response(self.document(quote=quote), "stop", fragments=self.fragments,
                                         min_quote_chars=chars, min_quote_words=words)
                self.assertEqual(result["local_status"], expected)
        for limit in (0, True, "12"):
            result = verify_response(self.document(), "stop", fragments=self.fragments,
                                     min_quote_chars=limit)
            self.assertEqual(result["checks"][-2]["reason"], "invalid_quote_limits")

    def test_source_aliases_hide_stable_ids_and_resolve_server_evidence(self):
        from .sources import build_sources
        sources = build_sources(self.fragments)
        self.assertEqual(json.loads(sources.prompt_json), [{"id": "S1", "locator": "paragraph:1",
                                                          "text": self.fragments[0]["text"]}])
        self.assertEqual(sources.alias_to_id, {"S1": "current-document:1"})
        self.assertNotIn("current-document:1", sources.prompt_json)
        result = verify_response(self.document(identifier="S1"), "stop", fragments=self.fragments,
                                 alias_to_id=sources.alias_to_id)
        self.assertEqual(result["local_status"], "passed")
        self.assertEqual(result["evidence"], [{"claim_index": 1, "alias": "S1",
            "fragment_id": "current-document:1", "id": "current-document:1", "locator": "paragraph:1",
            "excerpt": "revenue is 10 euros."}])

    def test_thirty_claims_fit_the_judge_limit_and_more_are_rejected(self):
        claim = json.loads(self.document())["claims"][0]
        for count, expected in ((30, "passed"), (31, "failed"), (32, "failed")):
            with self.subTest(count=count):
                result = verify_response(json.dumps({"claims": [claim] * count}), "stop",
                                         fragments=self.fragments)
                self.assertEqual(result["local_status"], expected)
                if count == 30:
                    self.assertEqual(result["evidence"][-1]["claim_index"], 30)
                else:
                    self.assertEqual(result["checks"][-2]["reason"], "invalid_claims")

    def test_alias_mode_rejects_stable_ids_and_forged_alias_maps(self):
        for identifier in ("current-document:1", "S2", "https://example.test/source"):
            result = verify_response(self.document(identifier=identifier), "stop", fragments=self.fragments,
                                     alias_to_id={"S1": "current-document:1"})
            self.assertEqual(result["checks"][-2]["reason"], "unknown_citation")
            self.assertEqual(result["evidence"], [])
        for aliases in ({"S1": "previous-document:1"}, {"S1": 1}, {"unsafe": "current-document:1"},
                        {"S1": "current-document:1", "S2": "current-document:1"}, []):
            result = verify_response(self.document(identifier="S1"), "stop", fragments=self.fragments,
                                     alias_to_id=aliases)
            self.assertEqual(result["checks"][-2]["reason"], "invalid_source_aliases")

    def test_sources_preserve_masked_text_locators_and_reject_duplicate_ids(self):
        from .sources import build_sources
        fragments = [{"id": "stable-sha", "locator": "lines:1-3", "text": "Code: <NUM_1> is valid."},
                     {"id": "second-sha", "locator": "paragraph:2", "text": "No refund is available."}]
        sources = build_sources(fragments)
        self.assertEqual(sources.alias_to_id, {"S1": "stable-sha", "S2": "second-sha"})
        result = verify_response(self.document(identifier="S1", quote="Code: <NUM_1> is valid."), "stop",
                                 fragments=fragments, alias_to_id=sources.alias_to_id)
        self.assertEqual(result["evidence"][0]["excerpt"], "Code: <NUM_1> is valid.")
        self.assertEqual(result["evidence"][0]["locator"], "lines:1-3")
        for invalid in ([fragments[0], fragments[0]], [{"id": "bad", "text": "No locator"}]):
            with self.assertRaisesRegex(ValueError, "invalid_sources"):
                build_sources(invalid)

    def test_exactly_one_outer_json_fence_and_no_surrounding_prose_is_allowed(self):
        raw = self.document()
        for content in (raw, "```json\n" + raw + "\n```", " \r\n```json\r\n" + raw + "\r\n```\r\n "):
            self.assertEqual(verify_response(content, "stop", fragments=self.fragments)["local_status"], "passed")
        for content in ("Prefix\n```json\n" + raw + "\n```", "```json\n" + raw + "\n```\nSuffix",
                        "```\n" + raw + "\n```", "```json\n" + raw + "\n```\n```json\n{}\n```",
                        raw.replace('"quote":', '"quote": "e", "quote":')):
            result = verify_response(content, "stop", fragments=self.fragments)
            self.assertEqual(result["checks"][-2]["reason"], "invalid_document_json")

    def test_missing_finish_reason_keeps_completeness_unknown(self):
        result = verify_response(self.document(), None, fragments=self.fragments)
        self.assertEqual(result["finish_reason"], "unknown")
        self.assertEqual(result["local_status"], "failed")
        self.assertEqual(result["evidence"], [])
