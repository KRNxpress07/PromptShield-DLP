# Phase 2 Baseline Test Triage

Prepared **before implementation**, 13 October 2026. Baseline reproduced: gateway 211 passed/1 failed, scanner 44 passed/24 failed, SDK 20 passed; total **275 passed, 25 failed, 0 skipped**. All 141 Phase 1 regression cases pass.

## Detection decisions

- Credit cards: retain **Luhn/checksum validation**, support valid contiguous/space/dash formatting. Do not treat known checksum-invalid examples as valid cards merely to satisfy fixtures.
- SSNs: structural validity checks, zero/reserved groups and known Presidio sample exclusions; no claim that a syntactically valid synthetic value is actually issued. Add valid synthetic-format cases, preserve rejection of invalid values.
- International phones: explicitly marked '+' formats and possible-number length validation; detection does not prove assignment/reachability. This defensibly protects synthetic example numbers without a provider lookup.
- Accept bounded English numbered-street and PO-box patterns, UK postal shapes and context-qualified US ZIP/Indian PIN. These are address-shape heuristics, not authoritative postal validation.
- Accept masked SSN fragments as PII under distinct **MASKED_US_SSN**, not as valid full US_SSN. Tests asserting the old entity name will receive an explicitly documented category correction without weakening span/redaction assertions.
- Postal values belong to **POSTAL_CODE**, not LOCATION. Existing tests will be migrated to this implemented category while preserving the exact-value span assertions.
- CVV and card expiry are **out of scope** this phase: short numeric/date matches need a separate PCI-specific requirement. They will not be mislabeled CREDIT_CARD.
- Preserve the unrelated config fallback failure; no behavior change to configuration fallback.

## Every baseline failure

All scanner methods below are in `presidio/tests/test_sovereign_safety.py`.

| Test | Classification | Phase decision and rationale |
|---|---|---|
| proxy-api TestGetGatewayConfig.test_missing_file_returns_empty | D: expectation/isolation mismatch | DEFER: real repository YAML fallback exists; unrelated to detection |
| TestPIIRedaction.test_ssn_detected | B: questionable sample | INVALID/QUESTIONABLE FIXTURE: 123-45-6789 is deliberately excluded by existing Presidio validator; retain rejection |
| TestCreditCardEdgeCases.test_dash_separated_card | B: checksum-invalid fixture | INVALID/QUESTIONABLE FIXTURE: 4111-2222-3333-4444 is not Luhn-valid; add a valid dashed card test |
| TestCreditCardEdgeCases.test_space_separated_non_luhn_with_context | B: explicitly invalid | INVALID/QUESTIONABLE FIXTURE: do not disable checksum for Visa prose |
| TestCreditCardEdgeCases.test_card_expiry_slash | C: entity conflation | OUT OF SCOPE: expiry is not a card number; no CREDIT_CARD_EXPIRY implementation |
| TestCreditCardEdgeCases.test_cvv_after_keyword | C: entity conflation | OUT OF SCOPE: CVV is not CREDIT_CARD; no standalone CVV implementation |
| TestCreditCardEdgeCases.test_full_pci_payload_all_redacted | C/B: mixed unsupported/invalid | OUT OF SCOPE: invalid card plus CVV/expiry cannot establish accepted card coverage |
| TestCreditCardEdgeCases.test_dash_card_with_cardholder_context | B: checksum-invalid | INVALID/QUESTIONABLE FIXTURE: retain checksum requirement; corresponding valid-format regression added |
| TestCreditCardEdgeCases.test_mixed_pci_hipaa_prompt | B/C: invalid and unsupported | INVALID/QUESTIONABLE FIXTURE: 000-00-0000 invalid SSN, invalid card, unsupported PCI short values |
| TestTabularDataEdgeCases.test_us_phone_dash_with_country_code | A: accepted shaped PII | FIX IN PHASE 2: explicit international format with possible-number length check; not assignment verification |
| TestTabularDataEdgeCases.test_masked_ssn_xxx | A/D: accepted partial PII, wrong category | FIX IN PHASE 2: active MASKED_US_SSN; preserve exact span checks |
| TestTabularDataEdgeCases.test_masked_ssn_star | A/D: accepted partial PII, wrong category | FIX IN PHASE 2: same, asterisk masking |
| TestTabularDataEdgeCases.test_uk_postcode | A/D: accepted postal value, wrong category | FIX IN PHASE 2: POSTAL_CODE, exact postal span retained |
| TestTabularDataEdgeCases.test_uk_postcode_sw1a | A/D | FIX IN PHASE 2: POSTAL_CODE, not LOCATION |
| TestTabularDataEdgeCases.test_india_pin_code | A/D | FIX IN PHASE 2: context-qualified POSTAL_CODE, not arbitrary six-digit numbers |
| TestTabularDataEdgeCases.test_full_csv_row_redaction | A | FIX IN PHASE 2: phone, date, masked ID and address protection; no general CSV classifier claim |
| TestTabularDataEdgeCases.test_multi_row_csv | A/D | FIX IN PHASE 2: MASKED_US_SSN rather than mislabeling partial IDs full US_SSN |
| TestFullCsvIntegration.test_complete_csv_redaction | A | FIX IN PHASE 2: each accepted phone/partial-ID span removed |
| TestStreetAddressRecognizer.test_basic_street_rd | A | FIX IN PHASE 2: bounded numbered-street rule |
| TestStreetAddressRecognizer.test_basic_street_st | A | FIX IN PHASE 2: same |
| TestStreetAddressRecognizer.test_po_box | A | FIX IN PHASE 2: explicit PO box |
| TestStreetAddressRecognizer.test_street_address_redacted | A | FIX IN PHASE 2: full address span replacement |
| TestStreetAddressRecognizer.test_uk_road | A | FIX IN PHASE 2: numbered English street shape |
| TestOverlapSuppression.test_ssn_dash_format_no_datetime | B: excluded sample | INVALID/QUESTIONABLE FIXTURE: add valid synthetic counterpart; do not re-enable known sample |
| TestOverlapSuppression.test_non_overlapping_entities_kept | B: excluded sample | INVALID/QUESTIONABLE FIXTURE: email should still work; excluded sample is not a real detector defect |

The proposed changes do not touch or weaken the Phase 1 security regression files. Remaining invalid/out-of-scope failures will stay visible, without xfail/skip. Final outcomes are recorded in PHASE2_DETECTION_COVERAGE_REPORT.md.

## Additional fixture correction required by accepted validator semantics

The previously passing TestPIIRedaction.test_multiple_entities_all_redacted used reserved 900-series value 999-88-7777. The Phase 2 validator rejects that area range under the SSA structural rules. This composite redaction test now uses synthetic 321-54-6789 and retains both entity-presence and exact sensitive-value removal assertions. This is a validity correction tied to implementation, not a removed requirement or weaker assertion. The separate negative regression explicitly verifies rejection of 900-series values.

