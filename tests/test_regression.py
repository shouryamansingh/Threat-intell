"""Regression tests for soc_report_formatter_enhanced.

These run against the EXACT two articles (Cisco SD-WAN, Weekly Recap) that
produced the two broken reports, so the known failures cannot silently return.

AI models are disabled so we exercise the deterministic extraction path — the
same path that produced the original buggy emails in production.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from soc_report_formatter_enhanced import EnhancedSOCReportFormatter

FIXTURES = json.load(open(os.path.join(HERE, "regression_fixtures.json")))


def make_formatter():
    f = EnhancedSOCReportFormatter()
    # Force the deterministic (non-AI) path for reproducible assertions.
    f._ai_available = False
    f._summarizer = False
    f._sentence_model = False
    return f


def build(article):
    return make_formatter().format_soc_report(article)


def dump(label, r):
    print(f"\n{'='*80}\n{label}\n{'='*80}")
    if r is None:
        print("  <None returned>")
        return
    for fld in ("threat_type", "cve_id", "severity_rating", "exploited_systems",
                "tactics_used", "attack_outcome", "financial_impact",
                "data_loss_exposure", "reputational_risk", "mitigation_measures",
                "is_roundup"):
        print(f"  {fld:18}: {getattr(r, fld)}")
    print("  validation_warnings:")
    for w in r.validation_warnings:
        print(f"      - {w}")


def check(name, cond):
    status = "PASS" if cond else "FAIL"
    print(f"  [{status}] {name}")
    return (name, bool(cond))


def verify(results):
    """Fail the test, naming every sub-check that broke.

    These functions used to end in `return all(results)`. pytest ignores what a
    test returns — it only warns about it — so every test here reported PASS
    even when the checks inside it failed, and the suite could not catch the
    regressions it was written to catch. Assert instead, and list the failures
    so the output says which behaviour came back.
    """
    failed = [name for name, ok in results if not ok]
    assert not failed, "failed checks:\n  - " + "\n  - ".join(failed)


def test_cisco():
    r = build(FIXTURES["1356"])
    dump("CISCO SD-WAN (id 1356)", r)
    results = [
        check("primary CVE is CVE-2026-20262", r.cve_id == "CVE-2026-20262"),
        check("severity is Medium 6.5", "Medium" in r.severity_rating and "6.5" in r.severity_rating),
        check("NOT a roundup", r.is_roundup is False),
        check("tactics do NOT claim credential theft",
              "credential theft" not in r.tactics_used.lower()),
        check("exploited systems names Cisco/SD-WAN product",
              "sd-wan" in r.exploited_systems.lower() or "cisco" in r.exploited_systems.lower()),
        check("exploited systems is not the 'Word 0' fragment",
              not EnhancedSOCReportFormatter._looks_like_fragment(r.exploited_systems)),
        check("reputational risk de-inflated (not High)",
              not r.reputational_risk.startswith("High")),
        check("attack outcome doesn't start with 'However,'",
              not r.attack_outcome.lower().startswith("however")),
        check("mitigation names a fixed version (20.9.9.2)",
              "20.9.9.2" in r.mitigation_measures),
        check("mitigation has no recap filler",
              "scroll through" not in r.mitigation_measures.lower()),
        check("CVE appears in the prose (no mismatch warning)",
              not any("not mentioned" in w for w in r.validation_warnings)),
    ]
    verify(results)


def test_weekly_recap():
    r = build(FIXTURES["1358"])
    dump("WEEKLY RECAP (id 1358)", r)
    results = [
        check("detected as roundup", r.is_roundup is True),
        check("primary CVE is CVE-2026-11645 (NOT 5281)", r.cve_id == "CVE-2026-11645"),
        check("attack outcome NOT contaminated with PeopleSoft",
              "peoplesoft" not in r.attack_outcome.lower()),
        check("exploited systems is not 'Chrome 0' fragment",
              r.exploited_systems.strip().lower() != "chrome 0"
              and not EnhancedSOCReportFormatter._looks_like_fragment(r.exploited_systems)),
        check("severity is High 8.8", "High" in r.severity_rating and "8.8" in r.severity_rating),
        check("mitigation has no 'scroll through' filler",
              "scroll through" not in r.mitigation_measures.lower()),
        check("mitigation not the 'this week is the same lesson' filler",
              "lesson in a new form" not in r.mitigation_measures.lower()),
        check("roundup warning present",
              any("roundup" in w.lower() or "digest" in w.lower() for w in r.validation_warnings)),
    ]
    verify(results)


def _shares_a_sentence(a, b):
    """True if any normalized sentence appears in BOTH texts (cross-section dup)."""
    f = make_formatter()
    na = {f._norm_sentence(s) for s in f._split_sentences_clean(a) if f._norm_sentence(s)}
    nb = {f._norm_sentence(s) for s in f._split_sentences_clean(b) if f._norm_sentence(s)}
    return bool(na & nb)


def test_joomla():
    """Joomla JCE report (the email that had: a torn-off 'Phil E.' byline, the
    same CISA sentence repeated across sections, 'Exploited Systems' filled with
    the CISA cataloging sentence, and 'Data Loss: Low' for a CVSS 10.0 RCE)."""
    r = build(FIXTURES["1360"])
    dump("JOOMLA JCE (id 1360)", r)
    blob = " ".join([r.threat_summary, r.description, r.attack_outcome,
                     r.exploited_systems, r.mitigation_measures]).lower()
    results = [
        check("primary CVE is CVE-2026-48907", r.cve_id == "CVE-2026-48907"),
        check("severity is Critical 10.0",
              "Critical" in r.severity_rating and "10.0" in r.severity_rating),
        check("exploited systems names the product (Joomla/JCE), not the CISA action",
              ("joomla" in r.exploited_systems.lower() or "jce" in r.exploited_systems.lower())
              and "known exploited vulnerabilities" not in r.exploited_systems.lower()),
        check("no torn-off 'Phil E.' byline anywhere", "phil e." not in blob),
        check("data exposure NOT understated as 'Low' for an RCE/backdoor",
              not r.data_loss_exposure.lower().startswith("low")),
        check("mitigation is not a KEV-cataloging status sentence",
              "known exploited vulnerabilities" not in r.mitigation_measures.lower()),
        check("no sentence repeated across summary and mitigation",
              not _shares_a_sentence(r.threat_summary, r.mitigation_measures)),
        check("no sentence repeated across summary and exploited systems",
              not _shares_a_sentence(r.threat_summary, r.exploited_systems)),
    ]
    verify(results)


def test_cisa_kev_multicve():
    """CISA 'added 4 flaws to KEV' bulletin (the email that mixed CVEs: it began
    on CVE-2026-48282/Adobe ColdFusion but bled in Langflow's CVE-2026-55255 and
    listed 'JoomShaper SP Page Builder' as the exploited system).

    An inline multi-CVE list has no newsletter section markers, so the old
    scoper no-opped and every field bound to a different CVE. The report must
    now be isolated to the PRIMARY CVE only."""
    r = build(FIXTURES["1556"])
    dump("CISA KEV — 4 CVEs inline (id 1556)", r)
    es = r.exploited_systems.lower()
    ao = r.attack_outcome.lower()
    prose = " ".join([r.threat_summary, r.description, r.attack_outcome,
                      r.exploited_systems, r.mitigation_measures]).upper()
    foreign_cves = [c for c in ("CVE-2026-56290", "CVE-2026-55255", "CVE-2026-48908")
                    if c in prose]
    results = [
        check("detected as roundup/digest", r.is_roundup is True),
        check("primary CVE is CVE-2026-48282", r.cve_id == "CVE-2026-48282"),
        check("exploited systems names Adobe ColdFusion, not JoomShaper/Joomla",
              "coldfusion" in es and "joom" not in es),
        check("attack outcome free of cross-CVE bleed (no Langflow/Joomla)",
              "langflow" not in ao and "joom" not in ao),
        check("no foreign CVE ids leak into the report prose",
              not foreign_cves),
        check("roundup warning present for the validator",
              any("roundup" in w.lower() or "digest" in w.lower()
                  for w in r.validation_warnings)),
    ]
    verify(results)


def test_strip_leading_connective():
    """Stripping a leading 'However,' must NOT lowercase the rest of the
    sentence (acronyms like CVE/CVSS and proper nouns must stay intact)."""
    print(f"\n{'='*80}\nLEADING-CONNECTIVE CASING\n{'='*80}")
    f = EnhancedSOCReportFormatter()
    src = ("However, successful exploitation hinges on the attacker already having "
           "valid credentials with at least write access. The vulnerability, tracked "
           "as CVE-2026-20262, carries a CVSS score of 6.5 out of 10.0.")
    out = f._strip_leading_connective(src)
    print("  ->", out)
    results = [
        check("no leading 'However,'", not out.lower().startswith("however")),
        check("starts capitalised", out[:1].isupper()),
        check("CVE id casing preserved", "CVE-2026-20262" in out),
        check("CVSS casing preserved", "CVSS" in out),
        check("'The vulnerability' casing preserved", "The vulnerability" in out),
        check("no lowercased 'cve-'/'cvss'", "cve-2026" not in out and "cvss" not in out),
    ]
    # Non-connective text must pass through untouched.
    untouched = "An attacker could overwrite any file. The CVE is CVE-2026-1."
    results.append(check("non-connective text untouched", f._strip_leading_connective(untouched) == untouched))
    verify(results)


if __name__ == "__main__":
    # Direct execution keeps the old summary table; pytest uses the asserts.
    TESTS = [
        ("CISCO", test_cisco),
        ("RECAP", test_weekly_recap),
        ("JOOMLA", test_joomla),
        ("CISA-KEV", test_cisa_kev_multicve),
        ("CONNECTIVE", test_strip_leading_connective),
    ]
    outcomes = []
    for label, fn in TESTS:
        try:
            fn()
            outcomes.append((label, True))
        except AssertionError as exc:
            print(f"\n{label}: {exc}")
            outcomes.append((label, False))

    print(f"\n{'='*80}")
    for label, ok in outcomes:
        print(f"{label + ':':<13}{'ALL PASS' if ok else 'FAILURES'}")
    print(f"{'='*80}")
    sys.exit(0 if all(ok for _, ok in outcomes) else 1)
