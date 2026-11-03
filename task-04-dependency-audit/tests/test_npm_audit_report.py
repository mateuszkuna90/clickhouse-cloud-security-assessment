"""Unit tests for scripts/npm_audit_report.py (standard library only).

Run from task-04-dependency-audit/:
    py -3 -m unittest discover -s tests -v      (Windows)
    python3 -m unittest discover -s tests -v    (Linux/macOS)
"""

from __future__ import annotations

import contextlib
import csv
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TASK_DIR = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
MALFORMED = FIXTURES / "malformed"
REPORTS = TASK_DIR / "reports"
LOCK = TASK_DIR / "app" / "package-lock.json"
sys.path.insert(0, str(TASK_DIR / "scripts"))

import npm_audit_report as nar  # noqa: E402

VALID = FIXTURES / "example-npm-audit-v2.json"
VALID_LOCK = FIXTURES / "example-package-lock.json"

# Each malformed fixture and the part of the error message it must produce.
MALFORMED_CASES = {
    "example-missing-severity.json": "severity must be one of",
    "example-severity-array.json": "severity must be one of",
    "example-severity-object.json": "severity must be one of",
    "example-severity-unknown-value.json": "severity must be one of",
    "example-advisory-severity-array.json": "via[0]: severity must be one of",
    "example-nested-entry-not-object.json": "must be an object",
    "example-via-item-not-object.json": "must be a string or an object",
    "example-missing-fields.json": "isDirect must be true or false",
    "example-advisory-missing-url.json": "url is missing",
    "example-fix-available-malformed.json": "fixAvailable.version is missing",
    "example-name-mismatch.json": "expected 'example-major'",
    "example-metadata-count-mismatch.json": "do not match metadata.vulnerabilities",
    "example-metadata-total-mismatch.json": "total is not the sum",
    "example-metadata-missing.json": "'metadata' object is missing",
    "example-via-unknown-package.json": "not another package in this report",
    "example-effects-not-reciprocal.json": "does not list it in 'effects'",
    "example-severity-below-own-advisory.json": "lower than its own advisories",
    "example-vulnerabilities-not-object.json": "'vulnerabilities' must be an object",
    "example-report-version-float.json": "unsupported auditReportVersion",
    "example-npm6-format.json": "npm 6 audit format",
    # The only finding is the malformed one: the old parser exited 0 under --fail-on high.
    "example-only-high-missing-severity.json": "severity must be one of",
    "example-only-high-not-object.json": "must be an object",
}

# Saved reports in reports/generated/ and the inputs they were produced from.
GENERATED = {
    "baseline": ("baseline/npm-audit.json", LOCK),
    "baseline-prod": ("baseline/npm-audit-prod.json", LOCK),
    "initial-run/after-audit-fix": ("remediation/initial-run/npm-audit-after-audit-fix.json", None),
    "initial-run/after-minor-bumps": ("remediation/initial-run/npm-audit-after-minor-bumps.json", None),
    "initial-run/after-audit-fix-force":
        ("remediation/initial-run/npm-audit-after-audit-fix-force.json", None),
    **{
        f"rerun-2026-11-03/{s}": (f"remediation/rerun-2026-11-03/{s}/npm-audit.json",
                                  REPORTS / f"remediation/rerun-2026-11-03/{s}/package-lock.json")
        for s in ("baseline-reaudit", "A-audit-fix", "B-minor-pins", "C-audit-fix-force",
                  "D-force-then-mocha-11.0.0")
    },
}


class CliTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.out = self.tmp / "out"

    def run_cli(self, *args: str, out: Path | None = None) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = nar.run([*args, "--out-dir", str(out or self.out)])
        return code, stdout.getvalue(), stderr.getvalue()

    def summary(self) -> dict:
        return json.loads((self.out / nar.SUMMARY_FILE).read_text(encoding="utf-8"))

    def csv_rows(self) -> list[dict[str, str]]:
        with (self.out / nar.CSV_FILE).open(encoding="utf-8", newline="") as fh:
            return list(csv.DictReader(fh))

    def write_json(self, name: str, obj) -> Path:
        path = self.tmp / name
        path.write_text(json.dumps(obj), encoding="utf-8")
        return path

    def seed_stale_outputs(self) -> None:
        """Pretend an earlier run left a clean-looking result behind."""
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / nar.SUMMARY_FILE).write_text('{"status": "ok"}\n', encoding="utf-8")
        (self.out / nar.CSV_FILE).write_text("package\nstale\n", encoding="utf-8")

    def assert_failed_closed(self, code: int, expected_code: int, status: str) -> dict:
        self.assertEqual(code, expected_code)
        self.assertFalse((self.out / nar.CSV_FILE).exists(), "stale or partial CSV left behind")
        data = self.summary()
        self.assertEqual(data["status"], status)
        self.assertNotIn("packages", data)
        self.assertNotIn("counts", data)
        return data


class ValidReportTests(CliTestCase):
    def setUp(self) -> None:
        super().setUp()
        code, _, self.stderr = self.run_cli(str(VALID), "--lockfile", str(VALID_LOCK))
        self.assertEqual(code, nar.EXIT_OK, self.stderr)
        self.data = self.summary()
        self.pkgs = {p["package"]: p for p in self.data["packages"]}

    def test_status_and_format(self):
        self.assertEqual(self.data["status"], "ok")
        self.assertEqual(self.data["input"]["format"], "npm-audit-v2")
        self.assertEqual(len(self.data["input"]["sha256"]), 64)
        self.assertEqual(self.stderr, "")

    def test_counts_by_severity(self):
        counts = self.data["counts"]
        self.assertEqual(counts["vulnerable_packages"], 5)
        self.assertEqual(counts["vulnerable_packages_by_severity"],
                         {"critical": 2, "high": 1, "moderate": 1, "low": 1, "info": 0})
        self.assertEqual(counts["unique_advisories"], 5)
        self.assertEqual(counts["high_critical_packages"], 3)
        self.assertTrue(self.data["reconciliation"]["matches"])

    def test_direct_and_transitive(self):
        self.assertEqual(self.data["counts"]["direct_packages"], 2)
        self.assertEqual(self.data["counts"]["transitive_packages"], 3)

    def test_fix_status_variants(self):
        self.assertEqual(self.pkgs["example-direct"]["fix"],
                         {"status": "non-breaking", "package": "example-direct",
                          "version": "1.2.3", "is_semver_major": False})
        self.assertEqual(self.pkgs["example-major"]["fix"]["status"], "breaking")
        self.assertEqual(self.pkgs["example-nofix"]["fix"]["status"], "none")
        self.assertEqual(self.pkgs["example-auto"]["fix"]["status"], "non-breaking")
        self.assertIsNone(self.pkgs["example-auto"]["fix"]["version"])
        self.assertEqual(self.data["counts"]["packages_by_fix_status"],
                         {"breaking": 1, "non-breaking": 3, "none": 1})

    def test_inherited_severity_is_kept_separate(self):
        direct = self.pkgs["example-direct"]
        # npm rates the package critical because of its child; its own advisory is high.
        self.assertEqual(direct["severity"], "critical")
        self.assertEqual([a["severity"] for a in direct["advisories"]], ["high"])
        self.assertEqual(direct["inherited_from"], ["example-child"])

    def test_optional_fields_are_not_invented(self):
        adv = self.pkgs["example-nofix"]["advisories"][0]
        self.assertIsNone(adv["cvss_score"])
        self.assertEqual(adv["cwe"], [])

    def test_ghsa_only_taken_from_url(self):
        self.assertEqual(self.pkgs["example-direct"]["advisories"][0]["ghsa"],
                         "GHSA-2222-3333-4444")
        self.assertIsNone(self.pkgs["example-auto"]["advisories"][0]["ghsa"])

    def test_installed_versions_from_lockfile(self):
        self.assertEqual(self.pkgs["example-child"]["installed_versions"], ["0.3.1", "0.4.0"])
        self.assertEqual(self.pkgs["example-auto"]["installed_versions"], ["1.9.0"])

    def test_packages_sorted_by_severity_then_name(self):
        names = [p["package"] for p in self.data["packages"]]
        self.assertEqual(names, ["example-child", "example-direct", "example-major",
                                 "example-nofix", "example-auto"])

    def test_csv_matches_summary(self):
        rows = self.csv_rows()
        self.assertEqual(tuple(rows[0].keys()), nar.CSV_COLUMNS)
        self.assertEqual(len(rows), 5)
        child = rows[0]
        self.assertEqual(child["package"], "example-child")
        self.assertEqual(child["installed_versions"], "0.3.1;0.4.0")
        self.assertEqual(child["is_direct"], "false")
        self.assertEqual(child["fix_status"], "non-breaking")
        self.assertEqual(rows[3]["fix_version"], "")  # example-nofix

    def test_csv_formula_injection_is_neutralised(self):
        self.assertTrue(self.csv_rows()[0]["advisory_titles"].startswith("'=HYPERLINK"))


class MalformedReportTests(CliTestCase):
    """Invalid evidence must never be reported as a clean (or any) result."""

    def test_every_malformed_fixture_is_covered(self):
        self.assertEqual(sorted(p.name for p in MALFORMED.glob("*.json")),
                         sorted(MALFORMED_CASES))

    def test_malformed_reports_are_rejected(self):
        for name, message in MALFORMED_CASES.items():
            with self.subTest(fixture=name):
                self.seed_stale_outputs()
                code, out, err = self.run_cli(str(MALFORMED / name))
                data = self.assert_failed_closed(code, nar.EXIT_INPUT_ERROR, "input_error")
                self.assertIn(message, data["error"])
                self.assertIn(message, err)
                self.assertEqual(out, "", "no result line for invalid input")
                self.assertNotIn("Traceback", err)

    def test_malformed_reports_fail_closed_with_fail_on(self):
        for name in MALFORMED_CASES:
            for level in ("high", "critical", "info"):
                with self.subTest(fixture=name, fail_on=level):
                    code, _, _ = self.run_cli(str(MALFORMED / name), "--fail-on", level)
                    self.assertEqual(code, nar.EXIT_INPUT_ERROR)

    def test_lockfile_that_does_not_match_report(self):
        lock = json.loads(VALID_LOCK.read_text(encoding="utf-8"))
        del lock["packages"]["node_modules/example-auto"]
        code, _, err = self.run_cli(str(VALID), "--lockfile",
                                    str(self.write_json("lock.json", lock)))
        self.assert_failed_closed(code, nar.EXIT_INPUT_ERROR, "input_error")
        self.assertIn("report and lockfile do not match", err)

    def test_duplicate_advisory_with_different_details(self):
        report = json.loads(VALID.read_text(encoding="utf-8"))
        vulns = report["vulnerabilities"]
        clone = dict(vulns["example-major"]["via"][0], name="example-nofix", severity="moderate")
        vulns["example-nofix"]["via"].append(clone)
        code, _, err = self.run_cli(str(self.write_json("dup.json", report)))
        self.assert_failed_closed(code, nar.EXIT_INPUT_ERROR, "input_error")
        self.assertIn("appears twice with different details", err)


class InputErrorTests(CliTestCase):
    def assert_input_error(self, path: Path, message: str):
        self.seed_stale_outputs()
        code, _, err = self.run_cli(str(path))
        data = self.assert_failed_closed(code, nar.EXIT_INPUT_ERROR, "input_error")
        self.assertIn(message, err)
        self.assertIn(message, data["error"])

    def test_missing_file(self):
        self.assert_input_error(self.tmp / "does-not-exist.json", "not found")

    def test_malformed_json(self):
        self.assert_input_error(FIXTURES / "example-malformed.json", "not valid JSON")

    def test_empty_file(self):
        path = self.tmp / "empty.json"
        path.write_bytes(b"")
        self.assert_input_error(path, "is empty")

    def test_not_an_object(self):
        self.assert_input_error(self.write_json("list.json", []), "must be a JSON object")

    def test_unknown_schema_version(self):
        self.assert_input_error(FIXTURES / "example-unknown-schema.json",
                                "unsupported auditReportVersion")

    def test_unrecognised_object(self):
        self.assert_input_error(self.write_json("other.json", {"hello": "world"}),
                                "'auditReportVersion' is missing")

    def test_invalid_utf8(self):
        path = self.tmp / "latin1.json"
        path.write_bytes(b'{"x": "\xff"}')
        self.assert_input_error(path, "not valid UTF-8")

    def test_directory_as_input(self):
        (self.tmp / "dir").mkdir()
        self.assert_input_error(self.tmp / "dir", "not a regular file")

    def test_bad_lockfile(self):
        code, _, err = self.run_cli(str(VALID), "--lockfile",
                                    str(FIXTURES / "example-npm-error.json"))
        self.assert_failed_closed(code, nar.EXIT_INPUT_ERROR, "input_error")
        self.assertIn("lockfile has no 'packages' map", err)

    def test_error_object_mixed_with_results(self):
        report = json.loads(VALID.read_text(encoding="utf-8"))
        report["error"] = {"code": "EAUDIT", "summary": "x"}
        self.assert_input_error(self.write_json("mixed.json", report),
                                "both an 'error' object and audit results")

    def test_error_object_malformed(self):
        self.assert_input_error(self.write_json("err.json", {"error": "boom"}),
                                "'error' must be an object")

    def test_utf8_bom_is_accepted(self):
        path = self.tmp / "bom.json"
        path.write_bytes(b"\xef\xbb\xbf" + VALID.read_bytes())
        self.assertEqual(self.run_cli(str(path))[0], nar.EXIT_OK)


class ScannerAndInternalErrorTests(CliTestCase):
    def test_scanner_error_is_not_a_finding(self):
        self.seed_stale_outputs()
        code, out, err = self.run_cli(str(FIXTURES / "example-npm-error.json"),
                                      "--fail-on", "high")
        data = self.assert_failed_closed(code, nar.EXIT_SCANNER_ERROR, "scanner_error")
        self.assertIn("ENOLOCK", err)
        self.assertEqual(out, "")
        self.assertEqual(data["scanner_error"]["code"], "ENOLOCK")

    def test_unexpected_exception_fails_closed(self):
        self.seed_stale_outputs()
        with mock.patch.object(nar, "build_summary", side_effect=RuntimeError("boom")):
            code, _, err = self.run_cli(str(VALID), "--fail-on", "high")
        data = self.assert_failed_closed(code, nar.EXIT_INTERNAL_ERROR, "internal_error")
        self.assertIn("RuntimeError: boom", err)
        self.assertIn("boom", data["error"])


class BehaviourTests(CliTestCase):
    def test_output_is_deterministic(self):
        args = (str(VALID), "--lockfile", str(VALID_LOCK))
        self.run_cli(*args)
        first = ((self.out / nar.SUMMARY_FILE).read_bytes(), (self.out / nar.CSV_FILE).read_bytes())
        self.run_cli(*args)
        second = ((self.out / nar.SUMMARY_FILE).read_bytes(), (self.out / nar.CSV_FILE).read_bytes())
        self.assertEqual(first, second)

    def test_outputs_use_lf_line_endings(self):
        self.run_cli(str(VALID))
        for name in (nar.SUMMARY_FILE, nar.CSV_FILE):
            self.assertNotIn(b"\r\n", (self.out / name).read_bytes(), name)

    def test_no_partial_files_left(self):
        self.run_cli(str(VALID))
        self.assertEqual(sorted(p.name for p in self.out.iterdir()),
                         [nar.CSV_FILE, nar.SUMMARY_FILE])

    def test_fail_on_threshold(self):
        self.assertEqual(self.run_cli(str(VALID), "--fail-on", "critical")[0], nar.EXIT_THRESHOLD)
        self.assertEqual(self.run_cli(str(VALID), "--fail-on", "high")[0], nar.EXIT_THRESHOLD)

    def test_clean_report_passes_gate(self):
        clean = {"auditReportVersion": 2, "vulnerabilities": {},
                 "metadata": {"vulnerabilities": {"info": 0, "low": 0, "moderate": 0,
                                                  "high": 0, "critical": 0, "total": 0}}}
        code, out, _ = self.run_cli(str(self.write_json("clean.json", clean)), "--fail-on", "low")
        self.assertEqual(code, nar.EXIT_OK)
        self.assertIn("0 vulnerable packages", out)
        self.assertEqual(self.csv_rows(), [])


class SavedAuditTests(CliTestCase):
    """Checks against the genuine npm audit output committed in reports/."""

    def test_genuine_reports_parse_and_reconcile(self):
        reports = sorted(REPORTS.glob("baseline/npm-audit*.json")) + \
            sorted(REPORTS.glob("remediation/**/npm-audit*.json"))
        self.assertEqual(len(reports), 11)  # 2 baseline + 4 initial-run + 5 rerun
        for path in reports:
            with self.subTest(report=str(path.relative_to(REPORTS))):
                code, _, err = self.run_cli(str(path), "--fail-on", "critical")
                self.assertIn(code, (nar.EXIT_OK, nar.EXIT_THRESHOLD), err)
                self.assertEqual(err, "")
                data = self.summary()
                raw = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(data["counts"]["vulnerable_packages"],
                                 raw["metadata"]["vulnerabilities"]["total"])
                self.assertEqual(len(self.csv_rows()), len(raw["vulnerabilities"]))

    def test_baseline_counts(self):
        self.assertTrue(LOCK.is_file())
        code, _, _ = self.run_cli(str(REPORTS / "baseline/npm-audit.json"), "--lockfile", str(LOCK),
                                  "--fail-on", "high")
        self.assertEqual(code, nar.EXIT_THRESHOLD)
        counts = self.summary()["counts"]
        self.assertEqual(counts["vulnerable_packages"], 26)
        self.assertEqual(counts["high_critical_packages"], 18)
        self.assertEqual(counts["unique_advisories"], 47)
        self.assertEqual(counts["unique_advisories_by_severity"]["critical"]
                         + counts["unique_advisories_by_severity"]["high"], 25)
        self.assertTrue(all(p["installed_versions"] for p in self.summary()["packages"]))

    def test_saved_generated_reports_are_byte_identical(self):
        self.assertEqual(sorted(GENERATED), sorted(
            str(p.parent.relative_to(REPORTS / "generated")).replace("\\", "/")
            for p in (REPORTS / "generated").glob("**/" + nar.SUMMARY_FILE)))
        for name, (report, lock) in GENERATED.items():
            with self.subTest(generated=name):
                out = self.tmp / name
                args = [str(REPORTS / report)] + (["--lockfile", str(lock)] if lock else [])
                self.run_cli(*args, out=out)
                for f in (nar.SUMMARY_FILE, nar.CSV_FILE):
                    self.assertEqual((out / f).read_bytes(),
                                     (REPORTS / "generated" / name / f).read_bytes(), f)


if __name__ == "__main__":
    unittest.main()
