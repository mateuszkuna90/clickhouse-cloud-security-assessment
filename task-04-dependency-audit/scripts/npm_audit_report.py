#!/usr/bin/env python3
"""Turn a saved `npm audit --json` report into a JSON summary and a CSV.

The script only reads files. It never runs npm or any package code.

It fails closed: the report is validated in full before anything is
counted or any --fail-on gate is evaluated. A report that is missing
fields, has wrong types, refers to packages that are not in it, or whose
totals disagree with npm's own metadata is rejected as an input error. It
is never reported as a clean result.

Accepted input:
  * npm 7+ audit report: {"auditReportVersion": 2, "vulnerabilities": {...},
    "metadata": {"vulnerabilities": {...}}}
  * npm error report:    {"error": {"code": ..., "summary": ..., "detail": ...}}
The npm 6 format (no auditReportVersion, "advisories" map) is rejected
explicitly; regenerate the report with npm 7 or later.

Exit codes:
  0  report generated (vulnerabilities may still be present)
  1  report generated and a package at or above --fail-on was found
  2  invalid input or output problem; no CSV is left in --out-dir
  3  the input is an npm error report: the scan itself did not succeed
  4  unexpected internal error; no CSV is left in --out-dir

Output contract: existing audit-summary.json and audit-packages.csv in
--out-dir are deleted before anything new is written. On success both are
written. On exit 2, 3 or 4 only audit-summary.json is written, with
"status" set to "input_error", "scanner_error" or "internal_error".
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

SUMMARY_SCHEMA_VERSION = 2
MAX_INPUT_BYTES = 50 * 1024 * 1024
SEVERITIES = ("info", "low", "moderate", "high", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}
GHSA_RE = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}")

SUMMARY_FILE = "audit-summary.json"
CSV_FILE = "audit-packages.csv"

EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_INPUT_ERROR = 2
EXIT_SCANNER_ERROR = 3
EXIT_INTERNAL_ERROR = 4

CSV_COLUMNS = (
    "package",
    "severity",
    "is_direct",
    "installed_versions",
    "vulnerable_range",
    "nodes",
    "advisory_count",
    "advisory_ids",
    "advisory_urls",
    "advisory_titles",
    "inherited_from",
    "effects",
    "fix_status",
    "fix_package",
    "fix_version",
    "fix_is_semver_major",
)


class InputError(Exception):
    """The input cannot be trusted to build a report."""


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

def load_json(path: Path, what: str) -> tuple[Any, bytes]:
    """Read a JSON file with a size limit. Returns (parsed, raw bytes)."""
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        raise InputError(f"{what} not found: {path}") from None
    except OSError as exc:
        raise InputError(f"cannot access {what} {path}: {exc.strerror}") from None
    if not path.is_file():
        raise InputError(f"{what} is not a regular file: {path}")
    if size == 0:
        raise InputError(f"{what} is empty: {path}")
    if size > MAX_INPUT_BYTES:
        raise InputError(f"{what} is larger than {MAX_INPUT_BYTES} bytes: {path}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise InputError(f"cannot read {what} {path}: {exc.strerror}") from None
    try:
        # utf-8-sig tolerates the BOM that some Windows shells add.
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise InputError(f"{what} is not valid UTF-8: {path}") from None
    try:
        return json.loads(text), raw
    except json.JSONDecodeError as exc:
        raise InputError(
            f"{what} is not valid JSON (line {exc.lineno}, column {exc.colno}): {path}"
        ) from None
    except RecursionError:
        raise InputError(f"{what} is nested too deeply: {path}") from None


# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------

def _require(condition: bool, message: str) -> None:
    if not condition:
        raise InputError(message)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def _check_severity(value: Any, where: str) -> str:
    # isinstance first: an unhashable value (list, dict) must not reach the dict lookup.
    _require(isinstance(value, str) and value in SEVERITY_RANK,
             f"{where}: severity must be one of {', '.join(SEVERITIES)}; got {value!r}")
    return value


def _check_str_list(value: Any, where: str, *, non_empty: bool = False) -> list[str]:
    _require(isinstance(value, list) and all(_is_text(v) for v in value),
             f"{where}: must be a list of non-empty strings; got {value!r}")
    _require(not non_empty or len(value) > 0, f"{where}: must not be empty")
    _require(len(set(value)) == len(value), f"{where}: contains duplicates")
    return list(value)


def _ghsa(url: str) -> str | None:
    match = GHSA_RE.search(url)
    return match.group(0) if match else None


# --------------------------------------------------------------------------
# Format detection
# --------------------------------------------------------------------------

def detect_format(report: Any) -> str:
    _require(isinstance(report, dict), "audit report must be a JSON object")
    if "error" in report:
        _require("vulnerabilities" not in report and "auditReportVersion" not in report,
                 "report has both an 'error' object and audit results")
        err = report["error"]
        _require(isinstance(err, dict), "'error' must be an object")
        for key in ("code", "summary", "detail"):
            _require(err.get(key) is None or isinstance(err[key], str),
                     f"error.{key} must be a string")
        _require(_is_text(err.get("code")) or _is_text(err.get("summary")),
                 "'error' object has neither a code nor a summary")
        return "npm-error"
    if "auditReportVersion" not in report:
        _require("advisories" not in report,
                 "npm 6 audit format (no auditReportVersion) is not supported; "
                 "rerun the audit with npm 7 or later")
        raise InputError("unrecognised report: 'auditReportVersion' is missing")
    version = report["auditReportVersion"]
    _require(_is_int(version) and version == 2,
             f"unsupported auditReportVersion: {version!r} (only 2 is supported)")
    return "npm-audit-v2"


# --------------------------------------------------------------------------
# npm 7+ report validation and normalisation
# --------------------------------------------------------------------------

def _check_metadata(report: dict[str, Any]) -> dict[str, int]:
    meta = report.get("metadata")
    _require(isinstance(meta, dict), "'metadata' object is missing")
    counts = meta.get("vulnerabilities")
    _require(isinstance(counts, dict), "'metadata.vulnerabilities' object is missing")
    for key in SEVERITIES + ("total",):
        value = counts.get(key)
        _require(_is_int(value) and value >= 0,
                 f"metadata.vulnerabilities.{key} must be a non-negative integer; got {value!r}")
    _require(counts["total"] == sum(counts[s] for s in SEVERITIES),
             "metadata.vulnerabilities.total is not the sum of the severity counts")
    return {k: counts[k] for k in SEVERITIES + ("total",)}


def _parse_advisory(item: dict[str, Any], package: str, where: str) -> dict[str, Any]:
    source = item.get("source")
    _require(_is_int(source) or _is_text(source), f"{where}.source is missing or invalid")
    _require(item.get("name") == package,
             f"{where}.name is {item.get('name')!r}, expected {package!r}")
    for key in ("title", "url", "range"):
        _require(_is_text(item.get(key)), f"{where}.{key} is missing or not a string")
    severity = _check_severity(item.get("severity"), where)

    cvss = item.get("cvss")
    score = None
    if cvss is not None:
        _require(isinstance(cvss, dict), f"{where}.cvss must be an object")
        score = cvss.get("score")
        _require(score is None or (isinstance(score, (int, float))
                                   and not isinstance(score, bool) and 0 <= score <= 10),
                 f"{where}.cvss.score must be a number from 0 to 10")
    cwe = item.get("cwe")
    cwe = [] if cwe is None else _check_str_list(cwe, f"{where}.cwe")

    return {
        "id": source,
        "ghsa": _ghsa(item["url"]),
        "title": item["title"],
        "url": item["url"],
        "severity": severity,
        "vulnerable_range": item["range"],
        # npm uses 0 for "not scored"; keep npm's value rather than guessing.
        "cvss_score": score,
        "cwe": sorted(cwe),
    }


def _parse_fix(value: Any, where: str) -> dict[str, Any]:
    if value is True:
        # npm: `npm audit fix` resolves it within the declared ranges.
        return {"status": "non-breaking", "package": None, "version": None,
                "is_semver_major": False}
    if value is False:
        return {"status": "none", "package": None, "version": None, "is_semver_major": None}
    _require(isinstance(value, dict),
             f"{where}: must be true, false or an object; got {value!r}")
    _require(_is_text(value.get("name")), f"{where}.name is missing or not a string")
    _require(_is_text(value.get("version")), f"{where}.version is missing or not a string")
    major = value.get("isSemVerMajor")
    _require(isinstance(major, bool), f"{where}.isSemVerMajor must be true or false")
    return {"status": "breaking" if major else "non-breaking", "package": value["name"],
            "version": value["version"], "is_semver_major": major}


def parse_v2(report: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Validate an npm 7+ report in full and return (packages, npm metadata counts)."""
    vulns = report.get("vulnerabilities")
    _require(isinstance(vulns, dict), "'vulnerabilities' must be an object")
    metadata = _check_metadata(report)

    packages: list[dict[str, Any]] = []
    for key, vuln in vulns.items():
        where = f"vulnerabilities[{key!r}]"
        _require(_is_text(key), f"{where}: empty package key")
        _require(isinstance(vuln, dict), f"{where}: must be an object")
        _require(vuln.get("name") == key,
                 f"{where}.name is {vuln.get('name')!r}, expected {key!r}")
        severity = _check_severity(vuln.get("severity"), where)
        _require(isinstance(vuln.get("isDirect"), bool), f"{where}.isDirect must be true or false")
        _require(_is_text(vuln.get("range")), f"{where}.range is missing or not a string")
        nodes = _check_str_list(vuln.get("nodes"), f"{where}.nodes", non_empty=True)
        effects = _check_str_list(vuln.get("effects"), f"{where}.effects")
        fix = _parse_fix(vuln.get("fixAvailable"), f"{where}.fixAvailable")

        via = vuln.get("via")
        _require(isinstance(via, list) and len(via) > 0, f"{where}.via must be a non-empty list")
        advisories, inherited = [], []
        for i, item in enumerate(via):
            if isinstance(item, str):
                _require(item in vulns and item != key,
                         f"{where}.via[{i}] refers to {item!r}, which is not another "
                         "package in this report")
                inherited.append(item)
            elif isinstance(item, dict):
                advisories.append(_parse_advisory(item, key, f"{where}.via[{i}]"))
            else:
                raise InputError(f"{where}.via[{i}] must be a string or an object")
        _require(len(set(inherited)) == len(inherited), f"{where}.via has duplicate entries")

        if advisories:
            worst = max(SEVERITY_RANK[a["severity"]] for a in advisories)
            _require(SEVERITY_RANK[severity] >= worst,
                     f"{where}: severity {severity!r} is lower than its own advisories")

        packages.append({
            "package": key,
            "severity": severity,
            "is_direct": vuln["isDirect"],
            "vulnerable_range": vuln["range"],
            "nodes": sorted(nodes),
            "advisories": sorted(advisories, key=lambda a: str(a["id"])),
            "inherited_from": sorted(inherited),
            "effects": sorted(effects),
            "fix": fix,
        })

    # Cross-references must agree in both directions.
    by_name = {p["package"]: p for p in packages}
    for pkg in packages:
        for child in pkg["inherited_from"]:
            _require(pkg["package"] in by_name[child]["effects"],
                     f"inconsistent report: {pkg['package']!r} lists {child!r} in 'via' "
                     f"but {child!r} does not list it in 'effects'")
        for parent in pkg["effects"]:
            _require(parent in by_name and pkg["package"] in by_name[parent]["inherited_from"],
                     f"inconsistent report: {pkg['package']!r} lists {parent!r} in 'effects' "
                     f"but {parent!r} does not list it in 'via'")

    # The same advisory must not be described differently in two places.
    seen: dict[str, dict[str, Any]] = {}
    for pkg in packages:
        for adv in pkg["advisories"]:
            key = str(adv["id"])
            if key in seen:
                _require(seen[key] == adv, f"advisory {key} appears twice with different details")
            seen[key] = adv

    counted = {s: sum(1 for p in packages if p["severity"] == s) for s in SEVERITIES}
    counted["total"] = len(packages)
    _require(counted == metadata,
             f"inconsistent report: per-package counts {counted} do not match "
             f"metadata.vulnerabilities {metadata}")
    return packages, metadata


def lockfile_versions(lock: Any) -> dict[str, str]:
    """Map lockfile install paths (node_modules/...) to resolved versions."""
    _require(isinstance(lock, dict) and isinstance(lock.get("packages"), dict),
             "lockfile has no 'packages' map (lockfileVersion 2 or 3 required)")
    versions = {}
    for node_path, meta in lock["packages"].items():
        if node_path and isinstance(meta, dict) and isinstance(meta.get("version"), str):
            versions[node_path] = meta["version"]
    return versions


# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------

def build_summary(report: dict[str, Any], fmt: str, input_name: str, input_sha256: str,
                  versions: dict[str, str] | None) -> dict[str, Any]:
    base = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "input": {"file": input_name, "sha256": input_sha256, "format": fmt},
    }
    if fmt == "npm-error":
        err = report["error"]
        return {**base, "status": "scanner_error",
                "scanner_error": {k: err.get(k) for k in ("code", "summary", "detail")}}

    packages, metadata = parse_v2(report)
    packages.sort(key=lambda p: (-SEVERITY_RANK[p["severity"]], p["package"]))

    for pkg in packages:
        if versions is None:
            pkg["installed_versions"] = None
            continue
        missing = [n for n in pkg["nodes"] if n not in versions]
        _require(not missing,
                 f"report and lockfile do not match: {pkg['package']} nodes not in "
                 f"lockfile: {', '.join(missing)}")
        pkg["installed_versions"] = sorted({versions[n] for n in pkg["nodes"]})

    unique: dict[str, dict[str, Any]] = {}
    for pkg in packages:
        for adv in pkg["advisories"]:
            unique.setdefault(str(adv["id"]), adv)

    def tally(items: list[dict[str, Any]], key) -> dict[str, int]:
        out: dict[str, int] = {}
        for item in items:
            out[key(item)] = out.get(key(item), 0) + 1
        return dict(sorted(out.items()))

    high_critical = [p for p in packages if p["severity"] in ("high", "critical")]
    return {
        **base,
        "status": "ok",
        "counts": {
            "vulnerable_packages": len(packages),
            "vulnerable_packages_by_severity": {s: metadata[s] for s in SEVERITIES},
            "direct_packages": sum(1 for p in packages if p["is_direct"]),
            "transitive_packages": sum(1 for p in packages if not p["is_direct"]),
            "unique_advisories": len(unique),
            "unique_advisories_by_severity": {
                s: sum(1 for a in unique.values() if a["severity"] == s) for s in SEVERITIES},
            "packages_by_fix_status": tally(packages, lambda p: p["fix"]["status"]),
            "high_critical_packages": len(high_critical),
            "high_critical_packages_by_fix_status":
                tally(high_critical, lambda p: p["fix"]["status"]),
        },
        # parse_v2 rejects any mismatch, so a written summary always matches.
        "reconciliation": {"npm_metadata": metadata, "matches": True},
        "packages": packages,
    }


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def _csv_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    # Stop spreadsheet apps treating advisory text as a formula.
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        text = "'" + text
    return text


def csv_rows(summary: dict[str, Any]) -> list[dict[str, str]]:
    rows = []
    for p in summary["packages"]:
        advs = p["advisories"]
        row = {
            "package": p["package"],
            "severity": p["severity"],
            "is_direct": p["is_direct"],
            "installed_versions": (None if p["installed_versions"] is None
                                   else ";".join(p["installed_versions"])),
            "vulnerable_range": p["vulnerable_range"],
            "nodes": ";".join(p["nodes"]),
            "advisory_count": len(advs),
            "advisory_ids": ";".join(a["ghsa"] or str(a["id"]) for a in advs),
            "advisory_urls": ";".join(a["url"] for a in advs),
            "advisory_titles": " | ".join(a["title"] for a in advs),
            "inherited_from": ";".join(p["inherited_from"]),
            "effects": ";".join(p["effects"]),
            "fix_status": p["fix"]["status"],
            "fix_package": p["fix"]["package"],
            "fix_version": p["fix"]["version"],
            "fix_is_semver_major": p["fix"]["is_semver_major"],
        }
        rows.append({k: _csv_cell(v) for k, v in row.items()})
    return rows


def clear_outputs(out_dir: Path) -> None:
    """Delete outputs from an earlier run so they can never be mistaken for this one."""
    for name in (SUMMARY_FILE, CSV_FILE):
        try:
            (out_dir / name).unlink(missing_ok=True)
        except OSError as exc:
            raise InputError(f"cannot remove old output {out_dir / name}: {exc.strerror}") from None


def _write_atomic(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".partial")
    with tmp.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    os.replace(tmp, path)


def write_summary(summary: dict[str, Any], out_dir: Path) -> None:
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        _write_atomic(out_dir / SUMMARY_FILE, json.dumps(summary, indent=2, sort_keys=True) + "\n")
    except OSError as exc:
        raise InputError(f"cannot write {SUMMARY_FILE} to {out_dir}: {exc.strerror}") from None


def write_csv(summary: dict[str, Any], out_dir: Path) -> None:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(csv_rows(summary))
    try:
        _write_atomic(out_dir / CSV_FILE, buf.getvalue())
    except OSError as exc:
        raise InputError(f"cannot write {CSV_FILE} to {out_dir}: {exc.strerror}") from None


def _write_failure(out_dir: Path, status: str, message: str, input_name: str) -> None:
    """Best effort: record why the run failed. Stale outputs are already gone."""
    try:
        write_summary({"schema_version": SUMMARY_SCHEMA_VERSION, "status": status,
                       "error": message, "input": {"file": input_name}}, out_dir)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _process(args: argparse.Namespace) -> int:
    clear_outputs(args.out_dir)
    report, raw = load_json(args.report, "audit report")
    fmt = detect_format(report)
    versions = None
    if args.lockfile:
        versions = lockfile_versions(load_json(args.lockfile, "lockfile")[0])
    summary = build_summary(report, fmt, args.report.name,
                            hashlib.sha256(raw).hexdigest(), versions)
    write_summary(summary, args.out_dir)

    if summary["status"] == "scanner_error":
        err = summary["scanner_error"]
        print(f"npm audit did not complete: {err['code'] or ''} {err['summary'] or ''}".strip(),
              file=sys.stderr)
        return EXIT_SCANNER_ERROR

    write_csv(summary, args.out_dir)
    c = summary["counts"]
    sev = c["vulnerable_packages_by_severity"]
    print(f"{c['vulnerable_packages']} vulnerable packages "
          f"(critical {sev['critical']}, high {sev['high']}, moderate {sev['moderate']}, "
          f"low {sev['low']}, info {sev['info']}); "
          f"{c['unique_advisories']} unique advisories; "
          f"fix status {c['packages_by_fix_status']}")

    if args.fail_on:
        threshold = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[p["severity"]] >= threshold for p in summary["packages"]):
            return EXIT_THRESHOLD
    return EXIT_OK


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Summarise a saved `npm audit --json` report as JSON and CSV.")
    parser.add_argument("report", type=Path, help="path to the saved npm audit JSON")
    parser.add_argument("--out-dir", type=Path, required=True,
                        help=f"directory for {SUMMARY_FILE} and {CSV_FILE}")
    parser.add_argument("--lockfile", type=Path,
                        help="package-lock.json (v2/v3) to add installed versions")
    parser.add_argument("--fail-on", choices=SEVERITIES,
                        help="exit 1 if any package is at or above this severity")
    args = parser.parse_args(argv)

    try:
        return _process(args)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        _clear_quietly(args.out_dir)
        _write_failure(args.out_dir, "input_error", str(exc), args.report.name)
        return EXIT_INPUT_ERROR
    except Exception as exc:  # fail closed on anything unexpected
        print(f"internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        _clear_quietly(args.out_dir)
        _write_failure(args.out_dir, "internal_error", f"{type(exc).__name__}: {exc}",
                       args.report.name)
        return EXIT_INTERNAL_ERROR


def _clear_quietly(out_dir: Path) -> None:
    try:
        clear_outputs(out_dir)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(run())
