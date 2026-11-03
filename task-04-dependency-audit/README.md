# Task 04 — Third-Party Dependency Security Audit

A vulnerability audit of the Node.js `package.json` supplied in the
assessment brief, using `npm audit`. It covers the high/critical
analysis, remediation options checked by re-running the audit, and a
Python script that turns the audit output into JSON and CSV reports.

> **Every number here is from npm's output on 2026-11-03.** `npm audit`
> results depend on two things: the resolved dependency tree (here
> [app/package-lock.json](app/package-lock.json)) and the GitHub Advisory
> Database at scan time. The same `package.json` can give different results
> on another day, because new advisories are published and caret ranges
> (`^1.19.0`) can resolve to newer versions.

## Contents

1. [Requirements](#1-requirements)
2. [Methodology](#2-methodology)
3. [Tool versions and scan date](#3-tool-versions-and-scan-date)
4. [Baseline dependencies](#4-baseline-dependencies)
5. [Findings](#5-findings)
6. [High and critical analysis](#6-high-and-critical-analysis)
7. [Remediation](#7-remediation)
8. [How many issues can be fixed](#8-how-many-issues-can-be-fixed)
9. [Remaining risks and limitations](#9-remaining-risks-and-limitations)
10. [Reproducing the scan](#10-reproducing-the-scan)
11. [Python reporting script](#11-python-reporting-script)
12. [Validation evidence](#12-validation-evidence)
13. [Files](#13-files)

---

## 1. Requirements

From the assessment brief (section 4, *Third-Party Dependency Security Audit*):

> You are given a package.json file containing dependencies for a Node.js
> application. Your task is to scan it for vulnerabilities, analyze the
> results, and provide security recommendations.
>
> 1. Analyze the given package.json to identify security vulnerabilities.
> 2. Use at least one vulnerability scanning tool, such as: npm audit,
>    yarn audit, snyk test, OWASP Dependency-Check.
> 3. Document:
>    - The list of detected vulnerabilities (high/critical priority).
>    - Which dependencies are vulnerable.
>    - How to fix the issues (e.g., updating the package, replacing dependencies).
>    - How many issues can be fixed.
> 4. Bonus: Automate the scan with a Python or Go script that:
>    - Parses the vulnerabilities.
>    - Generates a CSV or JSON report.
>
> Expected deliverables: a list of vulnerabilities (e.g. "Lodash prototype
> pollution vulnerability in version 4.17.10"), remediation steps (e.g.
> "Upgrade lodash to 4.17.21"), and a script (optional bonus) to automate
> vulnerability reporting.

The supplied `package.json` is reproduced unchanged in
[app/package.json](app/package.json). No packages or versions were added.

## 2. Methodology

1. **Reproduce the input.** Copy the brief's `package.json` exactly. The
   brief has no lockfile, so one was generated **without installing
   anything and without running lifecycle scripts**:
   `npm install --package-lock-only --ignore-scripts --no-audit`. No
   `node_modules/` was created at any point. [app/.npmrc](app/.npmrc) sets
   `ignore-scripts=true` as a second safeguard.
2. **Scan.** `npm audit --json` (all dependencies) and
   `npm audit --omit=dev --json` (production only). The raw JSON is kept in
   [reports/baseline/](reports/baseline/).
3. **Separate scanner errors from findings.** `npm audit` exits `1` when it
   finds vulnerabilities. Both runs exited `1` with an **empty stderr** and a
   valid report (`auditReportVersion: 2`), so exit code 1 here means
   "findings", not "scan failed". A failed scan returns an `{"error": …}`
   object, which the Python script reports separately (exit code 3).
4. **Analyse.** Read each package's `severity`, `isDirect`, `via`
   (its own advisories or the dependency it inherits from), `nodes` and
   `fixAvailable`. Resolved versions and dependency chains come from the
   lockfile and `npm ls --package-lock-only`.
5. **Check remediation without touching the baseline.** Every fix was
   applied to a **throwaway copy** of `package.json` + lockfile in a temp
   directory outside the repository (lockfile-only, scripts disabled), then
   audited again. [scripts/run-remediation-scenarios.sh](scripts/run-remediation-scenarios.sh)
   does this for all scenarios and keeps the resulting `package.json`,
   `package-lock.json`, audit JSON, commands with exit codes, and hashes
   (§7.2). `npm audit fix` was **never** run against [app/](app/); the script
   checks the baseline hashes before and after.
6. **Report.** [scripts/npm_audit_report.py](scripts/npm_audit_report.py)
   produced the JSON/CSV in [reports/generated/](reports/generated/) and
   checked that its counts match npm's own totals.

## 3. Tool versions and scan date

| Item | Value |
|---|---|
| Scan date (UTC) | 2026-11-03T15:19:38Z |
| Node.js | v26.13.0 |
| npm (and `npm audit`) | 11.20.0 |
| Python | 3.11.2 |
| Registry / advisory source | `https://registry.npmjs.org/` (npm bulk advisory endpoint, GitHub Advisory Database) |
| OS | Windows 11 Home 10.0.26200 |

Recorded in [reports/evidence/tool-versions.txt](reports/evidence/tool-versions.txt).

## 4. Baseline dependencies

| Package | Declared | Resolved | Type | npm audit result |
|---|---|---|---|---|
| body-parser | `^1.19.0` | 1.20.9 | prod | no advisories |
| dotenv | `^8.2.0` | 8.6.0 | prod | no advisories |
| express | `4.15.0` (exact) | 4.15.0 | prod | **critical** (inherited) |
| lodash | `4.17.10` (exact) | 4.17.10 | prod | **critical** |
| jsonwebtoken | `8.1.0` (exact) | 8.1.0 | prod | **high** |
| mongoose | `^4.2.4` | 4.13.21 | prod | **critical** |
| mocha | `5.0.5` (exact) | 5.0.5 | dev | **critical** (inherited) |

The lockfile resolves 149 packages (128 prod, 22 dev, per npm's metadata).
None declares an install script (`hasInstallScript`), and every entry has an
`integrity` hash and a `registry.npmjs.org` source
([reports/evidence/lockfile-checks.txt](reports/evidence/lockfile-checks.txt)).

## 5. Findings

### 5.1 Totals

npm counts **vulnerable packages**, not advisories. One package can carry
several advisories, and a package can also be flagged only because a
dependency below it is vulnerable ("inherited").

| Measure | All deps | Prod only (`--omit=dev`) |
|---|---|---|
| Vulnerable packages | **26** | 20 |
| — critical | **10** | 7 |
| — high | **8** | 8 |
| — moderate | 5 | 3 |
| — low | 3 | 2 |
| Direct / transitive packages | 5 / 21 | — |
| Unique advisories (GHSA) | **47** | 43 |
| — critical / high / moderate / low | 7 / 18 / 16 / 6 | — |
| High + critical packages | **18** | 15 |

The 6 packages that appear only in the full scan (diff, glob, minimatch,
minimist, mkdirp, mocha) all come from the `mocha` dev dependency.

### 5.2 All 26 vulnerable packages

Full detail, with every advisory URL, is in
[reports/generated/baseline/audit-packages.csv](reports/generated/baseline/audit-packages.csv).

| Package | Installed | Severity | Direct | Own advisories | Flagged via | npm fix |
|---|---|---|---|---|---|---|
| bson | 1.0.9 | critical | no | 2 | — | mongoose 9.11.4 (major) |
| express | 4.15.0 | critical | **yes** | 2 | cookie, debug, fresh, path-to-regexp, proxy-addr, qs, send, serve-static | express 4.22.3 |
| lodash | 4.17.10 | critical | **yes** | 9 | — | lodash 4.18.1 |
| minimist | 0.0.8 | critical | no (dev) | 2 | — | mocha 12.0.3 (major) |
| mkdirp | 0.5.1 | critical | no (dev) | 0 | minimist | mocha 12.0.3 (major) |
| mocha | 5.0.5 | critical | **yes** (dev) | 0 | diff, glob, mkdirp | mocha 12.0.3 (major) |
| mongodb | 2.2.34 | critical | no | 1 | mongodb-core | mongoose 9.11.4 (major) |
| mongodb-core | 2.1.18 | critical | no | 0 | bson | mongoose 9.11.4 (major) |
| mongoose | 4.13.21 | critical | **yes** | 7 | async, bson, mongodb, mpath, mquery | mongoose 9.11.4 (major) |
| proxy-addr | 1.1.5 | critical | no | 1 | — | express 4.22.3 |
| async | 2.6.0 | high | no | 1 | — | mongoose 9.11.4 (major) |
| debug | 2.6.1 | high | no | 2 | ms | express 4.22.3 |
| fresh | 0.5.0 | high | no | 1 | — | express 4.22.3 |
| jsonwebtoken | 8.1.0 | high | **yes** | 3 | — | jsonwebtoken 9.0.3 (major) |
| mime | 1.3.4 | high | no | 1 | — | express 4.22.3 |
| path-to-regexp | 0.1.7 | high | no | 3 | — | express 4.22.3 |
| qs | 6.3.1 | high | no | 4 | — | express 4.22.3 |
| send | 0.15.0 | high | no | 1 | debug, fresh, mime, ms | express 4.22.3 |
| glob | 7.1.2 | moderate | no (dev) | 0 | minimatch | mocha 12.0.3 (major) |
| minimatch | 3.1.5 | moderate | no (dev) | 1 | — | mocha 12.0.3 (major) |
| mpath | 0.5.1 | moderate | no | 1 | — | mongoose 9.11.4 (major) |
| mquery | 2.3.3 | moderate | no | 1 | — | mongoose 9.11.4 (major) |
| ms | 0.7.2 | moderate | no | 1 | — | express 4.22.3 |
| cookie | 0.3.1 | low | no | 1 | — | express 4.22.3 |
| diff | 3.5.0 | low | no (dev) | 1 | — | mocha 12.0.3 (major) |
| serve-static | 1.12.0 | low | no | 1 | send | express 4.22.3 |

"Own advisories" are advisories against that package. Where a package's
rating is higher than any of its own advisories (express, send, mongodb,
mkdirp, mocha, mongodb-core), npm has passed up the severity of a
vulnerable dependency. The fix still has to happen through that package.

Not affected at this scan date: **body-parser 1.20.9** (its own `qs@6.16.2`
and `debug@2.6.9` are not flagged) and **dotenv 8.6.0**.

## 6. High and critical analysis

Advisory IDs, titles, severities, CVSS scores and URLs below are copied from
the npm audit JSON. npm's v2 report gives GHSA IDs, not CVE IDs, so no CVE
numbers are listed. The impact notes explain the advisory class for this
dependency set. No application code was supplied, so **reachability was not
assessed**: every finding is treated as potentially reachable.

The analysis is grouped by the direct dependency that has to change, since
that is the unit of remediation.

### 6.1 lodash 4.17.10 (direct, prod) — critical

Chain: `vulnerable-node-app > lodash@4.17.10`

| Advisory | Sev. | CVSS | Title (from npm) | Affected |
|---|---|---|---|---|
| [GHSA-jf85-cpcp-j695](https://github.com/advisories/GHSA-jf85-cpcp-j695) | critical | 9.1 | Prototype Pollution in lodash | <4.17.12 |
| [GHSA-35jh-r3h4-6jhm](https://github.com/advisories/GHSA-35jh-r3h4-6jhm) | high | 7.2 | Command Injection in lodash | <4.17.21 |
| [GHSA-4xc9-xhrj-v574](https://github.com/advisories/GHSA-4xc9-xhrj-v574) | high | — | Prototype Pollution in lodash | <4.17.11 |
| [GHSA-p6mc-m468-83gw](https://github.com/advisories/GHSA-p6mc-m468-83gw) | high | 7.4 | Prototype Pollution in lodash | >=3.7.0 <4.17.19 |
| [GHSA-r5fr-rjxr-66jc](https://github.com/advisories/GHSA-r5fr-rjxr-66jc) | high | 8.1 | lodash vulnerable to Code Injection via `_.template` imports key names | >=4.0.0 <=4.17.23 |

Also 4 moderate: GHSA-29mw-wpgm-hmr9 and GHSA-x5rq-j2xg-h7qm (ReDoS),
GHSA-f23m-r3pf-42rh and GHSA-xxjr-mmjv-4gpg (prototype pollution in
`_.unset` / `_.omit`).

**Impact.** Prototype pollution lets attacker-controlled keys such as
`__proto__` or `constructor.prototype`, passed to deep-merge or path
functions, add properties to `Object.prototype` for the whole process.
This can bypass authorisation checks or cause denial of service, and
sometimes leads to code execution. The `_.template` issues are code
injection if template input or options come from a user.

**Fix.** Upgrade to **lodash 4.18.1** (npm's `fixAvailable`, not
semver-major). Note that the brief's example target, **4.17.21, is no
longer enough** at this scan date: GHSA-r5fr-rjxr-66jc (high) affects
`<=4.17.23` and GHSA-xxjr-mmjv-4gpg affects `<=4.17.22`.
(GHSA-f23m-r3pf-42rh also listed `<=4.17.23` at scan time, but was narrowed
later that day; see §9.) Because `package.json` pins
`4.17.10` exactly, the pin itself has to be changed. Verified in §7.

### 6.2 express 4.15.0 (direct, prod) — critical (inherited); 7 high/critical transitive packages, 8 including express

Express's own advisories are low/moderate
([GHSA-qw6h-vgh9-j6wx](https://github.com/advisories/GHSA-qw6h-vgh9-j6wx)
XSS via `res.redirect()`;
[GHSA-rv95-896h-c2vc](https://github.com/advisories/GHSA-rv95-896h-c2vc)
open redirect). It is rated critical because of the packages it bundles.
The 7 high/critical transitive packages are proxy-addr, qs, path-to-regexp,
debug, fresh, mime and send:

| Package | Installed | Chain | Advisory | Sev. | CVSS | Title (from npm) |
|---|---|---|---|---|---|---|
| proxy-addr | 1.1.5 | express > proxy-addr | [GHSA-jqcg-44mw-7w3h](https://github.com/advisories/GHSA-jqcg-44mw-7w3h) | critical | 9.1 | proxy-addr vulnerable to IP spoofing via IPv4-mapped IPv6 trust subnet |
| qs | 6.3.1 | express > qs | [GHSA-gqgv-6jq5-jjj9](https://github.com/advisories/GHSA-gqgv-6jq5-jjj9) | high | 7.5 | Prototype Pollution Protection Bypass in qs |
| | | | [GHSA-hrpp-h998-j3pp](https://github.com/advisories/GHSA-hrpp-h998-j3pp) | high | 7.5 | qs vulnerable to Prototype Pollution |
| path-to-regexp | 0.1.7 | express > path-to-regexp | [GHSA-9wv6-86v2-598j](https://github.com/advisories/GHSA-9wv6-86v2-598j) | high | 7.5 | path-to-regexp outputs backtracking regular expressions |
| | | | [GHSA-rhx6-c78j-4q9w](https://github.com/advisories/GHSA-rhx6-c78j-4q9w) | high | 7.5 | path-to-regexp contains a ReDoS |
| | | | [GHSA-37ch-88jc-xwx2](https://github.com/advisories/GHSA-37ch-88jc-xwx2) | high | 7.5 | path-to-regexp vulnerable to Regular Expression Denial of Service via multiple route parameters |
| debug | 2.6.1 | express > debug; express > send > debug | [GHSA-9vvw-cc9w-f27h](https://github.com/advisories/GHSA-9vvw-cc9w-f27h) | high | 7.5 | debug Inefficient Regular Expression Complexity vulnerability |
| fresh | 0.5.0 | express > fresh; express > send > fresh | [GHSA-9qj9-36jm-prpv](https://github.com/advisories/GHSA-9qj9-36jm-prpv) | high | 7.5 | Regular Expression Denial of Service in fresh |
| mime | 1.3.4 | express > send > mime | [GHSA-wrvr-8mpx-r7pp](https://github.com/advisories/GHSA-wrvr-8mpx-r7pp) | high | 7.5 | mime Regular Expression Denial of Service when MIME lookup performed on untrusted user input |
| send | 0.15.0 | express > send; express > serve-static > send | [GHSA-m6fv-jmcg-4jfg](https://github.com/advisories/GHSA-m6fv-jmcg-4jfg) | low | 5.0 | send vulnerable to template injection that can lead to XSS |

send is rated **high** only through debug, fresh, mime and ms; its own
advisory is low. qs also has 2 moderate DoS advisories (GHSA-6rw7-vpxm-498p,
GHSA-4mjr-xmp4-gh2g). The lower-severity members of this chain are
cookie, ms and serve-static.

**Impact.** These packages run on **every HTTP request** before application
code, so they are the most exposed part of the tree:

- **proxy-addr** decides `req.ip` when `trust proxy` is set. Spoofing it
  defeats IP allow-lists, rate limits and audit logging.
- **qs** parses the query string into `req.query`. Prototype pollution from
  a URL affects the whole process.
- **path-to-regexp, fresh, mime, debug** — regular-expression denial of
  service. A crafted path, header or value pins a CPU core, and Node's single
  event loop then stalls every other request.

**Fix.** Upgrade to **express 4.22.3** (npm's `fixAvailable`, same major).
This pulls in proxy-addr 2.0.8, qs 6.16.2, path-to-regexp 0.1.13,
send 0.19.2, serve-static 1.16.3, fresh 0.5.2, mime 1.6.0, debug 2.6.9,
cookie 0.7.2 (resolved versions verified in the remediated lockfile). The
exact `4.15.0` pin must be changed. This is not a major version bump, but
4.15 → 4.22 covers several years of releases. Run the app's tests for
behaviour changes such as `res.redirect` encoding and query parsing.
Express 5 is an alternative long-term target but needs code migration.

### 6.3 mongoose ^4.2.4 → 4.13.21 (direct, prod) — critical; 4 high/critical transitive packages, 5 including mongoose

The 4 high/critical transitive packages are bson, mongodb, mongodb-core and
async.

| Package | Installed | Chain | Advisory | Sev. | CVSS | Title (from npm) |
|---|---|---|---|---|---|---|
| mongoose | 4.13.21 | direct | [GHSA-9m93-w8w6-76hh](https://github.com/advisories/GHSA-9m93-w8w6-76hh) | critical | 10 | Mongoose Prototype Pollution vulnerability |
| | | | [GHSA-h8hf-x3f4-xwgp](https://github.com/advisories/GHSA-h8hf-x3f4-xwgp) | critical | 9.8 | Mongoose Vulnerable to Prototype Pollution in Schema Object |
| | | | [GHSA-vg7j-7cwx-8wgw](https://github.com/advisories/GHSA-vg7j-7cwx-8wgw) | critical | 9.0 | Mongoose search injection vulnerability |
| | | | [GHSA-m7xq-9374-9rvx](https://github.com/advisories/GHSA-m7xq-9374-9rvx) | high | 9.8 | Mongoose search injection vulnerability |
| | | | [GHSA-f825-f98c-gj3g](https://github.com/advisories/GHSA-f825-f98c-gj3g) | high | 7.0 | automattic/mongoose vulnerable to Prototype pollution via Schema.path |
| | | | [GHSA-wpg9-53fq-2r8h](https://github.com/advisories/GHSA-wpg9-53fq-2r8h) | high | 7.5 | Mongoose's Improper Sanitization of $nor in sanitizeFilter May Allow NoSQL Injection |
| bson | 1.0.9 | mongoose > bson; mongoose > mongodb > mongodb-core > bson | [GHSA-v8w9-2789-6hhr](https://github.com/advisories/GHSA-v8w9-2789-6hhr) | critical | 9.8 | Deserialization of Untrusted Data in bson |
| mongodb | 2.2.34 | mongoose > mongodb | [GHSA-mh5c-679w-hh4r](https://github.com/advisories/GHSA-mh5c-679w-hh4r) | high (rated critical via bson) | — | Denial of Service in mongodb |
| mongodb-core | 2.1.18 | mongoose > mongodb > mongodb-core | inherited from bson | critical | — | — |
| async | 2.6.0 | mongoose > async | [GHSA-fwr7-v2mv-hh25](https://github.com/advisories/GHSA-fwr7-v2mv-hh25) | high | 7.8 | Prototype Pollution in async |

The two search-injection advisories cover `<6.13.6` (GHSA-vg7j) and
`>=3.6.0-rc0 <5.13.23` (GHSA-m7xq). Also moderate: mongoose GHSA-664h-wqgq-64gw, bson GHSA-4jwp-vfvf-657p,
mpath GHSA-p92x-r36w-9395, mquery GHSA-45q2-34rf-mr94.

**Impact.** This is the data-access layer. "Search injection" and the
`$nor` sanitisation bypass are **NoSQL injection**: request data passed
into a query filter can change what the query matches, for example
`{"$ne": null}` matching every user, and can read or change other users'
records. (GHSA-wpg9 is a bypass of the `sanitizeFilter` option, which
4.13.21 does not have. npm flags it by version range. On 4.13.21 there is
no built-in filter sanitisation to bypass in the first place.) Prototype
pollution in schema and update paths can affect the
whole process. The bson issues concern deserialising untrusted BSON/objects
in the driver. async's advisory has a local attack vector
(`AV:L`, CVSS 7.8), so it is less exposed.

**Fix.** npm's only fix is **mongoose 9.11.4, a semver-major upgrade across
five majors** (4 → 9). It replaces the MongoDB driver (mongodb 2.2.34 →
7.7.0, bson 1.0.9 → 7.3.3), requires **Node.js ≥ 20.19.0** (lockfile
`engines`), and needs a supported MongoDB server version. Expect API
migration work: callbacks are removed in favour of promises, plus changes
to connection options and query behaviour. Plan it as a project: upgrade
one major at a time following Mongoose's migration guides, with integration
tests against a real MongoDB.

**Interim controls while still on 4.13.21 (not remediation).** Mongoose's
`sanitizeFilter` option is **not available** in 4.13.21: it is absent from
the 4.13.21 package and present in 6.0.0 (checked by searching both
published tarballs, fetched with `npm pack`, which runs no package code). It
cannot be used as a stop-gap here. What does work on any version is
application-side input handling for the NoSQL-injection advisories:

- Build queries in server code from an **allow-list** of fields and
  operators. Never pass `req.body`, `req.query` or parsed JSON directly as a
  filter, update or projection object.
- **Validate and normalise scalars**: if a field should be a string, an
  ObjectId or a number, check its type and convert it before it reaches a
  query. Reject values of the wrong type rather than coercing them.
- **Reject unexpected objects and operators**: refuse any request value that
  is an object or array where a scalar is expected, and any key that starts
  with `$` or contains `.`, `__proto__`, `constructor` or `prototype`.

These controls **reduce exposure to some** of the advisories (query/search
injection where user input reaches a filter). They **do not fix** the
prototype-pollution issues inside Mongoose's schema and casting code, the
bson deserialisation issues, or the mongodb/async advisories, and npm audit
will still report all of them. The only remediation verified here is the
upgrade (scenario C, §7.2).

### 6.4 jsonwebtoken 8.1.0 (direct, prod) — high

Chain: `vulnerable-node-app > jsonwebtoken@8.1.0`

| Advisory | Sev. | CVSS | Title (from npm) | Affected |
|---|---|---|---|---|
| [GHSA-8cf7-32gw-wr33](https://github.com/advisories/GHSA-8cf7-32gw-wr33) | high | 8.1 | jsonwebtoken unrestricted key type could lead to legacy keys usage | <=8.5.1 |
| [GHSA-hjrf-2m68-5959](https://github.com/advisories/GHSA-hjrf-2m68-5959) | moderate | 5.0 | jsonwebtoken's insecure implementation of key retrieval function could lead to Forgeable Public/Private Tokens from RSA to HMAC | <=8.5.1 |
| [GHSA-qwph-4952-7xr6](https://github.com/advisories/GHSA-qwph-4952-7xr6) | moderate | 6.4 | jsonwebtoken vulnerable to signature validation bypass due to insecure default algorithm in jwt.verify() | <9.0.0 |

**Impact.** This library guards authentication, but each advisory needs a
specific misuse to be exploitable. Merely using 8.1.0, or omitting
`algorithms` on its own, does not make tokens forgeable. Per the GitHub
advisories (fetched 2026-11-03):

- **GHSA-hjrf-2m68-5959 (CVE-2022-23541), RSA→HMAC algorithm confusion.**
  Exploitable when the application passes a **key-retrieval function** as
  `secretOrPublicKey` and that function serves **both symmetric and
  asymmetric keys**. Then a token signed with HS256, using the RSA public
  key as the HMAC secret, can verify, i.e. forged tokens are accepted.
- **GHSA-qwph-4952-7xr6 (CVE-2022-23540), "none" algorithm bypass.** A
  separate issue. Per the advisory, all three must be true: an **unsigned
  token** is received, **no `algorithms`** are given to `verify()`, and a
  **falsy secret or key** (`null`, `undefined`, `false`) is passed, for
  example because a key lookup failed silently.
- **GHSA-8cf7-32gw-wr33 (CVE-2022-23539), legacy key types.** Not algorithm
  confusion: the library does not check that the key type matches the
  algorithm, so weak or legacy keys (the advisory's example is a DSA key
  with RS256) can be used for verification.

Without the application code we cannot say whether any of these
preconditions hold. They are treated as potential authentication-bypass
risks.

**Fix.** Upgrade to **jsonwebtoken 9.0.3** (semver-major; the advisories
name 9.0.0 as the patched version). v9 removes the default `none` support
and restricts key types to the algorithms they belong to. Code that relied
on the old behaviour will fail, which is the intended effect. On any
version, also pass an explicit allow-list such as `algorithms: ['RS256']`
to `jwt.verify`, use one key type per verification path, and fail closed
if key lookup returns nothing.

### 6.5 mocha 5.0.5 (direct, **dev only**) — critical (inherited)

| Package | Installed | Chain | Advisory | Sev. | CVSS | Title (from npm) |
|---|---|---|---|---|---|---|
| minimist | 0.0.8 | mocha > mkdirp > minimist | [GHSA-xvch-5gv4-984h](https://github.com/advisories/GHSA-xvch-5gv4-984h) | critical | 9.8 | Prototype Pollution in minimist |
| mkdirp | 0.5.1 | mocha > mkdirp | inherited from minimist | critical | — | — |
| mocha | 5.0.5 | direct (dev) | inherited from diff, glob, mkdirp | critical | — | — |

Also minimist GHSA-vh95-rmgr-6w4m (moderate), minimatch GHSA-g3hv-75wg-m249
(moderate), diff GHSA-73rr-hh4g-fpgx (low).

**Impact.** This is test tooling. It is not in a production install
(`npm ci --omit=dev`), and minimist only parses mocha's own command-line
arguments. The real exposure is CI runners and developer machines, which
often hold credentials, so it still matters, but it is lower priority than
the production findings above.

**Fix.** Upgrade to **mocha 12.0.3** (semver-major, requires Node
`^20.19.0 || >=22.12.0`). Verified: removes all critical/high findings in
this chain. 3 moderate findings remain (§7, §9).

## 7. Remediation

### 7.1 Recommended changes, in priority order

| # | Change | Type | Removes (high/critical packages) |
|---|---|---|---|
| 1 | `express` `4.15.0` → `4.22.3` | same major, pin edit | express + 7 transitive: proxy-addr, qs, path-to-regexp, debug, fresh, mime, send (8) |
| 2 | `lodash` `4.17.10` → `4.18.1` | same major, pin edit | lodash (1) |
| 3 | `jsonwebtoken` `8.1.0` → `9.0.3`, and pass `algorithms` to `verify` | **major** | jsonwebtoken (1) |
| 4 | `mongoose` `^4.2.4` → `^9.11.4` (step through majors) | **major**, Node ≥ 20.19 | mongoose + 4 transitive: bson, mongodb, mongodb-core, async (5) |
| 5 | `mocha` `5.0.5` → `12.0.3` | **major**, dev only | mocha + 2 transitive: mkdirp, minimist (3) |

Steps 1 and 2 have low risk and fix the most exposed code (the HTTP request
path), so ship them first. Steps 3 and 4 need code changes and tests. The
counts in the last column add up to the 18 high/critical packages.

Supporting controls:

- Commit the lockfile and install with `npm ci --ignore-scripts` (or keep
  `ignore-scripts=true` in `.npmrc`).
- Production images: `npm ci --omit=dev`.
- Gate CI on `npm audit --audit-level=high` (or the Python script with
  `--fail-on high`).
- Enable Dependabot/Renovate for routine updates.
- Run `npm audit signatures` after install to check registry signatures and
  provenance.

No dependency needs **replacing**: every vulnerable package has a fixed
version in the same project.

### 7.2 What was tested, and the result

Each scenario was applied to a temporary copy (lockfile-only,
`--ignore-scripts`) and then **audited again with `npm audit --json`**.
These are measured results, not estimates.

The scenarios were run twice on 2026-11-03 with the same tools (Node
v26.13.0, npm 11.20.0, registry.npmjs.org):

- **Initial run** (shortly after the 15:19 UTC baseline scan):
  [reports/remediation/initial-run/](reports/remediation/initial-run/) keeps
  the audit JSON and `package.json` per scenario. Its lockfiles were not
  kept, so this run alone does not preserve the resolved trees.
- **Evidence rerun** (16:04–16:05 UTC) by
  [scripts/run-remediation-scenarios.sh](scripts/run-remediation-scenarios.sh):
  [reports/remediation/rerun-2026-11-03/](reports/remediation/rerun-2026-11-03/)
  keeps, for each scenario, the npm-resolved `package.json` and
  `package-lock.json`, `npm-audit.json` (+ stderr, empty), `commands.tsv`
  (every command and its exit code), `sha256.txt`, `direct-versions.txt` and
  the full npm output. `run-info.txt` records tool versions and confirms
  the baseline in [app/](app/) was unchanged (same SHA-256 before and after)
  and that no `node_modules/` was created. Each lockfile passed
  `npm ls --package-lock-only --all` and
  `npm ci --dry-run --ignore-scripts` (both exit 0).

**Difference between the runs:** none in the evidence. For every scenario,
the rerun's `npm-audit.json` and `package.json` are **byte-identical** to
the initial run's, and the baseline re-audit is byte-identical to
[reports/baseline/npm-audit.json](reports/baseline/npm-audit.json). A third
run into a scratch directory (about 16:07 UTC) produced identical JSON,
lockfiles and `commands.tsv` again, apart from npm's timings. In that third
run's scenario A text output (`npm audit fix`, not JSON), lodash advisory
GHSA-f23m-r3pf-42rh was missing. Its JSON audit still included it. This was
the first sign of the advisory update described in §9, after which current
audits no longer report that advisory.

| Scenario | package.json change | Lockfile SHA-256 (first 16) | Vulnerable packages | Critical | High | Moderate | Low |
|---|---|---|---|---|---|---|---|
| Baseline (re-audit) | — | `7c40b1545681450f` (= app/) | 26 | 10 | 8 | 5 | 3 |

| A. `npm audit fix` (no `--force`) | **none** | `7c40b1545681450f` (unchanged) | 26 | 10 | 8 | 5 | 3 |
| B. Pin bumps only: express 4.22.3, lodash 4.18.1 | 2 exact pins | `546ef71e657b531e` | **14** | 7 | 2 | 4 | 1 |
| C. `npm audit fix --force` | express ^4.22.3, lodash ^4.18.1, jsonwebtoken ^9.0.3, mongoose ^9.11.4, mocha ^12.0.3 | `2453f4b54505f05e` | **3** | **0** | **0** | 3 | 0 |
| D. C, then npm's suggested mocha 11.0.0 | as C, mocha 11.0.0 | `71b81604ba70d5f9` | 4 | 0 | **1** | 3 | 0 |

`npm audit fix` exits 1 in A and C because vulnerabilities remain after the
fix. The install and consistency commands all exit 0 (`commands.tsv`).

What this shows:

- **A changes nothing.** npm reports express and lodash as fixable without a
  major bump, but plain `npm audit fix` will not move an exact pin. Calling
  them "fixable with `npm audit fix`" would be wrong for this
  `package.json`.
- **B** removes exactly the 12 packages npm marked as non-major fixes
  (26 → 14). High/critical packages drop from 18 to 9.
- **C** removes every high and critical finding. The 3 that remain are
  moderate, dev-only, in mocha 12.0.3's dependencies (glob 13.0.6,
  minimatch 10.2.6).
- **D is rejected.** npm suggests "fixing" the remaining moderates by moving
  mocha to 11.0.0. That is a downgrade, and it adds
  `serialize-javascript` with a **high** advisory
  ([GHSA-5c6j-r48x-rmvq](https://github.com/advisories/GHSA-5c6j-r48x-rmvq)).
  So `fixAvailable` should not be applied blindly.

**Audit-confirmed vs untested.** The reductions above are confirmed by
`npm audit` on the npm-resolved lockfiles. Application compatibility is
**untested**: no application code or tests were supplied, and the breaking
upgrades in C (mongoose 4 → 9, jsonwebtoken 8 → 9, mocha 5 → 12) are certain
to need code changes. "Verified" in this report means verified by a second
`npm audit` run only.

## 8. How many issues can be fixed

Counted in vulnerable packages, the unit npm uses. Advisory counts are in
brackets.

| | All (26 pkgs / 47 adv.) | High + critical (18 pkgs / 25 adv.) |
|---|---|---|
| Fix available according to npm (baseline) | 26 | 18 |
| — without a semver-major upgrade (express, lodash) | 12 | 9 |
| — only with a semver-major upgrade | 14 | 9 |
| — no fix available | 0 | 0 |
| **Verified fixed**, non-major changes only (scenario B) | 12 | 9 |
| **Verified fixed**, including major upgrades (scenario C) | 23 | **18** |
| **Verified remaining** after scenario C | 3 moderate, dev-only | **0** |

For the 3 remaining moderates (glob, minimatch, and mocha flagged through
them), npm's only offered "fix" made things worse (scenario D). At this scan
date they have **no clean fix** and are accepted as dev-only residual risk.

## 9. Remaining risks and limitations

- **Point in time, and it already moved.** Results depend on the advisory
  database and the lockfile in [app/](app/). On the scan date itself,
  between about 16:07 and 16:12 UTC, GitHub updated
  [GHSA-f23m-r3pf-42rh](https://github.com/advisories/GHSA-f23m-r3pf-42rh)
  (moderate, lodash). Its lodash range changed from `<=4.17.23` to
  `=4.17.23`, so audits of the same lockfile after that no longer report it
  for lodash 4.17.10. Eight repeated audits at 16:13 UTC all gave
  **26 packages (10 critical, 8 high, 5 moderate, 3 low), 46 unique
  advisories instead of 47**. The JSON differs from the baseline only by
  that one advisory. High/critical results and every package-level count in
  this report are unaffected. The baseline and remediation evidence are
  kept as captured (they include the advisory). The later audit is saved
  separately in
  [reports/evidence/advisory-update-2026-11-03/](reports/evidence/advisory-update-2026-11-03/).
  Re-run the scan regularly; do not treat this report as permanent.
- **Remediation reproducibility.** The initial remediation run kept only
  audit JSON and manifests. The full resolved trees come from the evidence
  rerun 45 minutes later, whose audit JSON and manifests are byte-identical
  to the initial run's. That shows the same resolution, but it is not the
  original lockfile bytes.
- **One scanner.** Only `npm audit` was run. `osv-scanner`, `snyk`,
  `trivy`, `yarn` and OWASP Dependency-Check are **not installed** on this
  machine, so no cross-check against another database was done (none was
  installed without approval). `npm audit` only finds **published
  advisories**: it does not detect malicious packages, typosquatting,
  abandoned packages or licence problems.
- **No reachability analysis.** No application code was supplied, so we
  cannot say which vulnerable functions are actually called. Severities
  are npm's, not adjusted for context.
- **Functional impact not tested.** Upgrades were checked for security
  effect only (§7.2). The major upgrades need code migration and tests.
- **Residual dev findings.** After scenario C: glob GHSA-3g3m-2fjr-6pw4 and
  minimatch GHSA-g3hv-75wg-m249 (moderate), through mocha 12.0.3. Dev and CI
  only. Track for an upstream fix.
- **Old, unflagged packages.** dotenv resolves to 8.6.0, several majors
  behind current. It has no advisory at this date, which is not the same
  as being maintained or safe in future.
- **Floating ranges.** `body-parser`, `dotenv` and `mongoose` use `^` ranges.
  Without the committed lockfile, a later install may resolve different
  versions with different results.
- **Registry signatures not checked.** `npm audit signatures` needs an
  installed `node_modules/`. To avoid running untrusted package code, nothing
  was installed, so it was not run. Lockfile `integrity` hashes were checked
  for presence only.

## 10. Reproducing the scan

On Windows PowerShell use `npm.cmd` instead of `npm` and `py -3` instead of
`python3`. None of these commands creates `node_modules/` or runs package
scripts.

The committed evidence in `reports/baseline/` and `reports/remediation/` is
historical: **do not write new scan output over it.** Write each new scan
to a new directory and compare.

```sh
cd task-04-dependency-audit/app

# Lockfile consistency (both should exit 0)
npm ls --package-lock-only --all
npm ci --dry-run --ignore-scripts --no-audit

# Audit into a NEW directory. Exit code 1 + valid JSON + empty stderr =
# vulnerabilities found.
mkdir ../reports/scan-$(date -u +%Y%m%dT%H%M%SZ) && cd "$_"
npm --prefix ../../app audit --json            > npm-audit.json
npm --prefix ../../app audit --omit=dev --json > npm-audit-prod.json
cmp npm-audit.json ../baseline/npm-audit.json && echo "same as baseline"
```

A different result does not invalidate the baseline. It means the
advisory database (or, if the lockfile was regenerated, the resolved tree)
has changed since the scan. Record it as a new scan. This has already
happened once: from between about 16:07 and 16:12 UTC on the scan date, `cmp` reports a
difference because GHSA-f23m-r3pf-42rh was updated (§9).

> **PowerShell note:** depending on the PowerShell version, `>` may write
> UTF-16 or add a BOM. Use `| Out-File -Encoding utf8 <file>`, or run the
> commands from Git Bash. The Python script accepts UTF-8 with or without a
> BOM.

To repeat all remediation scenarios (A–D plus a baseline re-audit) with full
evidence, run from `task-04-dependency-audit/` in Git Bash or any POSIX
shell:

```sh
scripts/run-remediation-scenarios.sh reports/remediation/rerun-$(date -u +%Y-%m-%d-%H%M)
```

The script refuses to write into an existing directory (exit 2), so earlier
evidence is never overwritten. Set `NPM=npm.cmd` if plain `npm` does not
work in your shell.

## 11. Python reporting script

[scripts/npm_audit_report.py](scripts/npm_audit_report.py) reads a saved
`npm audit --json` file and writes:

- `audit-summary.json`: status, input SHA-256 and format, counts by
  severity (packages and unique advisories), direct/transitive split,
  fix-status counts (overall and for high/critical), npm's own totals, and
  the full per-package detail.
- `audit-packages.csv`: one row per vulnerable package. Columns:
  `package, severity, is_direct, installed_versions, vulnerable_range, nodes,
  advisory_count, advisory_ids, advisory_urls, advisory_titles,
  inherited_from, effects, fix_status, fix_package, fix_version,
  fix_is_semver_major`.

### Fail-closed validation

The whole report is validated **before** anything is counted or any
`--fail-on` gate is evaluated. Invalid evidence is never reported as a
result, clean or otherwise. A report is rejected (exit 2) if:

- it is not a JSON object, has no `auditReportVersion`, or the version is
  not the integer `2`. The npm 6 format is **rejected explicitly** (rerun
  with npm 7+). An `{"error": …}` object mixed with results is rejected;
- `vulnerabilities` or `metadata.vulnerabilities` is missing or the wrong
  type, a metadata count is not a non-negative integer, or `total` is not
  the sum of the severity counts;
- any entry is not an object, its `name` differs from its key, or a required
  field is missing or the wrong type: `severity` (must be one of `info`,
  `low`, `moderate`, `high`, `critical`), `isDirect` (bool), `range`,
  `nodes` (non-empty list), `effects` (list), `via` (non-empty list),
  `fixAvailable` (`true`, `false`, or an object with `name`, `version` and a
  boolean `isSemVerMajor`);
- an advisory in `via` lacks `source`, `title`, `url`, `range` or a valid
  `severity`, names a different package, or has a malformed `cvss`/`cwe`;
- the report is internally inconsistent: `via` names a package that is not
  in the report, `via` and `effects` do not point at each other, a package
  is rated lower than one of its own advisories, one advisory appears twice
  with different details, or the per-package counts differ from
  `metadata.vulnerabilities`;
- `--lockfile` is given and a reported node is not in it (report and
  lockfile do not belong together).

Only `cvss` and `cwe` are optional (npm does not always provide them); when
absent they are written as `null` / `[]`. The only derived value is the
GHSA ID, read from the advisory URL. A package's severity is **not**
required to equal the highest severity of its dependencies: in the real
reports npm rates `serve-static` low although `send` is high, so that rule
would reject genuine npm output.

### Exit codes and output contract

| Exit | Meaning | Files left in `--out-dir` |
|---|---|---|
| 0 | report generated (vulnerabilities may be present) | `audit-summary.json` (`status: ok`) + `audit-packages.csv` |
| 1 | report generated, a package is at or above `--fail-on` | same as 0 |
| 2 | invalid input, or output could not be written | `audit-summary.json` with `status: input_error` and the reason; **no CSV** |
| 3 | input is an npm error report: the scan itself failed | `audit-summary.json` with `status: scanner_error`; **no CSV** |
| 4 | unexpected internal error (fail closed) | `audit-summary.json` with `status: internal_error`; **no CSV** |

Existing `audit-summary.json` and `audit-packages.csv` are deleted **before**
the input is read, and new files are written atomically (temp file +
rename). A result from an earlier run can never sit next to a failed run.
If even the error summary cannot be written, the exit code is still
non-zero. **The exit code is authoritative.**

Other properties: standard library only (tested with Python 3.11.2); reads
files and never runs npm or package code; deterministic (sorted keys and
rows, no timestamps, `\n` line endings on every OS); CSV cells starting with
`= + - @` are prefixed with `'` against spreadsheet formula injection;
inputs over 50 MiB are rejected. "Fix status" is `non-breaking`, `breaking`
(semver-major) or `none`, exactly as npm reported it. As §7.2 shows,
"non-breaking" can still need an edit to `package.json`.

```sh
# from task-04-dependency-audit/   (Windows: py -3 instead of python3)
python3 scripts/npm_audit_report.py reports/baseline/npm-audit.json \
    --lockfile app/package-lock.json --out-dir reports/generated/baseline

# CI gate: exit 1 if any high or critical package, 2/3/4 if the evidence is bad
python3 scripts/npm_audit_report.py reports/baseline/npm-audit.json \
    --out-dir out --fail-on high
```

Actual output of the first command:

```text
26 vulnerable packages (critical 10, high 8, moderate 5, low 3, info 0); 47 unique advisories; fix status {'breaking': 14, 'non-breaking': 12}
```

The saved reports in [reports/generated/](reports/generated/) were produced
by this version of the script. A unit test regenerates all of them and
compares them **byte for byte**.

## 12. Validation evidence

All commands below were actually run on 2026-11-03. The output is real.

| Check | Command | Result |
|---|---|---|
| package.json valid JSON | `node -e "JSON.parse(...)"` | valid |
| Baseline lockfile matches package.json | `npm ls --package-lock-only --all` | exit 0 ([npm-ls.txt](reports/evidence/npm-ls.txt)) |
| Baseline lockfile installable | `npm ci --dry-run --ignore-scripts --no-audit` | exit 0, "added 149 packages" (dry run; no `node_modules/` created) ([npm-ci-dry-run.txt](reports/evidence/npm-ci-dry-run.txt)) |
| Lockfile hygiene | integrity / registry / install-script check | 149 entries, none missing integrity, all from registry.npmjs.org, no install scripts |
| Scenario lockfiles consistent | same two commands per scenario (`commands.tsv`) | exit 0 for all 5 |
| Baseline unchanged by experiments | SHA-256 of `app/` files before/after (`run-info.txt`) | unchanged |
| Rerun matches initial run | byte comparison of audit JSON and package.json | identical, all 5 scenarios |
| Current audit vs baseline (16:13 UTC) | 8 repeated `npm audit --json` + JSON diff | differs only by GHSA-f23m (advisory updated); package counts identical ([advisory-update-2026-11-03/](reports/evidence/advisory-update-2026-11-03/)) |
| Counts reconcile | strict validation against `metadata.vulnerabilities` | all 11 genuine reports pass |
| Saved reports reproducible | unit test regenerates `reports/generated/**` | byte-identical (10 report pairs) |
| Python unit tests | `py -3 -m unittest discover -s tests -v` | **38 tests, OK** (below) |
| Malformed-input regression | old vs new script, `--fail-on high` | see below |
| Whitespace | `git diff --check` (tracked) and `git diff --no-index --check` per untracked file | clean |
| Secrets | pattern grep (keys, tokens, private keys) + username/path grep over Task 4 | no matches |

Unit test run (Python 3.11.2, Windows):

```text
$ py -3 -m unittest discover -s tests -v
...
Ran 38 tests in 0.651s

OK
```

The tests cover: every fix-status variant; inherited vs own severity;
optional-field handling; lockfile version lookup and report/lockfile
mismatch; GHSA extraction; CSV columns and formula escaping; determinism
and LF line endings; `--fail-on`; a clean (zero-finding) report; and every
error path (missing, empty, malformed, non-object, unsupported or
float version, npm 6 format, invalid UTF-8, directory input, bad
lockfile, BOM input, malformed or mixed npm error object, npm scanner
error, unexpected internal exception). Each error-path test first plants a
stale `status: ok` summary and CSV, and checks that neither survives.

**Malformed-input regression.** [tests/fixtures/malformed/](tests/fixtures/malformed/)
holds 22 invalid reports, among them missing severity, array/object
severity, non-object entries, missing fields, inconsistent metadata, broken
`via`/`effects` links, and two reports where the malformed entry is the
**only** finding. Each is rejected with exit 2 under `--fail-on high`, and
also with `critical` and `info`. To show these tests catch the original
bug, the previous script version was recreated in a scratch directory and
run on the same fixtures
([reports/evidence/malformed-input-regression.txt](reports/evidence/malformed-input-regression.txt)):

| | Previous script | Current script |
|---|---|---|
| Accepted as `status: ok` | 18 of 22 | 0 |
| Crashed with `TypeError` (no summary) | 3 of 22 (array/object severity) | 0 |
| **Exit 0 under `--fail-on high`** (only finding malformed) | **2 of 2** | 0 (exit 2) |
| Rejected with exit 2 | 1 of 22 | 22 of 22 |

Running the new `MalformedReportTests` class against the previous script
gave `FAILED (failures=75, errors=12)`; against the current script it passes.

Test fixtures in [tests/fixtures/](tests/fixtures/) are synthetic
(`example-*`, fake package names, `example.invalid` URLs). No credentials
of any kind are used or stored in this task.

## 13. Files

```text
task-04-dependency-audit/
├── README.md
├── .gitignore                     # node_modules/, *.partial
├── app/
│   ├── package.json               # exactly as supplied in the brief
│   ├── package-lock.json          # generated lockfile-only, no scripts
│   └── .npmrc                     # ignore-scripts=true
├── reports/
│   ├── baseline/                  # raw npm audit JSON (+ stderr, empty)
│   ├── remediation/
│   │   ├── initial-run/           # first run: audit JSON + package.json per scenario (no lockfiles)
│   │   └── rerun-2026-11-03/      # full evidence per scenario: manifest, lockfile, audit,
│   │                              #   commands + exit codes, hashes, npm output, run-info.txt
│   ├── generated/                 # script output (JSON + CSV): baseline, baseline-prod,
│   │                              #   initial-run/*, rerun-2026-11-03/*
│   └── evidence/                  # tool versions, npm ls, npm ci --dry-run, lockfile checks,
│                                  #   malformed-input regression
├── scripts/
│   ├── npm_audit_report.py
│   └── run-remediation-scenarios.sh
└── tests/
    ├── test_npm_audit_report.py
    └── fixtures/                  # synthetic example-* inputs; malformed/ = invalid reports
```

The `initial-run/*` reports in `reports/generated/` were produced without
`--lockfile` because that run's lockfiles were not kept, so their
`installed_versions` are `null`. The `rerun-2026-11-03/*` reports include
installed versions from the preserved lockfiles. The resolved versions
quoted in §6 match those lockfiles.
