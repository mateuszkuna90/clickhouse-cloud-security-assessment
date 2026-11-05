Repeated npm audit --json on the unchanged app/ lockfile (sha256 7c40b154...), npm 11.20.0, 2026-11-03
Baseline (reports/baseline/npm-audit.json, 15:19:38Z): 26 packages, 47 unique advisories, GHSA-f23m-r3pf-42rh present (lodash range <=4.17.23)
Remediation rerun (16:04-16:05Z): GHSA-f23m present in all audit JSON
Runs below (16:13Z): 8 of 8 without GHSA-f23m:
  run 1: exit 1, metadata {"info":0,"low":3,"moderate":5,"high":8,"critical":10,"total":26} unique advisories 46 GHSA-f23m present: false
  run 2: exit 1, metadata {"info":0,"low":3,"moderate":5,"high":8,"critical":10,"total":26} unique advisories 46 GHSA-f23m present: false
  run 3: exit 1, metadata {"info":0,"low":3,"moderate":5,"high":8,"critical":10,"total":26} unique advisories 46 GHSA-f23m present: false
  run 4: exit 1, metadata {"info":0,"low":3,"moderate":5,"high":8,"critical":10,"total":26} unique advisories 46 GHSA-f23m present: false
  run 5: exit 1, metadata {"info":0,"low":3,"moderate":5,"high":8,"critical":10,"total":26} unique advisories 46 GHSA-f23m present: false
  run 6: exit 1, metadata {"info":0,"low":3,"moderate":5,"high":8,"critical":10,"total":26} unique advisories 46 GHSA-f23m present: false
  run 7: exit 1, metadata {"info":0,"low":3,"moderate":5,"high":8,"critical":10,"total":26} unique advisories 46 GHSA-f23m present: false
  run 8: exit 1, metadata {"info":0,"low":3,"moderate":5,"high":8,"critical":10,"total":26} unique advisories 46 GHSA-f23m present: false
Cause (github.com/advisories/GHSA-f23m-r3pf-42rh, fetched 2026-11-03): advisory last updated Nov 3, 2026; lodash affected range now '= 4.17.23', so lodash 4.17.10 no longer matches.
Only difference vs baseline JSON: GHSA-f23m removed from lodash.via (diff checked).
