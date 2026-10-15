# Mobile app package intake and static analysis

A reusable workflow for acquiring an authorized Android APK or Apple IPA, preserving provenance, extracting package metadata, and analyzing code/resources without running the app. The helper scripts use Python 3.9+ and the standard library.

Start with the [mobile app package analysis skill](skills/mobile-app-package-analysis/SKILL.md). It covers App Store and Android package acquisition, APK/IPA static analysis, evidence-based UI and monetization analysis, and optional tools explored for this workflow. Use the [report template](templates/static-analysis-report.md) to record findings.

## Helpers

- scripts/fetch_package.py downloads a direct HTTPS asset without echoing its URL, checks that it is a valid ZIP-based package, and records its SHA-256.
- scripts/inspect_package.py safely extracts an APK, IPA, APKM, or XAPK into a new analysis directory and writes a metadata and archive-inventory report.

Example:

~~~sh
python3 scripts/fetch_package.py work/apks/sample.ipa
python3 scripts/inspect_package.py work/apks/sample.ipa work/analysis/sample
~~~

The fetch helper asks for the URL without echoing it. The inspect helper refuses to overwrite an existing analysis directory.

## Boundaries

Use official or user-authorized sources and accounts. Do not commit app packages, signed download URLs, account tokens, extracted user data, or full proprietary string dumps. Static resources and strings indicate possible UI states; they do not prove a user saw a screen. Do not bypass App Store DRM, purchase checks, authentication, or server controls.
