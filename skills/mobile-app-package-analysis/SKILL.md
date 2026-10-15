---
name: mobile-app-package-analysis
description: Acquire an authorized Android APK or Apple IPA, preserve source and hash metadata, and perform a fast static analysis of app code, UI resources, purchase flows, and user experience. Use for app package reverse engineering when the user supplies a package, official release link, store identifier, or authorized test build.
---

# Mobile app package acquisition and static analysis

## Goal

For each app, create a reproducible evidence trail from source to findings. Prefer static analysis first. Separate direct observations from inferences, and never claim that a string or feature name proves a screen was shown at runtime.

Work under a task directory such as work/apks/<app>/ and work/analysis/<app>/. Keep the original package immutable. Record the source, retrieval time, exact package filename, byte size, SHA-256, app identifier, version, and signature or encryption status when available.

## Scope and handling

- Analyze packages the user supplied or is authorized to obtain. Use official developer releases, the relevant app store with the user's account, or another source the user identifies and is entitled to use.
- Treat APKs, IPAs, archives, manifests, and extracted files as untrusted input. Start with read-only static inspection. Do not install or launch the app unless the user requests runtime analysis on a suitable test device or emulator.
- Do not bypass DRM, signature checks, store licensing, authentication, paywalls, or server controls. If an IPA's executable is encrypted, report that limit and continue with accessible metadata and resources.
- Never save account passwords, OAuth tokens, Apple credentials, Google Play auth tokens, or signed URL query strings in scripts, shell history, reports, or repository commits. Do not echo full signed URLs. A signed CDN URL can expire; preserve it exactly when fetching and request a fresh link if it has expired.
- Do not upload the APK/IPA, a complete extracted app, user data, or full proprietary localization/code dumps to a public repository. Publish only the reusable workflow and sanitized, minimal evidence needed for the task.
- A source page's claims about a “modded”, “unlocked”, or “ad-free” package are claims by that source. Check the downloaded bundle for added libraries, altered signatures, unexpected entitlements, and other modification evidence. Do not assume its UI reflects the official build.
- Do not perform purchase, account creation, or account login flows in a downloaded app as part of static analysis.

## 1. Acquire the package

First identify the source and package type. Do not claim that any tool can download every app: store licensing, regional availability, DRM, device compatibility, and source permissions constrain availability.

### Direct release or user-provided URL

For GitHub release assets or a fresh direct HTTPS URL, use scripts/fetch_package.py to avoid echoing signed query parameters:

~~~sh
python3 scripts/fetch_package.py work/apks/<app>.ipa
python3 scripts/fetch_package.py work/apks/<app>.apk
~~~

The helper reads the URL without displaying it, follows HTTPS redirects, checks the response is a ZIP archive, and reports the final host, byte count, and SHA-256. If a signed asset returns HTTP 403, 410, or 618, its link may have expired. Ask for a fresh exact URL; do not manually rebuild or decode the signed query string. Check the filename and digest before analysis.

For a public GitHub release when gh is available, downloading by repository and release pattern is also convenient:

~~~sh
gh release download <tag> --repo <owner>/<repo> --pattern '*.apk' --dir work/apks
~~~

For a user-supplied URL without a signed query string, curl --fail --location --output <file> <url> is a simple alternative. Avoid printing or logging a URL containing credentials or expiring query parameters.

### Android packages

Prefer the developer's release channel, Google Play through the user's authorized account, or a trusted open-source distribution such as F-Droid. apkeep can fetch from Google Play, APKPure, or F-Droid. Confirm its current options with apkeep --help; Google Play retrieval requires account authorization. Do not place tokens directly on a command line or in this repository.

For an F-Droid package, for example:

~~~sh
apkeep --app org.fdroid.fdroid --download-source f-droid work/apks
~~~

An .apkm or .xapk is a split-package archive, not a single APK. An .aab is a publishing bundle. Preserve the original, inventory nested APKs, and use bundle-aware tools rather than passing the archive to a single-APK decompiler.

### Apple packages

For an App Store package, use ipatool with the user's authorized Apple account:

~~~sh
ipatool search "App Name" --platform iphone
ipatool auth login
ipatool download --app-id <numeric-app-id> --platform iphone --output work/apks/<app>.ipa
~~~

Use ipatool list-versions --help and ipatool download --help to select a specific available version. The --purchase flag obtains a license if needed; do not use it unless the user explicitly authorizes a purchase. App Store downloads may be encrypted and device/store access is not universal.

A developer-provided IPA or user-provided GitHub release asset can be fetched directly with the helper above. Preserve the original .ipa; it is a ZIP package containing Payload/<App>.app.

### Candidate and version lookup

Use ipatool search and ipatool list-versions first for App Store records. A convenience page such as BetaDrop's App Store lookup can map an app name or App Store URL to a bundle ID and numeric App Store ID; that helps select the right record but does not provide an IPA.

For older builds, IPA Archive is an index of links into Archive.org collections, not a host or verification service. Other third-party catalogs can expose app names, bundle IDs, versions, and candidate download links, but listings do not establish publisher provenance, authorization, signature integrity, or whether the IPA was modified. Use them only as discovery leads; do not auto-download or treat their files as official. See references/mobile-package-source-catalog.md for the checked source-by-source assessment.

## 2. Intake and provenance

Run the inventory helper into a new, app-specific directory:

~~~sh
python3 scripts/inspect_package.py work/apks/<app>.apk work/analysis/<app>
python3 scripts/inspect_package.py work/apks/<app>.ipa work/analysis/<app>
~~~

It records SHA-256, archive inventory, package metadata when present, DEX/native-library counts, and safely extracts the archive. It refuses to overwrite an existing output directory. Keep intake metadata next to later reports.

For Android, record the application ID, version name/code, min/target SDK, signing-certificate digest, DEX count, and native .so files when tools permit. aapt dump badging, apkanalyzer, and apksigner verify --print-certs can provide extra facts. Compare a certificate only against a known trusted release; a valid signature alone does not prove the publisher is genuine.

For iOS, read Payload/<App>.app/Info.plist with Python plistlib or plutil. Record CFBundleIdentifier, short/build version, minimum OS, executable name, embedded frameworks, extensions, and signature details if available. On macOS, codesign -dv --verbose=4 <App.app> can expose signer metadata. Do not treat a failed signature check on a modified package as evidence about the official publisher.

## 3. Android static analysis

Use complementary views:

1. **Manifest, resources, and smali:** apktool d -f -o work/analysis/<app>/apktool work/apks/<app>.apk
2. **Java-like DEX reconstruction:** jadx -d work/analysis/<app>/jadx work/apks/<app>.apk
3. **Alternative DEX output:** dex-decompile -i work/apks/<app>.apk -d work/analysis/<app>/dex-decompile when installed. Use it to cross-check difficult classes, not as a substitute for evidence in the original DEX.
4. **Native libraries:** list lib/<abi>/*.so; use file, strings -a, readelf, Ghidra, or another compatible native analyzer.
5. **Search targeted evidence:** search decoded sources and resources with rg -n -i for terms suggested by the app, such as billing, subscription, trial, purchase, upgrade, paywall, ad, reward, heart, streak, notification, and feature names found in the manifest or code.
6. If Android SDK tools are unavailable, BetaDrop APK Inspector advertises client-side manifest and permission parsing in a browser. Treat this as a convenience parser, not a decompiler; the page says it checks only v1/JAR signature metadata, so use apksigner for complete signature verification. Prefer local tools for confidential samples.

Capture class/method names and file paths for each finding. Decompiled source is an approximation; validate important claims against the DEX, bytecode, resource, or a second decompiler view.

## 4. iOS static analysis

1. Extract with the intake helper, then inspect Payload/<App>.app/Info.plist, app extensions, Frameworks/, plug-ins, and embedded dylibs.
2. Identify the main executable from CFBundleExecutable. Inspect it and framework binaries with file and strings -a; search with rg -a -n -i. Review bundle resources such as .strings, .stringsdict, JSON, .xz, storyboards, nibs, and asset catalogs. Decompress known resource formats into a separate analysis directory before searching.
3. On macOS, use otool -L for linked libraries and otool -l to inspect Mach-O load commands. Check LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64 and report cryptid; do not attempt to defeat encryption. Linux tools may not understand Mach-O, so use Ghidra or another compatible parser for native code.
4. Search app and framework strings for concrete indicators: purchase-flow presenters, subscription/trial providers, ad mediation, offer screens, onboarding, cancellation flows, hearts/energy, streaks, reminders, referrals, and social features. Confirm with resource names and localized copy where possible.
5. Check for injected or unexpected libraries, frameworks, bundle identifiers, entitlements, and signing changes. Treat third-party mirror descriptions as unverified claims.

Strings and asset names establish that a flow or feature is present in the package, not that it is enabled for every user. Remote configuration, experiments, account state, region, server responses, and modifications can change the actual UI.

## 5. Analyze conversion, retention, and UX

Build an evidence table with columns finding, evidence, interpretation, confidence, and caveat. Keep direct observations separate from product interpretation.

Look for:

- **Acquisition/onboarding:** first-run steps, skipped steps, goal selection, account prompts, notification or tracking permissions, and when the first lesson begins.
- **Offer design:** trial duration, plan choices, annual versus monthly price framing, billing cadence, trial-end disclosures, reminder prompts, discounts, countdowns, family or crossgrade offers, and cancellation save flows.
- **Contextual conversion:** upgrade prompts attached to a locked feature, depleted energy/heart, missed reward, lesson completion, or another moment when the user is likely to value the benefit.
- **Free/paid exchange:** ads versus purchases, earnable currency, refill paths, ad-free or unlimited claims, and whether a lesson is interrupted.
- **Retention:** streaks, freezes/repairs, loss warnings, daily goals, reminders, smart notification timing, friend activity, leaderboards, quests, and reactivation flows.
- **Learning and usability:** lesson size, progress visibility, immediate correction, practice from mistakes, accessibility/localization, offline behavior, permission declines, and clear ways to defer an offer or exit.
- **Pressure points:** time-limited language, trial renewal/charge timing, scarcity, repeated prompts, loss aversion, confusing billing cadence, and whether “not now” or cancellation choices are available.

Quote only short, relevant UI strings. A string template such as “Offer ends in …” is evidence that timed-offer copy exists, not proof a countdown was active in the tested session. Describe both conversion value and user cost; do not call a design “dark pattern” without explaining the observed behavior and context.

## 6. Optional analysis stack

Install only what the target needs; do not make every tool a prerequisite.

- **Apkeep:** Android package acquisition from supported sources.
- **ipatool:** App Store metadata, version lookup, account-authorized downloads.
- **Apktool and JADX:** Android resources/smali plus Java-like DEX output.
- **Androguard dex-decompiler:** optional alternate Android DEX view.
- **Ghidra:** native ARM64 analysis when strings and decompilers are insufficient; open source.
- **REA:** terminal-oriented reverse-engineering workflows, including supported Android resource and native-analysis handoffs. Check rea capabilities and rea analyze --help; provider availability varies by host.
- **Open-ReverseLab:** optional local knowledge base/case workflow for organizing repeatable APK analysis. It is not required to decode a package.
- **mcp2cli:** expose an available MCP server as CLI subcommands; use mcp2cli --mcp-stdio "<server command>" --list and --search <term> to discover calls. Keep secrets in environment variables or secure configuration, never literal command history.
- **BetaDrop utilities:** optional App Store ID/bundle ID lookup and browser-side APK metadata parsing. They are convenience tools, not package sources or DEX decompilers; avoid sending confidential packages to a service.
- **IDA Pro MCP:** optional only when the user has a valid IDA Pro installation/license. It is not required for APK/IPA triage; use Ghidra or static strings/resources first.

If a requested server is available only over MCP, mcp2cli can make its tool calls convenient from shell scripts. Do not install or invoke a paid/proprietary provider unless it is available and authorized.

### Setup and official project references

Use official releases and current install docs; do not copy tool binaries into this repository. Basic installs for the orchestration tools are:

~~~sh
uv tool install mcp2cli
npm install --global rea-agents
git clone https://github.com/androguard/dex-decompiler.git
cd dex-decompiler
cargo build --release --bin dex-decompile
~~~

Project references:

- apkeep: https://github.com/EFForg/apkeep
- ipatool: https://github.com/majd/ipatool
- Apktool: https://github.com/iBotPeaches/Apktool
- JADX: https://github.com/skylot/jadx
- DEX decompiler: https://github.com/androguard/dex-decompiler
- REA: https://github.com/morluto/rea
- Open-ReverseLab: https://github.com/LING71671/open-reverselab
- mcp2cli: https://github.com/knowsuchagency/mcp2cli
- IDA Pro MCP (optional): https://github.com/mrexodia/ida-pro-mcp
- Ghidra: https://github.com/NationalSecurityAgency/ghidra

## 7. Report format

Finish with:

1. **Package identity:** source type, filename, SHA-256, size, package/bundle ID, version, and signature/encryption status.
2. **What was inspected:** tools and extracted locations; note whether the app was not run.
3. **Findings:** concise evidence-backed conversion, retention, and UX observations.
4. **Confidence and limits:** distinguish code/resource indicators from observed screens; note modified packages, missing symbols, encrypted executables, server experiments, and unverified mirror claims.
5. **Follow-up:** only concrete gaps that materially change the conclusion.

Never present a decompiler's inferred source as original developer source code. Label generated pseudocode and strings accurately.
