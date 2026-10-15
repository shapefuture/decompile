# Mobile package sources and supporting services

Reviewed on 2026-10-15 by reading public page metadata/text only; no IPA/APK binaries were downloaded from these catalogs. This is a source assessment for an analysis workflow, not an endorsement of every site or file. Page contents and access can change.

## Preferred routes

| Source | What it is useful for | Workflow decision |
|---|---|---|
| Official developer release or user-supplied artifact | Best route for a specific version and known provenance | Prefer it. Record the exact URL host, date, filename, and SHA-256. |
| Apple App Store with [ipatool](https://github.com/majd/ipatool) | Search, version metadata, and downloads available to the user's authorized account | Primary iOS route already covered in the skill. It does not provide every app or guarantee a decrypted executable. |
| Google Play through an authorized account / [F-Droid](https://f-droid.org/) for open-source apps | Android package acquisition | Use apkeep only with an authorized source/account. Verify package ID and signing certificate against a known trusted release. |
| [BetaDrop App Store lookup](https://betadrop.app/app-store/) | Convenience lookup for Apple bundle ID and numeric App Store ID; its page says it queries Apple's public iTunes endpoint | Optional identifier lookup. Prefer ipatool search or Apple's API when convenient. The lookup identifies an App Store record; it does not provide its IPA. |
| [IPA Archive](https://stuffed18.github.io/ipa-archive-updated/) | Searchable index of IPA records linked from Archive.org collections | Optional historical-version discovery only. Its README explicitly says the site does not host the apps and disclaims involvement in linked projects. Verify the actual linked source and package. |

## Secondary catalogs: discovery only, not trusted acquisition

These catalogs may help identify a candidate version or bundle ID, but the publisher, signing, modification history, and license are not established by the listing. Do not configure them as automatic download sources. If a user supplies a package from one of them and is authorized to analyze it, treat it as an untrusted, possibly modified sample and inspect the exact binary.

| Source | What was observed | Decision |
|---|---|---|
| [CyPwn IPA Library](https://ipa.cypwn.xyz/) | Its page advertises regular and TrollStore IPAs and provides repo feeds for sideloading clients. The feed includes app/version/size/download metadata; the page also has an “Injected Dylibs” field. | Useful for candidate/version metadata, but not a provenance guarantee. Inspect each artifact for added libraries and signing changes. |
| [ARM Store](https://armconverter.com/store/us) | Third-party catalogue advertising current and older IPA downloads. PlayCover's documentation lists it among external decrypted-IPA sources and explicitly says those sites' quality and safety cannot be verified. | Do not use as a default source. |
| [Decrypt IPA Store / decrypt.day](https://decrypt.day/apps) | Third-party decrypted-IPA catalogue; also listed by PlayCover with its warning that external-site quality and safety cannot be verified. | Do not use as a default source. |
| [appdb](https://appdb.to/) | Independent app marketplace and distribution service, not Apple's App Store. | Treat each package as third-party; verify provenance and authorization. |
| [TrollStore-IPAs GitHub repository](https://github.com/swaggyP36000/TrollStore-IPAs) | Community collection of IPAs from multiple sources intended for TrollStore. | A collection is not publisher provenance. Do not treat as an official release channel. |
| [iOSBoom IPA Library](https://iosboom.com/ipa-library) | Describes itself as hosting tweaked, premium, and third-party iOS apps with on-demand signing. | High uncertainty about modifications and publisher authorization. Do not treat as a normal App Store build. |
| [ipalibrary.net](https://ipalibrary.net/) and [ipalibrary.me](https://ipalibrary.me/) | Their pages advertise tweaked apps/modded games and IPA downloads. | Third-party mirrors; no automatic acquisition integration. |
| [iOSVIZOR](https://iosvizor.com/) | Advertises IPA games/apps and version/update pages. | Third-party source; verify independently. |
| [ONEJailbreak](https://onejailbreak.com/categories/ipa-files/) and [qbap/ONEJailbreak](https://github.com/qbap/ONEJailbreak) | GitHub describes its repository as “IPA files for popular apps”; the website returned HTTP 403 during this review. | Not verified as an official source. |
| [OMTK](https://www.omtk.vip/IPA-Library-new-IPA.html) | The site could not be fetched in this environment (network tunnel returned 403). | Not assessed; do not infer safety or contents. |
| [S0n1c](https://s0n1c.ca/) | The homepage loaded, but this review did not find useful IPA-source metadata in its returned page. | Not assessed; not integrated. |
| [IPAlibrary/IPA GitHub](https://github.com/IPAlibrary/IPA) | The repository describes itself as profile configuration files, not an IPA package archive. | Not relevant to package acquisition. |

The [PlayCover guide](https://docs.playcover.io/getting_started/download_ipa) is primarily about running compatible iOS apps on Apple Silicon Mac. It says the IPA must be decrypted for PlayCover, lists external IPA sites, and disclaims their safety. This does not make PlayCover an IPA downloader or a static decompiler. Do not use its “decrypt yourself” instructions to bypass store encryption; for an encrypted IPA, report the limitation and analyze accessible resources.

## Supporting tools, not package sources

### [BetaDrop CLI](https://betadrop.app/cli/)

The CLI is for uploading a developer's own signed APK/IPA build and generating an install link for testers or CI. It is a distribution step, not a way to obtain third-party apps. Use it only when the owner intends to upload/share that build; it sends the build to an external service and uses an account/token.

### [BetaDrop APK Inspector](https://betadrop.app/apk-inspector/)

The page advertises in-browser APK manifest, permission, component, native-library, and security checks, and says the parsing runs client-side with no upload. That can be a quick metadata fallback when Android SDK tools are unavailable, but it is not a Java/DEX decompiler. Its page also notes that its browser signature check sees only v1/JAR metadata; use Android SDK apksigner verify -v --print-certs for complete APK signature-scheme verification. The client-side/privacy claim was read from the page, not independently audited; prefer local tools for confidential samples.

## Package provenance checklist

For any secondary-source sample, save the original package separately and record its SHA-256 before analysis. Compare package/bundle ID, version, build, and publisher claims against an official listing. Inspect Android signing certificates or iOS signer/entitlement information when available; list unusual frameworks, dylibs, load commands, URL schemes, and injected substrate/tweak libraries. A valid signature or a catalogue's “verified” label is not proof that a binary is an untouched publisher build. State explicitly when the package is modified or provenance is unknown.
