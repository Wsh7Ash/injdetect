# Security Policy

## Authorized use

`injdetect` is a **defensive tool for systems you own or are explicitly authorized to
test**. Do not point it at third-party infrastructure without written permission;
unauthorized security testing violates computer-misuse laws in most jurisdictions.

`injdetect` is detection-only: it does not generate, weaponize, or deliver injection payloads. Repository samples are defanged structural skeletons used as test fixtures. The tool runs fully offline; scanned content never leaves your machine.

## Reporting a vulnerability

If you find a vulnerability or unsafe default in `injdetect` itself, please open a
private security advisory on the GitHub repository (or open an issue describing the
problem at a high level if you cannot use advisories). We will acknowledge within
72 hours and coordinate a fix before public disclosure.

## Secrets

`injdetect` stores no credentials and requires none. Do not commit real tokens, cookies
or keys to the spec/example files in this repository; `.gitignore` excludes `.env`
and common key material.
