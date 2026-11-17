# Signed release builds

**Why.** An unsigned one-file `usbhawk.exe` triggers SmartScreen warnings, and some EDR policies block unsigned
binaries that unpack themselves (PyInstaller one-file builds do). Responders need to run it on locked-down hosts.

**Approach.** Build in GitHub Actions on `windows-latest` from a tagged commit, sign with a code-signing certificate
(or Azure Trusted Signing), publish SHA-256 hashes and a build provenance attestation with the release. Consider a
one-folder build as well, which unpacks nothing at run time.

**Tests.** The release workflow runs the demo smoke test (`scripts/build_release.ps1`) on the signed binary and checks
the signature with `Get-AuthenticodeSignature`.
