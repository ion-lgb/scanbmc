# Contributing to ScanBMC

Thank you for your interest in contributing to **ScanBMC**! Issues, pull requests, and verified BMC vendor fingerprints / IPMI IANA OEM ID mappings are always welcome.

## Development Setup

### Prerequisites

- Windows 10 / 11 (x64)
- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

### Build & Test

```powershell
git clone https://github.com/ion-lgb/scanbmc.git
cd scanbmc

# Run unit and loopback integration tests
dotnet test ScanBMC.sln -c Release

# Launch the WPF desktop app
dotnet run --project src/ScanBMC.App
```

Please ensure all tests pass before opening a pull request, and add unit tests in `tests/ScanBMC.Core.Tests/` whenever adding new protocol parsers, classification rules, or vendor fingerprints.

## Coding Conventions

- **`ScanBMC.Core` must remain zero-dependency** (only .NET 8 BCL; third-party packages are restricted to `tests/`).
- Use English for identifiers (types, methods, properties) and keep UI copy / comments consistent with existing files.
- **Protocol-first classification**: Only genuine BMC protocol responses (IPMI RMCP, Get Device ID, ASF Pong, or Redfish JSON) may trigger the `Confirmed` level. Never mark generic web servers as BMCs based solely on open ports.
- **Read-only guarantee**: Never add credential guessing, login attempts, or state-mutating BMC operations.

## Submitting Vendor Fingerprints

If you tested ScanBMC against a BMC model that was unrecognized or misclassified, please open an issue with:
- Server / BMC model & firmware version
- IPMI OEM ID / Get Device ID manufacturer & product ID (if available)
- Redfish `/redfish/v1/` `Server` header and sanitized JSON root fields (`Vendor`, `Product`, `Oem` keys)
- HTTP(S) `Server` header and `<title>`

## Commit Guidelines

- Keep each commit focused on a single logical change.
- Explain **why** the change is needed, not just what changed.
- For protocol parsing or classification changes, note which hardware / firmware versions were verified.
