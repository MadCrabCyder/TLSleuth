# Development

## Architecture Overview

TLSleuth follows a **source-first modular design**:

- One function per file
- Clear separation of public vs private functions
- Pester-driven development
- Stable output contract
- Minimal side effects

## Project Layout

```text
TLSleuth/
├── docs/
├── examples/
├── gists/
├── output/
└── source/
    ├── private/
    ├── public/
    └── tests/
        ├── integration/
        └── unit/
```

## Building from Source

TLSleuth uses **ModuleBuilder (Build-Module)**.

The repository contains individual function files. During build:

- Functions are merged into a single `.psm1`
- The module manifest is generated/updated
- Public functions are auto-exported
- Build settings are read from `/build.psd1`
- Compiled output is written to `/output`

Do not modify files in `/output` directly.

## Requirements

```powershell
Install-Module InvokeBuild -Scope CurrentUser
Install-Module ModuleBuilder -Scope CurrentUser
Install-Module Pester -Scope CurrentUser
Install-Module PSScriptAnalyzer -Scope CurrentUser
```

## Build

From project root:

```powershell
Invoke-Build Build
```

Force clean rebuild:

```powershell
Invoke-Build Rebuild
```

## Invoke-Build Tasks

```powershell
Invoke-Build Analyze                 # Run PSScriptAnalyzer
Invoke-Build Test                    # Run unit tests
Invoke-Build IntegrationTest         # Run live integration tests
Invoke-Build Build                   # Build module output with ModuleBuilder
Invoke-Build Clean                   # Remove generated output
Invoke-Build Validate                # Analyze, test, and build
Invoke-Build ValidateReleaseMetadata # Check manifest version has changelog notes
Invoke-Build WriteReleaseNotes       # Write release-notes.md from CHANGELOG.md
Invoke-Build ListGists               # List configured gist snippets
Invoke-Build ValidateGists           # Validate configured gist snippets
Invoke-Build PublishGists            # Create or update configured GitHub gists
Invoke-Build PublishBuilt            # Publish built output to PowerShell Gallery
```

`.\build.ps1` remains available as a wrapper for the `Build` task.

Analyzer exclusions live in `PSScriptAnalyzerSettings.psd1`.

## Gist Publishing

Reusable standalone snippets are listed in `gists/gists.psd1`. Each entry points
at a source file in the repository and includes its gist description,
visibility, and optional `GistId`.

The initial configured gist is `invoke-retry`, which publishes
`source/private/Invoke-WithRetry.ps1`.

List configured gists:

```powershell
Invoke-Build ListGists
```

Validate the gist list without contacting GitHub:

```powershell
Invoke-Build ValidateGists
```

Create or update all configured gists:

```powershell
Invoke-Build PublishGists
```

Create or update one configured gist:

```powershell
Invoke-Build PublishGists -GistName invoke-retry
```

`PublishGists` requires the GitHub CLI (`gh`) and an authenticated session from
`gh auth login`. When `GistId` is blank, the task creates a new gist using the
configured visibility. Secret gists use the GitHub CLI default behavior; public
gists pass `--public`. Add the returned gist ID or URL to `gists/gists.psd1` so
future runs update the existing gist.

## Release And Compatibility

- Release checklist: `docs/release.md`
- Runtime compatibility notes: `docs/compatibility.md`
