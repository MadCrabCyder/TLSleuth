param(
    [switch] $IncludeIntegrationTests,
    [string] $ReleaseVersion,
    [string] $ReleaseNotesPath = (Join-Path $PSScriptRoot 'release-notes.md')
)

$ProjectRoot = $PSScriptRoot
$SourceRoot = Join-Path $ProjectRoot 'source'
$TestRoot = Join-Path $SourceRoot 'tests'
$UnitTestRoot = Join-Path $TestRoot 'unit'
$IntegrationTestRoot = Join-Path $TestRoot 'integration'
$OutputRoot = Join-Path $ProjectRoot 'output'
$BuiltModuleRoot = Join-Path $OutputRoot 'TLSleuth'
$AnalyzerSettings = Join-Path $ProjectRoot 'PSScriptAnalyzerSettings.psd1'
$SourceManifestPath = Join-Path $SourceRoot 'TLSleuth.psd1'
$ChangelogPath = Join-Path $ProjectRoot 'CHANGELOG.md'

function Assert-ModuleAvailable {
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [string] $InstallCommand
    )

    if (-not (Get-Module -ListAvailable -Name $Name)) {
        throw "Required module '$Name' was not found. Install it with: $InstallCommand"
    }
}

function Assert-CommandAvailable {
    param(
        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [string] $InstallCommand
    )

    if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found. Install it with: $InstallCommand"
    }
}

function Assert-BuiltModuleAvailable {
    if (-not (Test-Path -LiteralPath $BuiltModuleRoot)) {
        throw "Built module path '$BuiltModuleRoot' was not found. Run Invoke-Build Build first."
    }

    $manifestPath = Join-Path $BuiltModuleRoot 'TLSleuth.psd1'
    if (-not (Test-Path -LiteralPath $manifestPath)) {
        throw "Built module manifest '$manifestPath' was not found. Run Invoke-Build Build first."
    }
}

function Get-ReleaseMetadata {
    if (-not (Test-Path -LiteralPath $SourceManifestPath)) {
        throw "Source module manifest '$SourceManifestPath' was not found."
    }

    if (-not (Test-Path -LiteralPath $ChangelogPath)) {
        throw "Changelog '$ChangelogPath' was not found."
    }

    $manifest = Import-PowerShellDataFile -LiteralPath $SourceManifestPath
    $version = [string]$manifest.ModuleVersion
    if ([string]::IsNullOrWhiteSpace($version)) {
        throw "ModuleVersion is missing from '$SourceManifestPath'."
    }

    if (-not [string]::IsNullOrWhiteSpace($ReleaseVersion) -and $version -ne $ReleaseVersion) {
        throw "ModuleVersion '$version' does not match release version '$ReleaseVersion'."
    }

    $manifestReleaseNotes = [string]$manifest.PrivateData.PSData.ReleaseNotes
    if ([string]::IsNullOrWhiteSpace($manifestReleaseNotes)) {
        throw "ReleaseNotes is missing from '$SourceManifestPath'."
    }

    if ($manifestReleaseNotes -notmatch "^$([regex]::Escape($version))\b") {
        throw "ReleaseNotes in '$SourceManifestPath' must start with the ModuleVersion '$version'."
    }

    $content = Get-Content -LiteralPath $ChangelogPath -Raw
    $pattern = "(?ms)^## $([regex]::Escape($version)) \([^)]+\)\s*(?<body>.*?)(?=^## |\z)"
    $match = [regex]::Match($content, $pattern)
    if (-not $match.Success) {
        throw "CHANGELOG.md does not contain a release entry for ModuleVersion '$version'. Expected heading format: ## $version (DD-Mmm-YYYY)"
    }

    $releaseNotes = $match.Groups['body'].Value.Trim()
    if ([string]::IsNullOrWhiteSpace($releaseNotes)) {
        throw "CHANGELOG.md release entry for ModuleVersion '$version' is empty."
    }

    [PSCustomObject]@{
        Version               = $version
        ChangelogReleaseNotes = $releaseNotes
        ManifestReleaseNotes  = $manifestReleaseNotes
    }
}

task . Validate

task Init {
    "Project root: $ProjectRoot"
    "PowerShell: $($PSVersionTable.PSVersion)"
}

task Clean {
    if (Test-Path -LiteralPath $OutputRoot) {
        Remove-Item -LiteralPath $OutputRoot -Recurse -Force
    }
}

task Analyze Init, {
    Assert-ModuleAvailable -Name 'PSScriptAnalyzer' -InstallCommand 'Install-Module PSScriptAnalyzer -Scope CurrentUser'

    $analyzerParameters = @{
        Path     = $SourceRoot
        Recurse  = $true
        Severity = @('Error', 'Warning')
    }
    if (Test-Path -LiteralPath $AnalyzerSettings) {
        $analyzerParameters.Settings = $AnalyzerSettings
    }

    $results = Invoke-ScriptAnalyzer @analyzerParameters
    if ($results) {
        $results | Format-Table -AutoSize
        throw "PSScriptAnalyzer reported $($results.Count) issue(s)."
    }
}

task ValidateReleaseMetadata {
    $metadata = Get-ReleaseMetadata
    "Release metadata validated for version $($metadata.Version)."
}

task WriteReleaseNotes ValidateReleaseMetadata, {
    $metadata = Get-ReleaseMetadata
    Set-Content -LiteralPath $ReleaseNotesPath -Value $metadata.ChangelogReleaseNotes
    "Wrote release notes for version $($metadata.Version) to $ReleaseNotesPath."
}

task Test Init, UnitTest

task UnitTest {
    Assert-ModuleAvailable -Name 'Pester' -InstallCommand 'Install-Module Pester -Scope CurrentUser'

    $config = New-PesterConfiguration
    $config.Output.Verbosity = 'Detailed'
    $config.Run.Path = $UnitTestRoot
    $config.Run.Throw = $true

    Invoke-Pester -Configuration $config
}

task IntegrationTest {
    Assert-ModuleAvailable -Name 'Pester' -InstallCommand 'Install-Module Pester -Scope CurrentUser'

    $config = New-PesterConfiguration
    $config.Output.Verbosity = 'Detailed'
    $config.Run.Path = $IntegrationTestRoot
    $config.Run.Throw = $true

    Invoke-Pester -Configuration $config
}

task AllTests UnitTest, IntegrationTest

task Build Init, {
    Assert-ModuleAvailable -Name 'ModuleBuilder' -InstallCommand 'Install-Module ModuleBuilder -Scope CurrentUser'

    Push-Location -LiteralPath $ProjectRoot
    try {
        Build-Module
    }
    finally {
        Pop-Location
    }
}

task Rebuild Clean, Build

task Validate Analyze, ValidateReleaseMetadata, Test, Build, {
    if ($IncludeIntegrationTests) {
        Invoke-Build IntegrationTest -File $BuildFile
    }
}

task PublishBuilt {
    Assert-CommandAvailable -Name 'Publish-Module' -InstallCommand 'Install-Module PowerShellGet -Scope CurrentUser'
    Assert-BuiltModuleAvailable

    if ([string]::IsNullOrWhiteSpace($env:PSGALLERY_API_KEY)) {
        throw "PSGALLERY_API_KEY is required to publish the built module."
    }

    Publish-Module -Path $BuiltModuleRoot -NuGetApiKey $env:PSGALLERY_API_KEY -Verbose
}

task PublishBuiltWhatIf {
    Assert-CommandAvailable -Name 'Publish-Module' -InstallCommand 'Install-Module PowerShellGet -Scope CurrentUser'
    Assert-BuiltModuleAvailable

    $apiKey = if ([string]::IsNullOrWhiteSpace($env:PSGALLERY_API_KEY)) { 'dry-run' } else { $env:PSGALLERY_API_KEY }
    Publish-Module -Path $BuiltModuleRoot -NuGetApiKey $apiKey -WhatIf -Verbose
}
