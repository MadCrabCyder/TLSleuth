[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSReviewUnusedParameter',
    '',
    Justification = 'Invoke-Build task blocks and helper functions consume script parameters dynamically.'
)]
param(
    [switch] $IncludeIntegrationTests,
    [string] $ReleaseVersion,
    [string] $ReleaseNotesPath = (Join-Path $PSScriptRoot 'release-notes.md'),
    [string[]] $GistName = @()
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
$GistManifestPath = Join-Path (Join-Path $ProjectRoot 'gists') 'gists.psd1'

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

function Resolve-ProjectPath {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }

    Join-Path $ProjectRoot $Path
}

function Get-ConfiguredGist {
    if (-not (Test-Path -LiteralPath $GistManifestPath)) {
        throw "Gist manifest '$GistManifestPath' was not found."
    }

    $manifest = Import-PowerShellDataFile -LiteralPath $GistManifestPath
    if (-not $manifest -or $manifest.Count -eq 0) {
        throw "Gist manifest '$GistManifestPath' does not contain any gist definitions."
    }

    foreach ($entry in ($manifest.GetEnumerator() | Sort-Object -Property Name)) {
        $definition = $entry.Value
        [PSCustomObject]@{
            Name               = [string]$entry.Key
            Description        = [string]$definition.Description
            RelativeSourcePath = [string]$definition.SourcePath
            SourcePath         = Resolve-ProjectPath -Path ([string]$definition.SourcePath)
            Public             = [bool]$definition.Public
            GistId             = [string]$definition.GistId
        }
    }
}

function Get-SelectedGist {
    $configuredGists = @(Get-ConfiguredGist)
    if (-not $GistName -or $GistName.Count -eq 0) {
        return $configuredGists
    }

    $selectedGists = foreach ($name in $GistName) {
        $match = @($configuredGists | Where-Object { $_.Name -eq $name })
        if ($match.Count -eq 0) {
            $knownNames = ($configuredGists.Name | Sort-Object) -join ', '
            throw "Gist '$name' was not found in '$GistManifestPath'. Known gists: $knownNames"
        }

        $match
    }

    $selectedGists
}

function Assert-GistDefinition {
    param(
        [Parameter(Mandatory)]
        [pscustomobject[]] $Gist
    )

    foreach ($gistDefinition in $Gist) {
        if ([string]::IsNullOrWhiteSpace($gistDefinition.Name)) {
            throw "A gist definition in '$GistManifestPath' is missing its name."
        }

        if ([string]::IsNullOrWhiteSpace($gistDefinition.Description)) {
            throw "Gist '$($gistDefinition.Name)' is missing Description."
        }

        if ([string]::IsNullOrWhiteSpace($gistDefinition.RelativeSourcePath)) {
            throw "Gist '$($gistDefinition.Name)' is missing SourcePath."
        }

        if (-not (Test-Path -LiteralPath $gistDefinition.SourcePath -PathType Leaf)) {
            throw "Gist '$($gistDefinition.Name)' source file '$($gistDefinition.SourcePath)' was not found."
        }
    }
}

function Invoke-GitHubCli {
    param(
        [Parameter(Mandatory)]
        [string[]] $ArgumentList
    )

    $output = & gh @ArgumentList 2>&1
    if ($LASTEXITCODE -ne 0) {
        $output | ForEach-Object { "$_" }
        throw "GitHub CLI command failed: gh $($ArgumentList -join ' ')"
    }

    $output
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

task ListGists {
    $gists = @(Get-SelectedGist)
    Assert-GistDefinition -Gist $gists

    foreach ($gistDefinition in $gists) {
        $visibility = if ($gistDefinition.Public) { 'public' } else { 'secret' }
        $mode = if ([string]::IsNullOrWhiteSpace($gistDefinition.GistId)) { 'create' } else { 'update' }
        "$($gistDefinition.Name): $($gistDefinition.RelativeSourcePath) ($visibility, $mode)"
    }
}

task ValidateGists {
    $gists = @(Get-SelectedGist)
    Assert-GistDefinition -Gist $gists
    "Validated $($gists.Count) configured gist(s)."
}

task PublishGists ValidateGists, {
    Assert-CommandAvailable -Name 'gh' -InstallCommand 'Install GitHub CLI from https://cli.github.com/ and run gh auth login'
    $null = Invoke-GitHubCli -ArgumentList @('auth', 'status')

    foreach ($gistDefinition in @(Get-SelectedGist)) {
        if ([string]::IsNullOrWhiteSpace($gistDefinition.GistId)) {
            "Creating gist '$($gistDefinition.Name)' from $($gistDefinition.RelativeSourcePath)."
            $createArgumentList = @(
                'gist',
                'create',
                $gistDefinition.SourcePath,
                '--desc',
                $gistDefinition.Description
            )
            if ($gistDefinition.Public) {
                $createArgumentList += '--public'
            }

            $createOutput = Invoke-GitHubCli -ArgumentList $createArgumentList
            $createOutput | ForEach-Object { "$_" }
            "Add the returned gist ID or URL to '$GistManifestPath' as GistId to update this gist in future runs."
        }
        else {
            "Updating gist '$($gistDefinition.Name)' ($($gistDefinition.GistId)) from $($gistDefinition.RelativeSourcePath)."
            Invoke-GitHubCli -ArgumentList @(
                'gist',
                'edit',
                $gistDefinition.GistId,
                $gistDefinition.SourcePath
            ) | ForEach-Object { "$_" }
        }
    }
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
