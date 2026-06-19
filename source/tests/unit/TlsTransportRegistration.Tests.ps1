BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    $script:sourceRoot = Join-Path $scriptRoot '..\..'
    $script:transportNames = @('ImplicitTls', 'SmtpStartTls', 'ImapStartTls', 'Pop3StartTls')

    function Get-ValidateSetValue {
        param(
            [Parameter(Mandatory)]
            [string]$Path,

            [Parameter(Mandatory)]
            [string]$FunctionName,

            [Parameter(Mandatory)]
            [string]$ParameterName
        )

        $parseErrors = $null
        $tokens = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
        if ($parseErrors) {
            throw "Failed to parse '$Path': $($parseErrors[0].Message)"
        }

        $functionAst = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $FunctionName
        }, $true)
        if (-not $functionAst) {
            throw "Function '$FunctionName' was not found in '$Path'."
        }

        $parameterAst = $functionAst.Body.ParamBlock.Parameters | Where-Object {
            $_.Name.VariablePath.UserPath -eq $ParameterName
        }
        if (-not $parameterAst) {
            throw "Parameter '$ParameterName' was not found on function '$FunctionName'."
        }

        $validateSet = $parameterAst.Attributes | Where-Object {
            $_.TypeName.Name -eq 'ValidateSet'
        } | Select-Object -First 1
        if (-not $validateSet) {
            throw "Parameter '$ParameterName' on function '$FunctionName' does not have a ValidateSet attribute."
        }

        @(
            foreach ($argument in $validateSet.PositionalArguments) {
                if ($argument -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                    $argument.Value
                }
            }
        )
    }
}

Describe 'TLS transport registration' {
    $validateSetTargets = @(
        @{
            Path = 'public/Get-TLSleuthCertificate.ps1'
            FunctionName = 'Get-TLSleuthCertificate'
        }
        @{
            Path = 'public/Test-TLSleuthProtocol.ps1'
            FunctionName = 'Test-TLSleuthProtocol'
        }
        @{
            Path = 'private/New-TlsOperationContext.ps1'
            FunctionName = 'New-TlsOperationContext'
        }
        @{
            Path = 'private/New-TlsTransportOptionSet.ps1'
            FunctionName = 'New-TlsTransportOptionSet'
        }
        @{
            Path = 'private/New-TlsTransportNegotiationResult.ps1'
            FunctionName = 'New-TlsTransportNegotiationResult'
        }
        @{
            Path = 'private/Invoke-TlsTransportNegotiation.ps1'
            FunctionName = 'Invoke-TlsTransportNegotiation'
        }
    )

    It 'keeps transport ValidateSet values aligned across public and private entry points' {
        foreach ($target in $validateSetTargets) {
            $path = Join-Path $script:sourceRoot $target.Path
            $actual = @(Get-ValidateSetValue `
                -Path $path `
                -FunctionName $target.FunctionName `
                -ParameterName 'Transport')

            $actual | Should -Be $script:transportNames
        }
    }

    It 'keeps transport dispatcher branches aligned with registered transports' {
        $dispatcherPath = Join-Path $script:sourceRoot 'private/Invoke-TlsTransportNegotiation.ps1'
        $dispatcherContent = Get-Content -LiteralPath $dispatcherPath -Raw
        $branchMatches = [regex]::Matches($dispatcherContent, "(?m)^\s+'([^']+)'\s+\{")
        $dispatcherTransports = @(
            foreach ($match in $branchMatches) {
                $match.Groups[1].Value
            }
        )

        $dispatcherTransports | Should -Be $script:transportNames
    }
}
