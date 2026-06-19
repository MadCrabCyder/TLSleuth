BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-WithRetry.ps1')

    if (-not ('TLSleuth.Tests.DerivedIOException' -as [type])) {
        Add-Type -TypeDefinition @"
namespace TLSleuth.Tests
{
    public class DerivedIOException : System.IO.IOException
    {
        public DerivedIOException(string message) : base(message) { }
    }
}
"@
    }
}

Describe 'Invoke-WithRetry' {
    It 'returns immediately on first successful attempt' {
        $attempts = 0
        $result = Invoke-WithRetry -DelayMs 0 -ScriptBlock {
            $script:attempts += 1
            'ok'
        }

        $result | Should -Be 'ok'
        $script:attempts | Should -Be 1
    }

    It 'retries configured transient exception and eventually succeeds' {
        $script:attempts = 0
        $result = Invoke-WithRetry -DelayMs 0 -MaxAttempts 3 -ScriptBlock {
            $script:attempts += 1
            if ($script:attempts -lt 3) {
                throw [System.TimeoutException]::new('transient')
            }
            'done'
        }

        $result | Should -Be 'done'
        $script:attempts | Should -Be 3
    }

    It 'does not retry non-configured exception types' {
        $script:attempts = 0
        {
            Invoke-WithRetry -DelayMs 0 -MaxAttempts 3 -ScriptBlock {
                $script:attempts += 1
                throw [System.InvalidOperationException]::new('non-transient')
            }
        } | Should -Throw

        $script:attempts | Should -Be 1
    }

    It 'retries derived exception types when their base type is configured' {
        $script:attempts = 0
        $result = Invoke-WithRetry -DelayMs 0 -MaxAttempts 3 -RetryOnExceptionType @('System.IO.IOException') -ScriptBlock {
            $script:attempts += 1
            if ($script:attempts -lt 3) {
                throw [TLSleuth.Tests.DerivedIOException]::new('derived transient')
            }
            'done'
        }

        $result | Should -Be 'done'
        $script:attempts | Should -Be 3
    }
}
