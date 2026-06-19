BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Resolve-TlsException.ps1')
}

Describe 'Resolve-TlsException' {
    It 'returns the original exception when there is no wrapper' {
        $exception = [System.InvalidOperationException]::new('direct failure')

        $result = Resolve-TlsException -Exception $exception

        [object]::ReferenceEquals($result, $exception) | Should -BeTrue
    }

    It 'unwraps PowerShell method invocation and task aggregate wrappers' {
        $inner = [System.Security.Authentication.AuthenticationException]::new('Authentication failed, see inner exception.')
        $aggregate = [System.AggregateException]::new($inner)
        $wrapper = [System.Management.Automation.MethodInvocationException]::new(
            'Exception calling "Wait" with "1" argument(s): "One or more errors occurred."',
            $aggregate
        )

        $result = Resolve-TlsException -Exception $wrapper

        [object]::ReferenceEquals($result, $inner) | Should -BeTrue
        $result.Message | Should -Be 'Authentication failed, see inner exception.'
    }
}
