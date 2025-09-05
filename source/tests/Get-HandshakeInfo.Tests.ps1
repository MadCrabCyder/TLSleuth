BeforeAll {
    $scriptRoot = $PSScriptRoot; if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    $private = Join-Path $scriptRoot '..\private'
    . (Join-Path $private 'Get-HandshakeInfo.ps1')
    . (Join-Path $private 'Test-NegotiatedCipherSuiteSupport.ps1')
}

Describe 'Get-HandshakeInfo' {
    It 'returns an object even if CipherSuite property is unavailable (mocked support=false)' {
        Mock -CommandName Test-NegotiatedCipherSuiteSupport -MockWith { $false }

        $ssl = [System.Net.Security.SslStream]::new([System.IO.MemoryStream]::new())
        $r   = Get-HandshakeInfo -SslStream $ssl

        Should -BeOfType 'System.Management.Automation.PSCustomObject' -ActualValue $r
        $r.PSObject.Properties['Protocol']    | Should -Not -Be $null
        $r.PSObject.Properties['CipherSuite'] | Should -Not -Be $null
    }

    It 'still returns shape when support=true but stream unauthenticated' {
        Mock -CommandName Test-NegotiatedCipherSuiteSupport -MockWith { $true }

        $ssl = [System.Net.Security.SslStream]::new([System.IO.MemoryStream]::new())
        $r   = Get-HandshakeInfo -SslStream $ssl

        Should -BeOfType 'System.Management.Automation.PSCustomObject' -ActualValue $r
        $r.PSObject.Properties['Protocol']    | Should -Not -Be $null
        $r.PSObject.Properties['CipherSuite'] | Should -Not -Be $null
    }
}
