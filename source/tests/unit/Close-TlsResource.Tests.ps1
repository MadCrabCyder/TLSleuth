BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Close-TlsResource.ps1')
}

Describe 'Close-TlsResource' {
    It 'handles null resources without throwing' {
        { Close-TlsResource -Resource $null -ResourceName 'NullResource' -OwnerName 'Test' } | Should -Not -Throw
    }

    It 'disposes an owned resource' {
        $stream = [System.IO.MemoryStream]::new()

        Close-TlsResource -Resource $stream -ResourceName 'MemoryStream' -OwnerName 'Test'

        $stream.CanRead | Should -BeFalse
    }

    It 'ignores non-disposable resources without throwing' {
        $resource = [PSCustomObject]@{ Name = 'NotDisposable' }

        { Close-TlsResource -Resource $resource -ResourceName 'CustomObject' -OwnerName 'Test' } | Should -Not -Throw
    }
}
