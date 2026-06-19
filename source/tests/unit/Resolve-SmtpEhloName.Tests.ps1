BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Resolve-SmtpEhloName.ps1')
}

Describe 'Resolve-SmtpEhloName' {
    It 'uses the normalized SMTP STARTTLS option when supplied' {
        $options = [PSCustomObject]@{
            SmtpStartTls = [PSCustomObject]@{
                EhloName = 'client.example.test'
            }
            SmtpEhloName = 'legacy.example.test'
        }

        $result = Resolve-SmtpEhloName -Options $options -HostNameResolver { 'host.example.test' }

        $result | Should -Be 'client.example.test'
    }

    It 'uses the legacy SMTP EHLO option when normalized option is missing' {
        $options = [PSCustomObject]@{
            SmtpEhloName = 'legacy.example.test'
        }

        $result = Resolve-SmtpEhloName -Options $options -HostNameResolver { 'host.example.test' }

        $result | Should -Be 'legacy.example.test'
    }

    It 'falls back to local hostname when no option is supplied' {
        $options = [PSCustomObject]@{}

        $result = Resolve-SmtpEhloName -Options $options -HostNameResolver { 'host.example.test' }

        $result | Should -Be 'host.example.test'
    }

    It 'falls back to localhost when local hostname is empty' {
        $options = [PSCustomObject]@{}

        $result = Resolve-SmtpEhloName -Options $options -HostNameResolver { '   ' }

        $result | Should -Be 'localhost'
    }
}
