@{
    ExcludeRules = @(
        # Existing public/private command names are part of the module contract and documentation.
        'PSUseSingularNouns',

        # Start-TlsHandshake performs an in-memory TLS negotiation, not a persistent state change.
        'PSUseShouldProcessForStateChangingFunctions',

        # TLSleuth currently keeps certificate validation disabled by default for inspection workflows.
        'PSAvoidDefaultValueSwitchParameter'
    )
}
