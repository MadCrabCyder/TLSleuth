#
# Module manifest for module 'TLSleuth'
#

@{

# Script module or binary module file associated with this manifest.
RootModule = '.\TLSleuth.psm1'

# Version number of this module.
ModuleVersion = '2.3.2'

# Supported PSEditions
CompatiblePSEditions = @('Desktop','Core')

# ID used to uniquely identify this module
GUID = 'd550281a-7d0b-4042-b7fc-fb0cf85b9a07'

# Author of this module
Author = 'Mad Crab Cyder'

# Company or vendor of this module
CompanyName = 'Mad Crab Cyder Productions'

# Copyright statement for this module
Copyright = '(c) 2025 Mad Crab Cyder. All rights reserved.'

# Description of the functionality provided by this module
Description = @'
TLSleuth is an open-source PowerShell module for inspecting TLS
endpoints and certificate details from scripts or the command line.

It provides clean, structured, script-friendly output for operators,
engineers, and automation pipelines that need reliable TLS insight.
'@

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.1'

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @()

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @()

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags for PowerShell Gallery search
        Tags = @(
            'TLS','SSL','X509','Certificate','Security','Handshake',
            'SChannel','OpenSSL','Networking','PowerShell','PSModule',
            'Windows','Linux','macOS','PSEdition_Core'
        )

        # A URL to the license for this module.
        LicenseUri = 'https://raw.githubusercontent.com/MadCrabCyder/TLSleuth/main/LICENSE'

        # A URL to the main website for this project.
        ProjectUri = 'https://tlsleuth.com/'

        # A URL to an icon representing this module.
        IconUri = 'https://raw.githubusercontent.com/MadCrabCyder/TLSleuth/main/source/assets/TLSleuth-icon.png'

        # ReleaseNotes of this module
        ReleaseNotes = '2.3.2: Added Invoke-TlsTransportNegotiation and refactored public command transport orchestration to use centralized internal transport negotiation with no public API changes.'

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}
