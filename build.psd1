# Preferences for ModuleBuilder
# https://github.com/PoshCode/ModuleBuilder
#

@{
    Path = "./source/TLSleuth.psd1"

    UnversionedOutputDirectory = $true

    SourceDirectories = @(
        "[Pp]rivate", "[Pp]ublic"
    )

    PublicFilter = @("[Pp]ublic/*.ps1")

}
