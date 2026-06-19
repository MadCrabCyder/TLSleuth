function Read-BinaryProtocolData {
<#
.SYNOPSIS
    Reads an exact number of bytes from a binary protocol stream.

.OUTPUTS
    System.Byte[]
#>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.IO.Stream]$Stream,

        [Parameter(Mandatory)]
        [ValidateRange(1,1048576)]
        [int]$Length,

        [ValidateRange(1000,600000)]
        [int]$TimeoutMs = 10000,

        [ValidateNotNullOrEmpty()]
        [string]$ProtocolName = 'Binary'
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Protocol=$ProtocolName, Length=$Length, TimeoutMs=$TimeoutMs)"

    try {
        if (-not $Stream.CanRead) {
            throw [System.InvalidOperationException]::new("$ProtocolName binary read requires a readable stream.")
        }

        $result = Invoke-WithStreamTimeout -Stream $Stream -TimeoutMs $TimeoutMs -ScriptBlock {
            $buffer = New-Object byte[] $Length
            $offset = 0

            while ($offset -lt $Length) {
                try {
                    $read = $Stream.Read($buffer, $offset, $Length - $offset)
                }
                catch [System.IO.IOException] {
                    if (Test-TlsTimeoutException -Exception $_.Exception) {
                        throw (New-TlsTimeoutException `
                            -Operation "$ProtocolName binary read" `
                            -TimeoutMs $TimeoutMs `
                            -Transport $ProtocolName `
                            -InnerException $_.Exception)
                    }

                    throw
                }

                if ($read -le 0) {
                    throw [System.IO.EndOfStreamException]::new("$ProtocolName stream ended before $Length bytes were read.")
                }

                $offset += $read
            }

            Write-Output -InputObject $buffer -NoEnumerate
        }

        Write-Output -InputObject ([byte[]]$result) -NoEnumerate
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
