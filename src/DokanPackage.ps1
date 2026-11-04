Set-StrictMode -Version Latest

function Test-DokanMsiHash {
    param([Parameter(Mandatory)][string] $Path, [Parameter(Mandatory)][string] $ExpectedHash,
          [Parameter(Mandatory)][string] $ExpectedName)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'Dokan MSI was not found.' }
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $ExpectedHash) {
        throw "Dokan MSI failed the pinned SHA-256 check: this build needs Dokan 2.3.1.1000's $ExpectedName (SHA-256 $ExpectedHash)."
    }
}

function Copy-VerifiedDokanMsi {
    param([Parameter(Mandatory)][string] $Source, [Parameter(Mandatory)][string] $Destination,
          [Parameter(Mandatory)][string] $ExpectedHash)
    # Hold the source without write/delete sharing during hashing and copying.
    $inputStream = [System.IO.File]::Open($Source, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { $sourceHash = [BitConverter]::ToString($sha.ComputeHash($inputStream)).Replace('-', '') }
        finally { $sha.Dispose() }
        if ($sourceHash -ne $ExpectedHash) { throw 'Dokan MSI failed the pinned SHA-256 check.' }
        $inputStream.Position = 0
        # CreateNew never replaces a file already in the package.
        $outputStream = [System.IO.File]::Open($Destination, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            $inputStream.CopyTo($outputStream)
            $outputStream.Flush($true)
            $outputStream.Position = 0
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try { $copiedHash = [BitConverter]::ToString($sha.ComputeHash($outputStream)).Replace('-', '') }
            finally { $sha.Dispose() }
            if ($copiedHash -ne $ExpectedHash) { throw 'Copied Dokan MSI failed the pinned SHA-256 check; do not use this package.' }
        }
        finally { $outputStream.Dispose() }
    }
    finally { $inputStream.Dispose() }
}
