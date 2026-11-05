<#
.SYNOPSIS
Builds the WimDrive prototype on an x64 Windows build machine, for x64 or ARM64.
.DESCRIPTION
Restores pinned direct packages, generates a NuGet lock file, and publishes
a self-contained Windows x64 (default) or ARM64 application, with that runtime's Dokan
installer beside it, so both behave the same and an offline PC needs no download.
The full console output is saved in a transcript in the temp folder
(WimDriverMount-build-logs), never in the project. The resulting package is a prototype, not an approved release.
.PARAMETER OutputPath
Destination for published files. Defaults to publish beside this script, or a new
timestamped folder when the default folder is already in use.
.PARAMETER Runtime
win-x64 (default) or win-arm64.
.PARAMETER DokanMsiPath
Required: the pinned Dokan 2.3.1.1000 MSI for that runtime (Dokan_x64.msi or
Dokan_ARM64.msi), from https://github.com/dokan-dev/dokany/releases/tag/v2.3.1.1000.
The script verifies its SHA-256 before and after copying it into the package.
.EXAMPLE
.\build.ps1 -DokanMsiPath C:\path\Dokan_x64.msi
.EXAMPLE
.\build.ps1 -Runtime win-arm64 -DokanMsiPath C:\path\Dokan_ARM64.msi -OutputPath C:\Temp\WimDriveBuild
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string] $OutputPath,
    [Parameter(Mandatory)]
    [string] $DokanMsiPath,
    [Parameter()]
    [ValidateSet('win-x64', 'win-arm64')]
    [string] $Runtime = 'win-x64'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$transcriptStarted = $false
$scriptStart = Get-Date

try {
    if (-not $PSBoundParameters.ContainsKey('OutputPath')) {
        $OutputPath = Join-Path $PSScriptRoot 'publish'
    }
    $dotnet = Get-Command -Name dotnet.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $project = Join-Path $PSScriptRoot 'WimDrive.csproj'
    $licensePath = Join-Path $PSScriptRoot 'licenses'
    . (Join-Path $PSScriptRoot 'DokanPackage.ps1')
    if (-not (Test-Path -LiteralPath $project -PathType Leaf)) { throw "Project not found: $project" }
    if (-not (Test-Path -LiteralPath $licensePath -PathType Container)) { throw "License directory not found: $licensePath" }
    # Dokan 2.3.1.1000, both from the GitHub release; these equal the SHA-256 digests
    # GitHub shows for its assets. The program also verifies the signature.
    $pinnedDokanHash, $dokanMsiName = if ($Runtime -eq 'win-arm64') {
        'F812A5BF11C15BC3910A1F0F53830FF771CEB3C80458F10686B0F45B0DB91D2E', 'Dokan_ARM64.msi'
    } else { '69FF8CB37BFEC3A75921C85FFD1C6370B50A9EC4ECEF2CF3A009D488DCBF5465', 'Dokan_x64.msi' }
    $DokanMsiPath = [System.IO.Path]::GetFullPath($DokanMsiPath)
    Test-DokanMsiHash -Path $DokanMsiPath -ExpectedHash $pinnedDokanHash -ExpectedName $dokanMsiName
    $fullOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
    $sourceRoot = [System.IO.Path]::GetFullPath($PSScriptRoot).TrimEnd([char]'\')
    if ([string]::Equals($fullOutputPath.TrimEnd([char]'\'), $sourceRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The publish output must not be the source project directory.'
    }
    if (Test-Path -LiteralPath $fullOutputPath) {
        if (-not (Test-Path -LiteralPath $fullOutputPath -PathType Container)) { throw "Output is not a directory: $fullOutputPath" }
        if (@(Get-ChildItem -LiteralPath $fullOutputPath -Force).Count -ne 0) {
            if ($PSBoundParameters.ContainsKey('OutputPath')) {
                throw "Output directory must be empty: $fullOutputPath"
            }
            $fullOutputPath = Join-Path $sourceRoot ("publish-{0}-{1}" -f (Get-Date -Format 'yyyyMMdd-HHmmss'), [Guid]::NewGuid().ToString('N').Substring(0, 8))
            Write-Host "Existing publish folder preserved. New output: $fullOutputPath"
        }
    }

    # In the temp folder, never in the project: the log records the build machine's details.
    $logDirectory = Join-Path ([IO.Path]::GetTempPath()) 'WimDriverMount-build-logs'
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
    $logPath = Join-Path $logDirectory ("build-{0}-{1}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'), [Guid]::NewGuid().ToString('N'))
    Start-Transcript -LiteralPath $logPath | Out-Null
    $transcriptStarted = $true
    Write-Host "Build started: $scriptStart"
    Write-Host "Project: $project ($Runtime)"
    Write-Host "Output: $fullOutputPath"
    Write-Host "Log: $logPath"

    # No --runtime here: it would replace the RuntimeIdentifiers in Directory.Build.props
    # and drop the other architecture from packages.lock.json.
    & $dotnet.Source restore $project --use-lock-file -p:SelfContained=true -p:PublishSingleFile=true
    if ($LASTEXITCODE -ne 0) { throw "dotnet restore failed with exit code $LASTEXITCODE." }

    # Stamp the commit into the version, so a binary in the field can be traced
    # to the exact source it was built from. A dirty tree is marked, because a
    # commit alone would then be a claim the build does not support.
    $revision = ''
    try {
        $commit = (& git -C $sourceRoot rev-parse --short HEAD 2>$null)
        if ($LASTEXITCODE -eq 0 -and $commit) {
            # Only what is compiled: this project folder. A log or test file
            # elsewhere in the repository says nothing about this binary.
            $dirty = (& git -C $sourceRoot status --porcelain -- $sourceRoot 2>$null)
            $revision = $commit.Trim() + $(if ($dirty) { '-modified' } else { '' })
        }
    } catch { }
    if ($revision) { Write-Host "Source revision: $revision" } else { Write-Host 'Source revision: unknown (not a git checkout)' }
    $revisionArgument = if ($revision) { "-p:SourceRevisionId=$revision" } else { '-p:SourceRevisionId=unknown' }

    & $dotnet.Source publish $project --configuration Release --runtime $Runtime --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true $revisionArgument --no-restore --output $fullOutputPath
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit code $LASTEXITCODE." }

    Copy-Item -LiteralPath $licensePath -Destination $fullOutputPath -Recurse -Force
    $bundledDokan = Join-Path $fullOutputPath $dokanMsiName
    Copy-VerifiedDokanMsi -Source $DokanMsiPath -Destination $bundledDokan -ExpectedHash $pinnedDokanHash
    Write-Host 'Verified the bundled Dokan MSI.'
    # The reader's notice ships with the other notices.
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'WimReader\SOURCE-NOTICES.md') -Destination (Join-Path $fullOutputPath 'licenses\WIMREADER-SOURCE-NOTICES.md') -Force
    Write-Host 'Build completed. Review the generated packages.lock.json and all dependency licenses before redistribution.'
    Write-Host ("Elapsed: {0}" -f ((Get-Date) - $scriptStart))
    Write-Host "Published application: $(Join-Path $fullOutputPath 'WimDriverMount.exe')"
    Write-Host "Full output: $logPath"
}
catch {
    Write-Error -ErrorRecord $_ -ErrorAction Continue
    Write-Host ("Build failed. Elapsed: {0}" -f ((Get-Date) - $scriptStart))
    if ($transcriptStarted) { Write-Host "Full output: $logPath" }
    exit 1
}
finally {
    if ($transcriptStarted) { Stop-Transcript | Out-Null }
}
