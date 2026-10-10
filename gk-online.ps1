[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $Package,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $GatekeeperArguments
)

$ErrorActionPreference = "Stop"
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("gatekeeper-package-" + [guid]::NewGuid())
$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$runner = Join-Path $PSScriptRoot "run_pipeline.py"

try {
    if (-not (Test-Path $python)) {
        throw "Virtual environment not found at $python"
    }

    New-Item -Path $tempRoot -ItemType Directory | Out-Null
    Write-Host "Downloading $Package without running package install scripts..."
    npm pack $Package --ignore-scripts --pack-destination $tempRoot | Out-Host

    $archive = Get-ChildItem -Path $tempRoot -Filter "*.tgz" | Select-Object -First 1
    if (-not $archive) {
        throw "npm did not produce an archive for '$Package'."
    }

    $packageRoot = Join-Path $tempRoot "package"
    New-Item -Path $packageRoot -ItemType Directory | Out-Null
    tar -xzf $archive.FullName -C $packageRoot --strip-components=1

    Write-Host "Scanning temporary package copy with Gatekeeper..."
    & $python $runner $packageRoot @GatekeeperArguments
    exit $LASTEXITCODE
}
catch {
    Write-Error $_
    exit 2
}
finally {
    Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
