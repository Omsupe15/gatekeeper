param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $Arguments
)

$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$runner = Join-Path $PSScriptRoot "run_pipeline.py"

if (-not (Test-Path $python)) {
    Write-Error "Virtual environment not found at $python"
    exit 2
}

& $python $runner @Arguments
exit $LASTEXITCODE
