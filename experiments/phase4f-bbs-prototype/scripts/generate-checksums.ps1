$ErrorActionPreference = 'Stop'

$taskRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$taskOutput = Join-Path $taskRoot 'SHA256SUMS.txt'
$taskFiles = Get-ChildItem -LiteralPath $taskRoot -Recurse -File | Where-Object {
    $_.FullName -ne $taskOutput -and
    $_.FullName -notmatch '\\node_modules\\' -and
    $_.FullName -notmatch '\\.npm-cache\\'
} | Sort-Object FullName

$taskLines = foreach ($taskFile in $taskFiles) {
    $taskHash = (Get-FileHash -LiteralPath $taskFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $taskRelativePath = [System.IO.Path]::GetRelativePath($taskRoot, $taskFile.FullName).Replace('\', '/')
    "$taskHash  $taskRelativePath"
}

[System.IO.File]::WriteAllLines($taskOutput, $taskLines)
Write-Output "WROTE=$taskOutput"
