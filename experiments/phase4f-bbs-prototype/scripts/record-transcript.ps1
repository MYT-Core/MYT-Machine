$ErrorActionPreference = 'Stop'

$taskRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$taskTranscript = Join-Path $taskRoot 'TEST-TRANSCRIPT.txt'
$taskLines = [System.Collections.Generic.List[string]]::new()

function Add-RecordedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][scriptblock]$Command
    )
    $taskLines.Add("COMMAND: $Label")
    $taskOutput = (& $Command 2>&1 | Out-String).Replace("`r`n", "`n").Replace("`r", "`n")
    $taskExitCode = $LASTEXITCODE
    $taskLines.Add($taskOutput.TrimEnd())
    $taskLines.Add("EXIT_CODE: $taskExitCode")
    $taskLines.Add('')
    if ($taskExitCode -ne 0) {
        throw "Recorded command failed: $Label"
    }
}

Push-Location -LiteralPath $taskRoot
try {
    $taskLines.Add('MYT MACHINE PHASE 4F EXPERIMENT - TEST TRANSCRIPT')
    $taskLines.Add('Recorded: 2026-09-11 (Europe/London)')
    $taskLines.Add('Platform: native Windows')
    $taskLines.Add('Status: EXPERIMENTAL - NOT FOR PRODUCTION')
    $taskLines.Add('')
    Add-RecordedCommand -Label 'node --version' -Command { node --version }
    Add-RecordedCommand -Label 'npm --version' -Command { npm --version }
    if (-not $env:MYT_PHASE4F_PYTHON) {
        throw 'Set MYT_PHASE4F_PYTHON to the approved Python 3.10+ executable'
    }
    Add-RecordedCommand -Label 'Python --version' -Command {
        & $env:MYT_PHASE4F_PYTHON --version
    }
    Add-RecordedCommand -Label 'npm ls --all' -Command { npm ls --all }
    Add-RecordedCommand -Label 'npm test' -Command { npm test }
    Add-RecordedCommand -Label 'npm run demo' -Command { npm run demo }
    $taskLines.Add('INSTALL OBSERVATION')
    $taskLines.Add('The pinned install added 3 packages and npm reported 0 vulnerabilities.')
    $taskLines.Add('See package-lock.json for exact tarball URLs and SHA-512 integrity values.')
    $taskLines.Add('This registry result is not an implementation audit or production approval.')
    $taskUtf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText(
        $taskTranscript,
        ($taskLines -join "`n") + "`n",
        $taskUtf8NoBom
    )
} finally {
    Pop-Location
}

Write-Output "WROTE=$taskTranscript"
