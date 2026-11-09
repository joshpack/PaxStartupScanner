<#
    Checks the one-time migration from the former name (1.6.0) in a temp folder. The real %ProgramData%, %APPDATA%
    and Task Scheduler are never touched: the folders are passed in, and the task functions are replaced with fakes.
    Run from Windows PowerShell or pwsh:  powershell -ExecutionPolicy Bypass -File tools\Test-Migration.ps1
#>
$main = Join-Path $PSScriptRoot '..\pxdStartupScanner.ps1'
$text = [IO.File]::ReadAllText($main)
$text = $text.Substring(0, $text.LastIndexOf('Start-pxdStartupScanner -Gui'))
. ([scriptblock]::Create($text))

$fails = 0
function Check([string]$Name, [bool]$Ok) { if ($Ok) { Write-Host "PASS  $Name" -ForegroundColor Green } else { Write-Host "FAIL  $Name" -ForegroundColor Red; $script:fails++ } }

# Only this folder is created and removed again
$t = Join-Path ([IO.Path]::GetTempPath()) ('pss-migration-test-' + [guid]::NewGuid().ToString('N'))
$pd = Join-Path $t 'ProgramData'; $ad = Join-Path $t 'AppData'
$oldName = Get-PssFormerName $script:PssAppId
$realProgramData = $env:ProgramData
try {
    $script:PssReadOnly = $false
    function New-Old {
        New-Item -ItemType Directory -Force -Path (Join-Path $pd "$oldName\Backups"), (Join-Path $ad $oldName) | Out-Null
        Set-Content -LiteralPath (Join-Path $pd "$oldName\Backups\20261101-120000-0000000-abcd.json") -Value '{}'
        Set-Content -LiteralPath (Join-Path $pd "$oldName\boot-test.json") -Value '{"Label":"Before"}'
        Set-Content -LiteralPath (Join-Path $ad "$oldName\window.json") -Value '{"Left":1}'
    }
    # Fakes for Task Scheduler: an older version's boot test is armed
    $script:Armed = $true; $script:Registered = @(); $script:Removed = 0; $script:RegisterOk = $true
    function Get-PssFormerBootTasks { if ($script:Armed) { return @('Boot test - startup', 'Boot test - sign-in') } return @() }
    function Register-PssBootTasks([string]$Root) { $script:Registered += $Root; return @{ Ok = $script:RegisterOk; Message = 'fake' } }
    function Remove-PssFormerBootTasks { $script:Removed++; $script:Armed = $false }

    Check 'former name is derived from the app id' ($oldName -eq ('P' + 'ax' + 'StartupScanner'))
    Check 'former task folder is derived' ((Get-PssFormerTaskPath) -eq ('\' + 'P' + 'AX Startup Scanner\'))

    # ---- read-only: nothing moves
    New-Old
    $script:PssReadOnly = $true
    $r = Invoke-PssMigration -ProgramDataRoot $pd -AppDataRoot $ad -IsAdmin $true
    Check 'read-only run moves nothing' ($r.Count -eq 0 -and (Test-Path (Join-Path $pd $oldName)) -and (Test-Path (Join-Path $ad $oldName)))
    $script:PssReadOnly = $false

    # ---- not elevated: settings move, machine data stays and is still found
    $r = Invoke-PssMigration -ProgramDataRoot $pd -AppDataRoot $ad -IsAdmin $false
    Check 'not elevated: settings folder moved' ((Test-Path (Join-Path $ad 'pxdStartupScanner\window.json')) -and -not (Test-Path (Join-Path $ad $oldName)))
    Check 'not elevated: machine folder left alone' ((Test-Path (Join-Path $pd $oldName)) -and -not (Test-Path (Join-Path $pd 'pxdStartupScanner')))
    $env:ProgramData = $pd
    Check 'not elevated: data path falls back to the former folder' ((Get-PssDataPath) -eq (Join-Path $pd $oldName))
    $env:ProgramData = $realProgramData
    Check 'not elevated: armed test left as it was' ($script:Registered.Count -eq 0 -and $script:Removed -eq 0)

    # ---- elevated, re-arming fails: folder goes back so the old test still works
    $script:RegisterOk = $false
    $r = Invoke-PssMigration -ProgramDataRoot $pd -AppDataRoot $ad -IsAdmin $true
    Check 're-arm failed: machine folder moved back' ((Test-Path (Join-Path $pd "$oldName\boot-test.json")) -and -not (Test-Path (Join-Path $pd 'pxdStartupScanner')))
    Check 're-arm failed: old tasks kept' ($script:Removed -eq 0 -and $script:Armed)
    $script:RegisterOk = $true; $script:Registered = @()

    # ---- elevated: machine data moves, the armed test is re-armed under the new name
    $r = Invoke-PssMigration -ProgramDataRoot $pd -AppDataRoot $ad -IsAdmin $true
    $new = Join-Path $pd 'pxdStartupScanner'
    Check 'elevated: machine folder moved with its backups' ((Test-Path (Join-Path $new 'Backups\20261101-120000-0000000-abcd.json')) -and (Test-Path (Join-Path $new 'boot-test.json')) -and -not (Test-Path (Join-Path $pd $oldName)))
    Check 'elevated: boot test re-armed in the new folder' ($script:Registered.Count -eq 1 -and $script:Registered[0] -eq $new)
    Check 'elevated: old tasks removed' ($script:Removed -eq 1)
    $env:ProgramData = $pd
    Check 'data path is the new folder' ((Get-PssDataPath) -eq $new)
    $env:ProgramData = $realProgramData

    # ---- second run: no-op
    $r = Invoke-PssMigration -ProgramDataRoot $pd -AppDataRoot $ad -IsAdmin $true
    Check 'second run does nothing' ($r.Count -eq 0 -and $script:Registered.Count -eq 1 -and $script:Removed -eq 1)

    # ---- both folders exist: the new one wins, the old one is left
    New-Item -ItemType Directory -Force -Path (Join-Path $ad $oldName) | Out-Null
    $r = Invoke-PssMigration -ProgramDataRoot $pd -AppDataRoot $ad -IsAdmin $true
    Check 'existing new folder is never overwritten' ($r.Count -eq 0 -and (Test-Path (Join-Path $ad 'pxdStartupScanner\window.json')))

    # ---- full backups from older versions still load
    $ok = $true
    try { [void](Read-PssSnapshot ('{"Format":"' + $oldName + '.Backup","Items":[]}')); [void](Read-PssSnapshot '{"Format":"pxdStartupScanner.Backup","Items":[]}') } catch { $ok = $false }
    Check 'full backups with the former or new format load' $ok
    $bad = $false; try { [void](Read-PssSnapshot '{"Format":"Other.Backup"}') } catch { $bad = $true }
    Check 'other files are still refused' $bad
} finally {
    $env:ProgramData = $realProgramData
    if ($t -and (Split-Path $t -Leaf) -like 'pss-migration-test-*' -and (Test-Path -LiteralPath $t)) { Remove-Item -LiteralPath $t -Recurse -Force }
}
if ($fails) { Write-Host "$fails check(s) failed" -ForegroundColor Red; exit 1 } else { Write-Host 'All migration checks passed' -ForegroundColor Green }
