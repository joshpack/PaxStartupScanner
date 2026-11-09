<#
    Checks in-memory mode (PXD_INMEMORY=1, set by the pxd Toolkit console): the scanner writes nothing on the PC.
    APPDATA, LOCALAPPDATA, ProgramData, TEMP/TMP and the settings folder point at a temp folder for this process, and
    every file under it is compared before and after. Registry writes go to a fake key object; nothing real is changed.
    Run from Windows PowerShell or pwsh:  powershell -ExecutionPolicy Bypass -File tools\Test-InMemory.ps1
#>
$t = Join-Path ([IO.Path]::GetTempPath()) ('pss-inmemory-test-' + [guid]::NewGuid().ToString('N'))
$saved = @{}
foreach ($n in 'APPDATA', 'LOCALAPPDATA', 'ProgramData', 'TEMP', 'TMP', 'PSS_CONFIG_DIR', 'PXD_INMEMORY', 'PSS_READONLY') { $saved[$n] = [Environment]::GetEnvironmentVariable($n) }
$watch = @{ APPDATA = (Join-Path $t 'AppData'); LOCALAPPDATA = (Join-Path $t 'LocalAppData'); ProgramData = (Join-Path $t 'ProgramData'); TEMP = (Join-Path $t 'Temp') }
foreach ($d in $watch.Values) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
$startup = Join-Path $t 'Startup'   # stands in for a startup folder (not watched: the test deletes a file there)
New-Item -ItemType Directory -Force -Path $startup | Out-Null

$fails = 0
function Check([string]$Name, [bool]$Ok) { if ($Ok) { Microsoft.PowerShell.Utility\Write-Host "PASS  $Name" -ForegroundColor Green } else { Microsoft.PowerShell.Utility\Write-Host "FAIL  $Name" -ForegroundColor Red; $script:fails++ } }
# Windows' own shell caches (Microsoft\Windows\Caches\cversions.2.db ...) are left out: the shell writes them when the
# scan resolves shortcuts, and only show up here because %ProgramData%/%LOCALAPPDATA% point at the temp folder.
function Get-Files { @(Get-ChildItem -LiteralPath @($watch.Values) -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName } | Where-Object { $_ -notmatch '\\Microsoft(\\Windows(\\Caches(\\.*)?)?)?$' }) }
function Same($a, $b) { $d = @(Compare-Object @($a) @($b) -ErrorAction SilentlyContinue); if ($d.Count) { Microsoft.PowerShell.Utility\Write-Host ("      new or gone: " + (($d | ForEach-Object { $_.SideIndicator + " " + $_.InputObject }) -join "; ")) -ForegroundColor DarkGray }; return ($d.Count -eq 0) }

try {
    $env:APPDATA = $watch.APPDATA; $env:LOCALAPPDATA = $watch.LOCALAPPDATA; $env:ProgramData = $watch.ProgramData
    $env:TEMP = $watch.TEMP; $env:TMP = $watch.TEMP
    $env:PSS_CONFIG_DIR = Join-Path $watch.APPDATA 'pxdStartupScanner'
    $env:PSS_READONLY = $null
    $env:PXD_INMEMORY = '1'

    $main = Join-Path $PSScriptRoot '..\pxdStartupScanner.ps1'
    $text = [IO.File]::ReadAllText($main)
    $text = $text.Substring(0, $text.LastIndexOf('Start-pxdStartupScanner -Gui'))
    . ([scriptblock]::Create($text))

    # An older version's data folder: in-memory mode must not move it
    $oldData = Join-Path $watch.ProgramData (Get-PssFormerName $script:PssAppId)
    New-Item -ItemType Directory -Force -Path (Join-Path $oldData 'Backups') | Out-Null
    $script:MigrationCalls = 0
    $realMigration = ${function:Invoke-PssMigration}
    function Invoke-PssMigration { $script:MigrationCalls++; & $realMigration @args }

    # Console output is captured, never shown; no pauses
    $script:Out = New-Object System.Text.StringBuilder
    function Write-Host { param([Parameter(Position = 0)]$Object = '', [switch]$NoNewline, $ForegroundColor, $BackgroundColor) [void]$script:Out.Append([string]$Object); if (-not $NoNewline) { [void]$script:Out.AppendLine() } }
    function Clear-Host { }
    function Start-Sleep { }

    $before = Get-Files

    # ---- 1) a full run: scan this PC (read only) and print the report
    Start-pxdStartupScanner -Report
    $o = $script:Out.ToString()
    Check 'in-memory flag picked up from PXD_INMEMORY' ([bool]$script:PssInMemory)
    Check 'report run: in-memory line shown' ($o -match 'In-memory: nothing is saved on this PC\.')
    Check 'report run: header says IN-MEMORY' ($o -match 'IN-MEMORY')
    Check 'report run: migration skipped' ($script:MigrationCalls -eq 0 -and (Test-Path -LiteralPath $oldData) -and -not (Test-Path -LiteralPath (Join-Path $watch.ProgramData $script:PssAppId)))
    Check 'report run: no files created' (Same $before (Get-Files))

    # ---- 2) a faked Disable through the console details screen (registry writes go to a fake key)
    $script:Writes = New-Object System.Collections.Generic.List[string]
    function Open-PssKeyW([string]$Path, [switch]$Create) {
        $k = [pscustomobject]@{ Path = $Path }
        $k | Add-Member ScriptMethod GetValueNames { @() }
        $k | Add-Member ScriptMethod SetValue { param($n, $v, $kind) $script:Writes.Add("$($this.Path)\$n") }
        $k | Add-Member ScriptMethod DeleteValue { param($n) $script:Writes.Add("delete $($this.Path)\$n") }
        $k | Add-Member ScriptMethod Close { }
        return $k
    }
    Initialize-Pss
    $run = 'HKU\S-1-5-21-0\Software\Microsoft\Windows\CurrentVersion\Run'
    Add-PssItem -Category 'Run Key' -Name 'PssTestEntry' -Location $run -Command 'C:\PssTest\test.exe' -Image 'C:\PssTest\test.exe' -User 'TEST\user' -Trigger 'Logon' -ValueName 'PssTestEntry' -Op @{ Type = 'RegValue'; Key = $run; Name = 'PssTestEntry'; ApprovedRoot = 'HKU\S-1-5-21-0'; ApprovedKind = 'Run' }
    $lnk = Join-Path $startup 'PssTest.lnk'; Set-Content -LiteralPath $lnk -Value 'test'
    Add-PssItem -Category 'Startup Folder' -Name 'PssTest' -Location $lnk -Command 'C:\PssTest\test.exe' -Image 'C:\PssTest\test.exe' -User 'TEST\user' -Trigger 'Logon' -Kind 'File' -Op @{ Type = 'File'; Path = $lnk; ApprovedRoot = 'HKU\S-1-5-21-0'; ApprovedName = 'PssTest.lnk' }
    $id = 1
    foreach ($it in $script:PssItems) { $it.Id = $id++; $it.FileExists = $false; $it.Publisher = '(file missing)'; $it.SignText = '-'; Measure-PssRisk $it; Set-PssPermissions $it }
    $scan = [pscustomobject]@{ Items = $script:PssItems.ToArray(); Errors = @(); Computer = 'TEST-PC'; OS = 'Windows'; IsAdmin = $false; Users = @(); NotLoadedProfiles = @(); Uptime = (New-TimeSpan -Hours 1); Duration = 0.1; ScannedAt = (Get-Date); Version = $script:PssVersion; Boot = [pscustomobject]@{ Available = $false; Boots = @(); Delays = @() } }
    $runItem = $scan.Items[0]; $fileItem = $scan.Items[1]
    Check 'test items can be changed' ($runItem.CanDisable -and $fileItem.CanDelete)

    $script:Keys = New-Object System.Collections.Queue
    function Read-PssKey { if ($script:Keys.Count) { return [string]$script:Keys.Dequeue() } return '' }

    [void]$script:Out.Clear(); $before = Get-Files
    foreach ($k in 'd', 'n', '') { $script:Keys.Enqueue($k) }
    Show-PssDetails $scan 1
    $o = $script:Out.ToString()
    Check 'Disable: confirm prompt shown' ($o -match "In-memory mode: this change has no backup and can't be undone from here\. Continue\? \(y/N\)")
    Check '"n": nothing changed' ($script:Writes.Count -eq 0 -and $runItem.Enabled -and $o -match 'Nothing was changed')
    Check '"n": no files created' (Same $before (Get-Files))

    [void]$script:Out.Clear()
    foreach ($k in 'd', 'y', '') { $script:Keys.Enqueue($k) }
    Show-PssDetails $scan 1
    $o = $script:Out.ToString()
    Check '"y": the change is made (fake key written once)' ($script:Writes.Count -eq 1 -and -not $runItem.Enabled)
    Check '"y": says no backup was kept' ($o -match 'no backup was kept')
    Check '"y": no backup or other files created' (Same $before (Get-Files))

    # ---- 3) Delete of a startup-folder file: confirmed, removed for good, nothing copied anywhere
    [void]$script:Out.Clear()
    foreach ($k in 'x', 'n', '') { $script:Keys.Enqueue($k) }
    Show-PssDetails $scan 2
    Check 'Delete "n": file still there' ((Test-Path -LiteralPath $lnk) -and $script:Out.ToString() -match 'Continue\? \(y/N\)')
    foreach ($k in 'x', 'y', '') { $script:Keys.Enqueue($k) }
    Show-PssDetails $scan 2
    Check 'Delete "y": file removed, no backup copy, no files created' (-not (Test-Path -LiteralPath $lnk) -and $fileItem.State -eq 'Removed' -and (Same $before (Get-Files)))

    # ---- 4) everything that needs saved data says it's unavailable and writes nothing
    Check 'Undo unavailable' ((Invoke-PssUndo ([pscustomobject]@{ Steps = @() })).Message -like 'In-memory mode*')
    Check 'Restore unavailable' ((Restore-PssSnapshot ([pscustomobject]@{ Items = @() })).Message -like 'In-memory mode*')
    Check 'Boot test unavailable' ((Start-PssBootTest 'x').Message -like 'In-memory mode*' -and (Stop-PssBootTest).Message -like 'In-memory mode*' -and (Restart-PssNow).Message -like 'In-memory mode*')
    Check 'Window placement not saved' (-not (Save-PssPlacement $null))
    [void]$script:Out.Clear(); [void](Show-PssUndo $scan)
    Check 'Console Undo screen explains it' ($script:Out.ToString() -match 'Undo is not available')
    Check 'still no files created' (Same $before (Get-Files))

    # ---- 5) control: without in-memory mode the same Disable writes an undo backup (so the file check works)
    $script:PssInMemory = $false
    $runItem.Enabled = $true; Set-PssPermissions $runItem
    $res = Invoke-PssChange $runItem 'Disable'
    $backups = Join-Path $oldData 'Backups'   # (the former folder is still in use: it was never migrated)
    Check 'control: normal mode writes an undo backup' ($res.Ok -and @(Get-ChildItem -LiteralPath $backups -Filter *.json).Count -eq 1)
    Check 'control: the file check sees that write' (-not (Same $before (Get-Files)))
} finally {
    foreach ($n in $saved.Keys) { [Environment]::SetEnvironmentVariable($n, $saved[$n]) }
    if ($t -and (Split-Path $t -Leaf) -like 'pss-inmemory-test-*' -and (Test-Path -LiteralPath $t)) { Remove-Item -LiteralPath $t -Recurse -Force }
}
if ($fails) { Microsoft.PowerShell.Utility\Write-Host "$fails check(s) failed" -ForegroundColor Red; exit 1 } else { Microsoft.PowerShell.Utility\Write-Host 'All in-memory checks passed' -ForegroundColor Green }
