#Requires -Version 5.1
<#
.SYNOPSIS
    PAX Startup Scanner - finds everything that starts with Windows, shows what it is and where
    it lives, flags suspicious entries and shows what is slowing boot down.

.DESCRIPTION
    IT diagnostic tool. Nothing is installed. It only changes the system when you choose
    Disable or Delete on an item; every change is backed up to
    %ProgramData%\PaxStartupScanner\Backups first and can be undone from the Undo list.
    Run it from an elevated PowerShell prompt straight from GitHub:

        irm https://raw.githubusercontent.com/joshpack/PaxStartupScanner/main/PaxStartupScanner.ps1 | iex

    Scans: Run/RunOnce keys (machine + every loaded user), startup folders (all profiles),
    scheduled tasks, auto-start services and drivers, Winlogon, Explorer hooks, AppInit DLLs,
    Image File Execution Options, BootExecute, LSA packages, print monitors, Active Setup,
    WMI event subscriptions, cmd AutoRun, logon/startup scripts, Store app startup tasks,
    netsh helpers and the screensaver.

.PARAMETER Gui
    Open the graphical view instead of the console menu.
.PARAMETER Report
    Non-interactive: scan, print the summary and flagged items, then return.
.PARAMETER Export
    Write a report to this path (.html, .csv or .json) after scanning.
.PARAMETER ReadOnly
    Look only: nothing on the PC is written or changed (no Disable/Delete/Undo, boot tests,
    restarts, exports or Regedit jump). Also turned on by $env:PSS_READONLY = '1', which works with irm | iex.
#>
[CmdletBinding()]
param(
    [switch]$Gui,
    [switch]$Report,
    [string]$Export,
    [switch]$ReadOnly
)

$script:PssVersion = '1.3.0'
$script:PssUrl     = 'https://raw.githubusercontent.com/joshpack/PaxStartupScanner/main/PaxStartupScanner.ps1'
$script:PssSelfPath = $PSCommandPath   # empty when run through irm | iex

# ======================================================================================
#  Scanner engine
# ======================================================================================

function Initialize-PssRegistry {
    if (-not $script:PssHKLM) { $script:PssHKLM = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64) }
    if (-not $script:PssHKU) { $script:PssHKU = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Registry64) }
}

function Initialize-Pss {
    Initialize-PssRegistry
    $script:PssFileCache = @{}
    $win = $env:SystemRoot
    $dirs = New-Object System.Collections.Generic.List[string]
    foreach ($d in @("$win\System32", $win, "$win\System32\wbem", "$win\System32\WindowsPowerShell\v1.0")) { $dirs.Add($d) }
    foreach ($d in ($env:PATH -split ';')) {
        if ($d -and -not $dirs.Contains($d)) { $dirs.Add([Environment]::ExpandEnvironmentVariables($d)) }
    }
    $script:PssSearchDirs = $dirs
    $script:PssItems = New-Object System.Collections.Generic.List[object]
    $script:PssErrors = New-Object System.Collections.Generic.List[string]
}

function Set-PssStatus {
    param([string]$Stage, [int]$Pct, $Status)
    if ($Status) { $Status.Stage = $Stage; $Status.Pct = $Pct }
    if ($script:PssConsoleProgress) {
        $w = 30; $f = [int]($w * $Pct / 100)
        $bar = ([string][char]0x2588) * $f + ([string][char]0x2591) * ($w - $f)
        $line = "`r  $bar $($Pct.ToString().PadLeft(3))%  $Stage"
        Write-Host ($line.PadRight(90)) -NoNewline -ForegroundColor Cyan
    }
}

function Open-PssKey([string]$Path) {
    $i = $Path.IndexOf('\')
    if ($i -lt 0) { return $null }
    $hive = $Path.Substring(0, $i); $sub = $Path.Substring($i + 1)
    $base = $null
    if ($hive -eq 'HKLM') { $base = $script:PssHKLM } elseif ($hive -eq 'HKU') { $base = $script:PssHKU }
    if (-not $base) { return $null }
    try { return $base.OpenSubKey($sub, $false) } catch { return $null }
}

function Open-PssSub($Key, [string]$Name) {
    if (-not $Key) { return $null }
    try { return $Key.OpenSubKey($Name, $false) } catch { return $null }
}

function Get-PssRegValue($Key, [string]$Name) {
    if (-not $Key) { return $null }
    try { return $Key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) } catch { return $null }
}

function Convert-PssNtPath([string]$p) {
    if (-not $p) { return $p }
    $p = $p.Trim()
    if ($p.StartsWith('\??\')) { $p = $p.Substring(4) }
    if ($p -match '^(?i)\\SystemRoot\\') { $p = $env:SystemRoot + $p.Substring(11) }
    elseif ($p -match '^(?i)SystemRoot\\') { $p = $env:SystemRoot + '\' + $p.Substring(11) }
    elseif ($p -match '^(?i)System32\\') { $p = $env:SystemRoot + '\' + $p }
    return $p
}

function Find-PssFile([string]$p) {
    if ([string]::IsNullOrWhiteSpace($p)) { return $null }
    $p = (Convert-PssNtPath ([Environment]::ExpandEnvironmentVariables($p.Trim().Trim('"')))).Trim()
    if (-not $p) { return $null }
    if ($script:PssFileCache.ContainsKey($p)) { return $script:PssFileCache[$p] }
    $result = $null
    try {
        $hasExt = [IO.Path]::HasExtension($p)
        $cands = New-Object System.Collections.Generic.List[string]
        if ([IO.Path]::IsPathRooted($p)) {
            $cands.Add($p); if (-not $hasExt) { $cands.Add("$p.exe") }
        } else {
            foreach ($d in $script:PssSearchDirs) {
                $cands.Add([IO.Path]::Combine($d, $p))
                if (-not $hasExt) { $cands.Add([IO.Path]::Combine($d, "$p.exe")) }
            }
        }
        foreach ($c in $cands) { if ([IO.File]::Exists($c)) { $result = [IO.Path]::GetFullPath($c); break } }
    } catch { $result = $null }
    $script:PssFileCache[$p] = $result
    return $result
}

function Split-PssArgs([string]$s) {
    if (-not $s) { return @() }
    return @([regex]::Matches($s, '"[^"]*"|\S+') | ForEach-Object { $_.Value.Trim('"') })
}

function Resolve-PssImage([string]$Command) {
    # Returns @{ Image; Found; Host } for a raw command line.
    $r = @{ Image = $null; Found = $false; Host = '' }
    if ([string]::IsNullOrWhiteSpace($Command)) { return $r }
    $c = Convert-PssNtPath ([Environment]::ExpandEnvironmentVariables($Command))
    $exe = $null; $rest = ''; $found = $null
    if ($c.StartsWith('"')) {
        $e = $c.IndexOf('"', 1)
        if ($e -gt 0) { $exe = $c.Substring(1, $e - 1); $rest = $c.Substring($e + 1).Trim() } else { $exe = $c.Trim('"') }
        $found = Find-PssFile $exe
    } else {
        $parts = $c.Split(' ')
        $max = [Math]::Min($parts.Count, 12)
        for ($i = 0; $i -lt $max; $i++) {
            $cand = ($parts[0..$i] -join ' ').TrimEnd(',')
            $f = Find-PssFile $cand
            if ($f) {
                $found = $f; $exe = $cand
                if ($i + 1 -lt $parts.Count) { $rest = ($parts[($i + 1)..($parts.Count - 1)] -join ' ') }
                break
            }
        }
        if (-not $found) {
            $exe = $parts[0].TrimEnd(',')
            if ($parts.Count -gt 1) { $rest = ($parts[1..($parts.Count - 1)] -join ' ') }
        }
    }
    $r.Image = if ($found) { $found } else { $exe }
    $r.Found = [bool]$found

    # Unwrap host processes so we check the file that actually runs
    $leaf = ''
    try { $leaf = [IO.Path]::GetFileName([string]$r.Image).ToLowerInvariant() } catch {}
    $target = $null
    $a = Split-PssArgs $rest
    switch ($leaf) {
        'rundll32.exe' { $t0 = $a | Where-Object { $_ -notmatch '^/' } | Select-Object -First 1; if ($t0) { $target = ($t0 -split ',')[0] } }
        'regsvr32.exe' { $target = $a | Where-Object { $_ -notmatch '^[/-]' } | Select-Object -Last 1 }
        { $_ -in 'wscript.exe', 'cscript.exe' } { $target = $a | Where-Object { $_ -notmatch '^/' } | Select-Object -First 1 }
        'mshta.exe' { if ($a.Count -and $a[0] -notmatch '^(?i)(https?|javascript|vbscript):') { $target = $a[0] } }
        { $_ -in 'powershell.exe', 'pwsh.exe' } {
            for ($i = 0; $i -lt $a.Count - 1; $i++) { if ($a[$i] -match '^(?i)-f(ile)?$') { $target = $a[$i + 1]; break } }
        }
        'cmd.exe' {
            for ($i = 0; $i -lt $a.Count - 1; $i++) {
                if ($a[$i] -match '^(?i)/[ck]$') { if ($a[$i + 1] -match '(?i)\.(bat|cmd|exe|vbs|ps1)$') { $target = $a[$i + 1] }; break }
            }
        }
    }
    if ($target) {
        $t = Find-PssFile $target
        if ($t) { $r.Host = $leaf; $r.Image = $t; $r.Found = $true }
        elseif ([IO.Path]::IsPathRooted([Environment]::ExpandEnvironmentVariables($target))) {
            $r.Host = $leaf; $r.Image = [Environment]::ExpandEnvironmentVariables($target); $r.Found = $false
        }
    }
    return $r
}

function Add-PssItem {
    param(
        [string]$Category, [string]$Name, [string]$Location, [string]$Command,
        [string]$Image, [bool]$Enabled = $true, [string]$User = '', [string]$Trigger = '',
        [string]$RegKey = '', [string]$ValueName = '', [string]$Extra = '', [string]$ServiceName = '',
        [string]$Publisher = '', [string]$Kind = '', [bool]$NoImage = $false,
        # How Disable/Delete work for this entry (see Invoke-PssChange)
        [hashtable]$Op = $null
    )
    $res = $null
    # An explicit but empty -Image (e.g. a CLSID with no registered DLL) means there is no file to check
    if (-not $NoImage -and $PSBoundParameters.ContainsKey('Image') -and -not $Image) {
        $NoImage = $true; if (-not $Extra) { $Extra = 'No file registered for this entry' }
    }
    if (-not $NoImage) {
        if ($Image) { $res = @{ Image = (Convert-PssNtPath ([Environment]::ExpandEnvironmentVariables($Image.Trim('"')))); Host = '' }
            $f = Find-PssFile $res.Image; if ($f) { $res.Image = $f }
        } else { $res = Resolve-PssImage $Command }
    }
    # Squirrel-style launchers ("Update.exe --processStart Discord.exe") start a different exe than the one in the command
    $alt = ''
    if ($Command -match '(?i)--processStart(?:AndWait)?\s+"?([^"\s]+\.exe)') { $alt = $Matches[1] }
    $it = [pscustomobject][ordered]@{
        Id = 0; Risk = 'OK'; RiskScore = 0; Category = $Category; Name = $Name; Enabled = $Enabled
        EnabledText = $(if ($Enabled) { 'Yes' } else { 'No' }); User = $User; Trigger = $Trigger
        Command = $Command; ImagePath = $(if ($res) { $res.Image } else { '' }); Via = $(if ($res) { $res.Host } else { '' })
        Location = $Location; RegKey = $RegKey; ValueName = $ValueName; ServiceName = $ServiceName; Extra = $Extra; Kind = $Kind
        NoImage = $NoImage; AltExe = $alt
        FileExists = $false; Size = $null; Created = $null; Modified = $null; Hidden = $false
        Publisher = $Publisher; Company = ''; Description = ''; Product = ''; Version = ''
        SignStatus = ''; Signer = ''; SignText = ''; IsMicrosoft = $false
        Running = $false; ProcCount = 0; MemoryMB = 0; CpuSec = 0; RunText = ''
        BootDelayMs = 0; BootDelayCount = 0; BootDelayText = ''; BootDelayLast = $null; Impact = ''
        Flags = ''; FlagList = @(); Sha256 = ''
        Op = $Op; State = ''; CanDisable = $false; CanDelete = $false; ActionNote = ''
        Vendor = ''; SigGroup = ''; Scope = ''
    }
    $script:PssItems.Add($it)
}

function Get-PssUserHives {
    $list = @()
    foreach ($sid in $script:PssHKU.GetSubKeyNames()) {
        if ($sid -match '^S-1-(5-21|12-1)-[\d-]+$') {
            $name = $sid
            try { $name = (New-Object System.Security.Principal.SecurityIdentifier $sid).Translate([System.Security.Principal.NTAccount]).Value } catch {}
            $list += [pscustomobject]@{ Sid = $sid; User = $name; Root = "HKU\$sid" }
        }
    }
    return $list
}

function Get-PssApproved([string]$Root, [string]$Kind, [string]$Name) {
    # StartupApproved: byte 0 odd = disabled in Task Manager / Settings
    $k = Open-PssKey "$Root\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\$Kind"
    if (-not $k) { return $true }
    try {
        $v = $k.GetValue($Name, $null)
        if ($v -is [byte[]] -and $v.Length -gt 0) { return (($v[0] -band 1) -eq 0) }
        return $true
    } finally { $k.Close() }
}

function Resolve-PssMsiShortcut([string]$Lnk) {
    # Returns the real program behind a Windows Installer advertised shortcut, or $null
    try {
        $wi = New-Object -ComObject WindowsInstaller.Installer
        $get = [Reflection.BindingFlags]::GetProperty
        $rec = $wi.GetType().InvokeMember('ShortcutTarget', $get, $null, $wi, @($Lnk))
        $prod = $rec.GetType().InvokeMember('StringData', $get, $null, $rec, @(1))
        $comp = $rec.GetType().InvokeMember('StringData', $get, $null, $rec, @(3))
        if ($prod -and $comp) {
            $path = [string]$wi.GetType().InvokeMember('ComponentPath', $get, $null, $wi, @($prod, $comp))
            if ($path) { return $path }
        }
    } catch {}
    return $null
}

function Get-PssClsid([string]$Clsid) {
    foreach ($p in @("SOFTWARE\Classes\CLSID\$Clsid", "SOFTWARE\Classes\WOW6432Node\CLSID\$Clsid")) {
        $k = Open-PssKey "HKLM\$p"
        if ($k) {
            $name = [string]$k.GetValue('')
            $dll = $null
            foreach ($s in 'InprocServer32', 'LocalServer32') {
                $sk = (Open-PssSub $k $s)
                if ($sk) { $dll = [string](Get-PssRegValue $sk ''); $sk.Close(); if ($dll) { break } }
            }
            $k.Close()
            return @{ Name = $name; Dll = $dll }
        }
    }
    return @{ Name = ''; Dll = '' }
}

# ---------- collectors ----------

function Get-PssRunKeys {
    $defs = @(
        @{ Sub = 'Software\Microsoft\Windows\CurrentVersion\Run'; Cat = 'Run Key'; Appr = 'Run' }
        @{ Sub = 'Software\Microsoft\Windows\CurrentVersion\RunOnce'; Cat = 'RunOnce'; Appr = '' }
        @{ Sub = 'Software\Microsoft\Windows\CurrentVersion\RunServices'; Cat = 'Run Key'; Appr = '' }
        @{ Sub = 'Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'; Cat = 'RunOnce'; Appr = '' }
        @{ Sub = 'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Cat = 'Run Key'; Appr = 'Run32' }
        @{ Sub = 'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'; Cat = 'RunOnce'; Appr = '' }
        @{ Sub = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'; Cat = 'Policy Run'; Appr = '' }
        @{ Sub = 'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'; Cat = 'Policy Run'; Appr = '' }
    )
    $roots = @([pscustomobject]@{ Root = 'HKLM'; User = 'All users' }) + @($script:PssUsers | ForEach-Object { [pscustomobject]@{ Root = $_.Root; User = $_.User } })
    foreach ($r in $roots) {
        foreach ($d in $defs) {
            $path = "$($r.Root)\$($d.Sub)"
            $k = Open-PssKey $path
            if (-not $k) { continue }
            foreach ($n in $k.GetValueNames()) {
                $v = [string](Get-PssRegValue $k $n)
                if (-not $v) { continue }
                $en = $true; if ($d.Appr) { $en = Get-PssApproved $r.Root $d.Appr $n }
                $nm = if ($n) { $n } else { '(Default)' }
                # Disable uses Task Manager's StartupApproved flag (Run32 only exists for HKLM)
                $appr = $d.Appr; if ($appr -eq 'Run32' -and $r.Root -ne 'HKLM') { $appr = '' }
                $op = @{ Type = 'RegValue'; Key = $path; Name = $n; ApprovedRoot = $(if ($appr) { $r.Root } else { '' }); ApprovedKind = $appr }
                Add-PssItem -Category $d.Cat -Name $nm -Location $path -Command $v -Enabled $en -User $r.User -Trigger 'Logon' -RegKey $path -ValueName $n -Op $op
            }
            $k.Close()
        }
        # Legacy Windows\Load / Windows\Run (user hives)
        if ($r.Root -ne 'HKLM') {
            $path = "$($r.Root)\Software\Microsoft\Windows NT\CurrentVersion\Windows"
            $k = Open-PssKey $path
            if ($k) {
                foreach ($n in 'Load', 'Run') {
                    $v = [string](Get-PssRegValue $k $n)
                    if ($v) { Add-PssItem -Category 'Run Key' -Name "Windows\$n" -Location $path -Command $v -User $r.User -Trigger 'Logon' -RegKey $path -ValueName $n -Extra 'Legacy load point (rarely used legitimately)' -Op @{ Type = 'RegValue'; Key = $path; Name = $n } }
                }
                $k.Close()
            }
        }
    }
}

function Get-PssStartupFolders {
    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell } catch {}
    $folders = @(@{ Path = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"; User = 'All users'; Root = 'HKLM' })
    $profRoot = Split-Path $env:PUBLIC -Parent
    foreach ($p in (Get-ChildItem -LiteralPath $profRoot -Directory -Force -ErrorAction SilentlyContinue)) {
        $f = Join-Path $p.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
        if (Test-Path -LiteralPath $f) {
            $u = $script:PssUsers | Where-Object { $_.User -match "\\$([regex]::Escape($p.Name))$" } | Select-Object -First 1
            $folders += @{ Path = $f; User = $p.Name; Root = $(if ($u) { $u.Root } else { '' }) }
        }
    }
    foreach ($fd in $folders) {
        foreach ($file in (Get-ChildItem -LiteralPath $fd.Path -File -Force -ErrorAction SilentlyContinue)) {
            if ($file.Name -eq 'desktop.ini') { continue }
            $cmd = $file.FullName; $img = $file.FullName; $extra = ''
            if ($file.Extension -eq '.lnk' -and $shell) {
                try {
                    $s = $shell.CreateShortcut($file.FullName)
                    if ($s.TargetPath) { $img = $s.TargetPath; $cmd = ('"{0}" {1}' -f $s.TargetPath, $s.Arguments).Trim() }
                    # Windows Installer "advertised" shortcuts point at an icon file in C:\Windows\Installer; ask MSI for the real program
                    if ($s.TargetPath -match '(?i)\\Installer\\\{[0-9A-F-]+\}\\') {
                        $msi = Resolve-PssMsiShortcut $file.FullName
                        if ($msi) { $img = $msi; $cmd = ('"{0}" {1}' -f $msi, $s.Arguments).Trim(); $extra = 'Windows Installer (advertised) shortcut' }
                    }
                } catch {}
            }
            $en = $true; if ($fd.Root) { $en = Get-PssApproved $fd.Root 'StartupFolder' $file.Name }
            $res = Resolve-PssImage $cmd
            $op = @{ Type = 'File'; Path = $file.FullName; ApprovedRoot = $fd.Root; ApprovedName = $file.Name }
            Add-PssItem -Category 'Startup Folder' -Name $file.BaseName -Location $file.FullName -Command $cmd -Image $res.Image -Enabled $en -User $fd.User -Trigger 'Logon' -Kind 'File' -Extra $extra -Op $op
        }
    }
}

function Get-PssTasks {
    try {
        $svc = New-Object -ComObject Schedule.Service
        $svc.Connect()
    } catch { $script:PssErrors.Add("Scheduled tasks: $($_.Exception.Message)"); return }
    $stack = New-Object System.Collections.Stack
    $stack.Push($svc.GetFolder('\'))
    while ($stack.Count) {
        $folder = $stack.Pop()
        try { foreach ($sf in $folder.GetFolders(0)) { $stack.Push($sf) } } catch {}
        $tasks = $null
        try { $tasks = $folder.GetTasks(1) } catch { continue }
        foreach ($t in $tasks) {
            try {
                $x = [xml]$t.Xml
                $trig = @()
                if ($x.Task.Triggers) {
                    foreach ($n in $x.Task.Triggers.ChildNodes) {
                        if ($n.NodeType -ne 'Element') { continue }
                        $trig += switch ($n.LocalName) {
                            'BootTrigger' { 'Boot' } 'LogonTrigger' { 'Logon' } 'TimeTrigger' { 'Time' }
                            'CalendarTrigger' { 'Schedule' } 'IdleTrigger' { 'Idle' } 'EventTrigger' { 'Event' }
                            'RegistrationTrigger' { 'Registration' } 'SessionStateChangeTrigger' { 'Session' }
                            default { $n.LocalName -replace 'Trigger$' }
                        }
                    }
                }
                $trigText = if ($trig) { ($trig | Select-Object -Unique) -join ', ' } else { 'On demand' }
                $runAs = ''
                try { $pr = $x.Task.Principals.Principal; $runAs = [string]$pr.UserId; if (-not $runAs) { $runAs = [string]$pr.GroupId }; if ($pr.RunLevel -eq 'HighestAvailable') { $runAs += ' (highest)' } } catch {}
                $author = ''; try { $author = [string]$x.Task.RegistrationInfo.Author } catch {}
                $hidden = $false; try { $hidden = ($x.Task.Settings.Hidden -eq 'true') } catch {}
                $extra = @(); if ($author) { $extra += "Author: $author" }; if ($hidden) { $extra += 'Hidden task' }
                try { if ($t.LastRunTime -and $t.LastRunTime.Year -gt 2000) { $extra += ('Last run: {0:yyyy-MM-dd HH:mm}' -f $t.LastRunTime) } } catch {}
                $acts = @()
                if ($x.Task.Actions) {
                    foreach ($e in @($x.Task.Actions.Exec)) { if ($e -and $e.Command) { $acts += @{ T = 'Exec'; C = [string]$e.Command; A = [string]$e.Arguments } } }
                    foreach ($e in @($x.Task.Actions.ComHandler)) { if ($e -and $e.ClassId) { $acts += @{ T = 'Com'; C = [string]$e.ClassId; A = '' } } }
                }
                if (-not $acts) { continue }
                foreach ($a in $acts) {
                    if ($a.T -eq 'Exec') {
                        $cmd = $a.C.Trim()
                        $full = if ($cmd.StartsWith('"')) { "$cmd $($a.A)" } else { "`"$cmd`" $($a.A)" }
                        $res = Resolve-PssImage $full
                        Add-PssItem -Category 'Scheduled Task' -Name $t.Path -Location "Task Scheduler $($t.Path)" -Command ("$cmd $($a.A)").Trim() -Image $res.Image -Enabled ([bool]$t.Enabled) -User $runAs -Trigger $trigText -Extra ($extra -join '; ') -Kind 'Task' -Op @{ Type = 'Task'; Path = $t.Path }
                    } else {
                        $c = Get-PssClsid $a.C
                        Add-PssItem -Category 'Scheduled Task' -Name $t.Path -Location "Task Scheduler $($t.Path)" -Command "COM handler $($a.C) $($c.Name)" -Image $c.Dll -NoImage (-not $c.Dll) -Enabled ([bool]$t.Enabled) -User $runAs -Trigger $trigText -Extra ($extra -join '; ') -Kind 'Task' -Op @{ Type = 'Task'; Path = $t.Path }
                    }
                }
            } catch {}
        }
    }
}

function Get-PssServices {
    $svcList = @(); $drvList = @()
    try { $svcList = @(Get-Service -ErrorAction SilentlyContinue) } catch {}
    try { $drvList = @([System.ServiceProcess.ServiceController]::GetDevices()) } catch {}
    foreach ($s in ($svcList + $drvList)) {
        $st = [string]$s.StartType
        $isDriver = $drvList -contains $s
        if ($isDriver) { if ($st -notin 'Boot', 'System', 'Automatic') { continue } }
        elseif ($st -ne 'Automatic') { continue }
        $path = "HKLM\SYSTEM\CurrentControlSet\Services\$($s.ServiceName)"
        $k = Open-PssKey $path
        $img = ''; $acct = ''; $delayed = $false; $dll = ''; $hasTrig = $false
        if ($k) {
            $img = [string](Get-PssRegValue $k 'ImagePath')
            $acct = [string]$k.GetValue('ObjectName')
            $delayed = ($k.GetValue('DelayedAutostart') -eq 1)
            $dll = [string](Get-PssRegValue $k 'ServiceDll')
            $pk = (Open-PssSub $k 'Parameters'); if ($pk) { $d2 = [string](Get-PssRegValue $pk 'ServiceDll'); if ($d2) { $dll = $d2 }; $pk.Close() }
            $tk = (Open-PssSub $k 'TriggerInfo'); if ($tk) { $hasTrig = $true; $tk.Close() }
            $k.Close()
        }
        # Per-user service instances (e.g. cbdhsvc_2c41dfa4) keep their ServiceDll on the template service
        if (-not $dll -and $s.ServiceName -match '^(.+)_[0-9a-fA-F]{4,}$') {
            $tk2 = Open-PssKey "HKLM\SYSTEM\CurrentControlSet\Services\$($Matches[1])"
            if ($tk2) {
                $dll = [string](Get-PssRegValue $tk2 'ServiceDll')
                $pk2 = Open-PssSub $tk2 'Parameters'; if ($pk2) { $d3 = [string](Get-PssRegValue $pk2 'ServiceDll'); if ($d3) { $dll = $d3 }; $pk2.Close() }
                $tk2.Close()
            }
        }
        if ($isDriver -and -not $img) { $img = "System32\drivers\$($s.ServiceName).sys" }
        $trig = if ($isDriver) { "$st start" } elseif ($delayed) { 'Automatic (delayed)' } else { 'Automatic' }
        if ($hasTrig -and -not $isDriver) { $trig += ' + trigger' }
        $status = [string]$s.Status
        $extra = "Status: $status"; if ($acct) { $extra += "; Account: $acct" }
        $res = Resolve-PssImage $img
        $image = $res.Image
        if ($dll) { $image = $dll; $extra += "; Host: $img" }
        # sc.exe start type to put back when the item is enabled again
        $orig = switch ($st) { 'Boot' { 'boot' } 'System' { 'system' } default { if ($delayed) { 'delayed-auto' } else { 'auto' } } }
        $op = @{ Type = 'Service'; Name = $s.ServiceName; Start = $orig; IsDriver = $isDriver }
        Add-PssItem -Category $(if ($isDriver) { 'Driver' } else { 'Service' }) -Name ("{0} ({1})" -f $s.DisplayName, $s.ServiceName) -Location $path -Command $img -Image $image -User $acct -Trigger $trig -RegKey $path -Extra $extra -ServiceName $s.ServiceName -Kind 'Service' -Op $op
        $script:PssItems[$script:PssItems.Count - 1].Running = ($status -eq 'Running')
    }
}

function Get-PssWinlogon {
    $roots = @([pscustomobject]@{ Root = 'HKLM'; User = 'All users' }) + @($script:PssUsers | ForEach-Object { [pscustomobject]@{ Root = $_.Root; User = $_.User } })
    foreach ($r in $roots) {
        $path = "$($r.Root)\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $k = Open-PssKey $path
        if (-not $k) { continue }
        foreach ($n in 'Shell', 'Userinit', 'Taskman', 'AppSetup', 'VmApplet') {
            $v = [string](Get-PssRegValue $k $n)
            if (-not $v) { continue }
            foreach ($part in ($v -split ',')) {
                $part = $part.Trim(); if (-not $part) { continue }
                $default = ($n -eq 'Shell' -and $part -match '^(?i)explorer(\.exe)?$') -or ($n -eq 'Userinit' -and $part -match '^(?i)(C:\\Windows\\system32\\)?userinit(\.exe)?$') -or ($n -eq 'VmApplet' -and $part -match '(?i)SystemPropertiesPerformance')
                # Removing a non-default part rewrites the value; an emptied machine Shell/Userinit gets the Windows default back
                $dflt = ''
                if ($r.Root -eq 'HKLM' -and $n -eq 'Shell') { $dflt = 'explorer.exe' }
                if ($r.Root -eq 'HKLM' -and $n -eq 'Userinit') { $dflt = 'C:\Windows\system32\userinit.exe,' }
                $op = @{ Type = 'ListPart'; Key = $path; Name = $n; Part = $part; Sep = ','; Default = $dflt }
                Add-PssItem -Category 'Winlogon' -Name "Winlogon\$n" -Location $path -Command $part -User $r.User -Trigger 'Logon' -RegKey $path -ValueName $n -Extra $(if ($default) { 'Windows default value' } else { 'NON-DEFAULT value' }) -Kind $(if ($default) { 'Default' } else { 'Modified' }) -Op $op
            }
        }
        $nk = (Open-PssSub $k 'Notify')
        if ($nk) {
            foreach ($sn in $nk.GetSubKeyNames()) {
                $sk = (Open-PssSub $nk $sn); $dll = [string](Get-PssRegValue $sk 'DllName'); $sk.Close()
                if ($dll) { Add-PssItem -Category 'Winlogon' -Name "Notify\$sn" -Location "$path\Notify\$sn" -Command $dll -Image $dll -User $r.User -Trigger 'Logon' -RegKey "$path\Notify\$sn" -Kind 'Modified' -Op @{ Type = 'RegKey'; Key = "$path\Notify\$sn" } }
            }
            $nk.Close()
        }
        $k.Close()
    }
}

function Get-PssMisc {
    # AppInit DLLs
    foreach ($p in 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        $k = Open-PssKey $p; if (-not $k) { continue }
        $v = [string](Get-PssRegValue $k 'AppInit_DLLs'); $load = $k.GetValue('LoadAppInit_DLLs')
        if ($v) {
            foreach ($d in ($v -split '[,\s]+' | Where-Object { $_ })) {
                Add-PssItem -Category 'AppInit' -Name ([IO.Path]::GetFileName($d)) -Location $p -Command $d -Image $d -Enabled ($load -eq 1) -Trigger 'Every GUI process' -RegKey $p -ValueName 'AppInit_DLLs' -Kind 'Modified' -Op @{ Type = 'ListPart'; Key = $p; Name = 'AppInit_DLLs'; Part = $d; Sep = ' '; Default = '' }
            }
        }
        $k.Close()
    }
    # Image File Execution Options debuggers + SilentProcessExit
    foreach ($base in 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
        $k = Open-PssKey $base; if (-not $k) { continue }
        foreach ($sn in $k.GetSubKeyNames()) {
            $sk = (Open-PssSub $k $sn); if (-not $sk) { continue }
            $dbg = [string](Get-PssRegValue $sk 'Debugger')
            if ($dbg) { Add-PssItem -Category 'IFEO' -Name "$sn -> Debugger" -Location "$base\$sn" -Command $dbg -Trigger "When $sn starts" -RegKey "$base\$sn" -ValueName 'Debugger' -Extra 'Runs instead of the target program' -Kind 'Modified' -Op @{ Type = 'RegValue'; Key = "$base\$sn"; Name = 'Debugger' } }
            $sk.Close()
        }
        $k.Close()
    }
    $spe = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
    $k = Open-PssKey $spe
    if ($k) {
        foreach ($sn in $k.GetSubKeyNames()) {
            $sk = (Open-PssSub $k $sn); $m = [string](Get-PssRegValue $sk 'MonitorProcess'); $sk.Close()
            if ($m) { Add-PssItem -Category 'IFEO' -Name "$sn -> MonitorProcess" -Location "$spe\$sn" -Command $m -Trigger "When $sn exits" -RegKey "$spe\$sn" -ValueName 'MonitorProcess' -Kind 'Modified' -Op @{ Type = 'RegValue'; Key = "$spe\$sn"; Name = 'MonitorProcess' } }
        }
        $k.Close()
    }
    # Session Manager: BootExecute and friends
    $sm = 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager'
    $k = Open-PssKey $sm
    if ($k) {
        foreach ($n in 'BootExecute', 'SetupExecute', 'Execute', 'S0InitialCommand') {
            foreach ($v in @($k.GetValue($n))) {
                if (-not $v) { continue }
                $def = ($v -match '^(?i)autocheck autochk \*$')
                $first = ($v -split ' ')[0]
                $img = $first; if ($first -eq 'autocheck') { $img = ($v -split ' ')[1] }
                Add-PssItem -Category 'Boot Execute' -Name "$n" -Location $sm -Command $v -Image "$env:SystemRoot\System32\$img.exe" -Trigger 'Before Windows starts' -RegKey $sm -ValueName $n -Extra $(if ($def) { 'Windows default value' } else { 'NON-DEFAULT value' }) -Kind $(if ($def) { 'Default' } else { 'Modified' }) -Op @{ Type = 'ListPart'; Key = $sm; Name = $n; Part = $v; Sep = 'multi'; Default = '' }
            }
        }
        $k.Close()
    }
    # LSA packages
    foreach ($p in 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa', 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig') {
        $k = Open-PssKey $p; if (-not $k) { continue }
        foreach ($n in 'Authentication Packages', 'Notification Packages', 'Security Packages') {
            foreach ($v in @($k.GetValue($n))) {
                foreach ($pkg in ($v -split '\s+' | Where-Object { $_ -and $_ -ne '""' })) {
                    $dll = if ($pkg -match '\.dll$') { $pkg } else { "$pkg.dll" }
                    Add-PssItem -Category 'LSA' -Name "$n\$pkg" -Location $p -Command $pkg -Image "$env:SystemRoot\System32\$dll" -Trigger 'Loaded by LSASS at boot' -RegKey $p -ValueName $n -Op @{ Type = 'ListPart'; Key = $p; Name = $n; Part = $pkg; Sep = 'multi'; Default = '' }
                }
            }
        }
        $k.Close()
    }
    # Print monitors
    $pm = 'HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors'
    $k = Open-PssKey $pm
    if ($k) {
        foreach ($sn in $k.GetSubKeyNames()) {
            $sk = (Open-PssSub $k $sn); $d = [string](Get-PssRegValue $sk 'Driver'); $sk.Close()
            if ($d) { Add-PssItem -Category 'Print Monitor' -Name $sn -Location "$pm\$sn" -Command $d -Image "$env:SystemRoot\System32\$d" -Trigger 'Loaded by spooler' -RegKey "$pm\$sn" -ValueName 'Driver' -Op @{ Type = 'RegKey'; Key = "$pm\$sn" } }
        }
        $k.Close()
    }
    # Active Setup
    foreach ($p in 'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components', 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components') {
        $k = Open-PssKey $p; if (-not $k) { continue }
        foreach ($sn in $k.GetSubKeyNames()) {
            $sk = (Open-PssSub $k $sn); if (-not $sk) { continue }
            $stub = [string](Get-PssRegValue $sk 'StubPath'); $nm = [string]$sk.GetValue(''); $isOn = $sk.GetValue('IsInstalled')
            $sk.Close()
            if ($stub) {
                # Some Windows components store a bare argument here (e.g. "U"); there is no program to check
                $noPath = $stub -notmatch '\\|\.(exe|dll|cmd|bat|vbs|js|ps1)\b' -and -not (Resolve-PssImage $stub).Found
                Add-PssItem -Category 'Active Setup' -Name $(if ($nm) { $nm } else { $sn }) -Location "$p\$sn" -Command $stub -Enabled ($isOn -ne 0) -Trigger 'First logon per user' -RegKey "$p\$sn" -ValueName 'StubPath' -NoImage $noPath -Extra $(if ($noPath) { 'StubPath holds no program path' } else { '' }) -Op @{ Type = 'RegValue'; Key = "$p\$sn"; Name = 'StubPath' }
            }
        }
        $k.Close()
    }
    # Explorer hooks: ShellServiceObjects, DelayLoad, BHOs, SharedTaskScheduler
    foreach ($p in 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects', 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects') {
        $k = Open-PssKey $p; if (-not $k) { continue }
        foreach ($sn in $k.GetSubKeyNames()) {
            $c = Get-PssClsid $sn
            Add-PssItem -Category 'Explorer' -Name $(if ($c.Name) { $c.Name } else { $sn }) -Location "$p\$sn" -Command "$sn" -Image $c.Dll -Trigger $(if ($p -match 'Browser') { 'Internet Explorer / Edge IE mode' } else { 'Explorer start' }) -RegKey "$p\$sn" -Op @{ Type = 'RegKey'; Key = "$p\$sn" }
        }
        $k.Close()
    }
    foreach ($p in 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler') {
        $k = Open-PssKey $p; if (-not $k) { continue }
        foreach ($n in $k.GetValueNames()) {
            $v = [string]$k.GetValue($n); $clsid = if ($p -match 'Shared') { $n } else { $v }
            $c = Get-PssClsid $clsid
            Add-PssItem -Category 'Explorer' -Name $(if ($c.Name) { $c.Name } elseif ($n) { $n } else { $clsid }) -Location $p -Command $clsid -Image $c.Dll -Trigger 'Explorer start' -RegKey $p -ValueName $n -Op @{ Type = 'RegValue'; Key = $p; Name = $n }
        }
        $k.Close()
    }
    # cmd.exe AutoRun, logon scripts, screensaver, Store startup tasks (per user)
    $roots = @([pscustomobject]@{ Root = 'HKLM'; User = 'All users' }) + @($script:PssUsers | ForEach-Object { [pscustomobject]@{ Root = $_.Root; User = $_.User; Sid = $_.Sid } })
    foreach ($r in $roots) {
        $p = "$($r.Root)\Software\Microsoft\Command Processor"
        $k = Open-PssKey $p
        if ($k) { $v = [string](Get-PssRegValue $k 'AutoRun'); $k.Close(); if ($v) { Add-PssItem -Category 'Cmd AutoRun' -Name 'Command Processor AutoRun' -Location $p -Command $v -User $r.User -Trigger 'Every cmd.exe start' -RegKey $p -ValueName 'AutoRun' -Kind 'Modified' -Op @{ Type = 'RegValue'; Key = $p; Name = 'AutoRun' } } }
        if ($r.Root -ne 'HKLM') {
            $p = "$($r.Root)\Environment"
            $k = Open-PssKey $p
            if ($k) { $v = [string](Get-PssRegValue $k 'UserInitMprLogonScript'); $k.Close(); if ($v) { Add-PssItem -Category 'Logon Script' -Name 'UserInitMprLogonScript' -Location $p -Command $v -User $r.User -Trigger 'Logon' -RegKey $p -ValueName 'UserInitMprLogonScript' -Kind 'Modified' -Op @{ Type = 'RegValue'; Key = $p; Name = 'UserInitMprLogonScript' } } }
            $p = "$($r.Root)\Control Panel\Desktop"
            $k = Open-PssKey $p
            if ($k) {
                $v = [string](Get-PssRegValue $k 'SCRNSAVE.EXE'); $act = [string]$k.GetValue('ScreenSaveActive'); $k.Close()
                if ($v) { Add-PssItem -Category 'Screensaver' -Name ([IO.Path]::GetFileName($v)) -Location $p -Command $v -Image $v -Enabled ($act -eq '1') -User $r.User -Trigger 'Idle' -RegKey $p -ValueName 'SCRNSAVE.EXE' -Op @{ Type = 'RegValue'; Key = $p; Name = 'SCRNSAVE.EXE' } }
            }
            $p = "HKU\$($r.Sid)_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData"
            $k = Open-PssKey $p
            if ($k) {
                foreach ($pkg in $k.GetSubKeyNames()) {
                    $pk = (Open-PssSub $k $pkg); if (-not $pk) { continue }
                    foreach ($tid in $pk.GetSubKeyNames()) {
                        $tk = (Open-PssSub $pk $tid); if (-not $tk) { continue }
                        $state = $tk.GetValue('State'); $tk.Close()
                        if ($null -eq $state) { continue }
                        $fam = ($pkg -split '_')[0]
                        Add-PssItem -Category 'Store App' -Name "$fam ($tid)" -Location "$p\$pkg\$tid" -Command $pkg -Enabled ($state -in 2, 4, 5) -User $r.User -Trigger 'Logon' -RegKey "$p\$pkg\$tid" -ValueName 'State' -Publisher $(if ($fam -match '^Microsoft') { 'Microsoft (Store package)' } else { 'Store package' }) -NoImage $true -Extra "Package: $pkg; State: $state" -Op @{ Type = 'StoreApp'; Key = "$p\$pkg\$tid"; ByPolicy = ($state -in 3, 4) }
                        $last = $script:PssItems[$script:PssItems.Count - 1]
                        $last.IsMicrosoft = ($fam -match '^(Microsoft|Windows)\.')
                    }
                    $pk.Close()
                }
                $k.Close()
            }
        }
        # Group Policy scripts
        $kinds = if ($r.Root -eq 'HKLM') { 'Startup', 'Shutdown' } else { 'Logon', 'Logoff' }
        foreach ($kind in $kinds) {
            $p = "$($r.Root)\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\$kind"
            $k = Open-PssKey $p; if (-not $k) { continue }
            foreach ($g in $k.GetSubKeyNames()) {
                $gk = (Open-PssSub $k $g); if (-not $gk) { continue }
                foreach ($s in $gk.GetSubKeyNames()) {
                    $sk = (Open-PssSub $gk $s); $scr = [string]$sk.GetValue('Script'); $par = [string]$sk.GetValue('Parameters'); $sk.Close()
                    if ($scr) { Add-PssItem -Category 'Logon Script' -Name "GPO $kind script" -Location "$p\$g\$s" -Command "$scr $par".Trim() -Image $scr -User $r.User -Trigger $kind -RegKey "$p\$g\$s" -ValueName 'Script' -Op @{ Type = 'Blocked'; Note = 'Set by Group Policy, which would put it back. Remove it from the Group Policy Object instead.' } }
                }
                $gk.Close()
            }
            $k.Close()
        }
    }
    # netsh helpers
    $p = 'HKLM\SOFTWARE\Microsoft\NetSh'
    $k = Open-PssKey $p
    if ($k) {
        foreach ($n in $k.GetValueNames()) { $v = [string]$k.GetValue($n); if ($v) { Add-PssItem -Category 'Netsh' -Name $n -Location $p -Command $v -Image "$env:SystemRoot\System32\$v" -Trigger 'When netsh runs' -RegKey $p -ValueName $n -Op @{ Type = 'RegValue'; Key = $p; Name = $n } } }
        $k.Close()
    }
}

function Get-PssWmi {
    try {
        $consumers = @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction Stop)
        $bindings = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue)
        $filters = @(Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue)
    } catch { $script:PssErrors.Add('WMI subscriptions: access denied (run elevated)'); return }
    foreach ($c in $consumers) {
        $cls = $c.CimClass.CimClassName
        $cmd = $null; $img = $null
        if ($cls -eq 'CommandLineEventConsumer') { $cmd = if ($c.CommandLineTemplate) { $c.CommandLineTemplate } else { $c.ExecutablePath }; if ($c.ExecutablePath) { $img = $c.ExecutablePath } }
        elseif ($cls -eq 'ActiveScriptEventConsumer') {
            $cmd = if ($c.ScriptFileName) { "$($c.ScriptingEngine): $($c.ScriptFileName)" } else { "$($c.ScriptingEngine) inline script: " + ([string]$c.ScriptText -replace '\s+', ' ') }
            $img = $c.ScriptFileName
        } else { continue }
        $q = ''
        foreach ($b in $bindings) {
            if ($b.Consumer.Name -eq $c.Name) {
                $f = $filters | Where-Object { $_.Name -eq $b.Filter.Name } | Select-Object -First 1
                if ($f) { $q = $f.Query }
            }
        }
        $wa = @{ Category = 'WMI'; Name = $c.Name; Location = "root\subscription $cls"; Command = $cmd; Trigger = $(if ($q) { $q } else { 'Not bound to a filter' }); Kind = 'Modified'; Extra = "Consumer type: $cls"; Op = @{ Type = 'Wmi'; Class = $cls; Name = $c.Name } }
        if ($img) { $wa.Image = $img } elseif (-not $cmd -or $cls -eq 'ActiveScriptEventConsumer') { $wa.NoImage = $true }
        Add-PssItem @wa
    }
}

# ---------- enrichment ----------

function Invoke-PssFileInfo([string[]]$Paths) {
    $worker = {
        param([string[]]$list)
        foreach ($path in $list) {
            $r = [ordered]@{ Path = $path; Exists = $false; Size = $null; Created = $null; Modified = $null; Hidden = $false; Company = ''; Description = ''; Product = ''; Version = ''; SignStatus = ''; Signer = '' }
            try {
                $fi = New-Object System.IO.FileInfo $path
                if ($fi.Exists) {
                    $r.Exists = $true; $r.Size = $fi.Length; $r.Created = $fi.CreationTime; $r.Modified = $fi.LastWriteTime
                    $r.Hidden = [bool]($fi.Attributes -band [System.IO.FileAttributes]::Hidden)
                    try { $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path); $r.Company = [string]$vi.CompanyName; $r.Description = [string]$vi.FileDescription; $r.Product = [string]$vi.ProductName; $r.Version = [string]$vi.FileVersion } catch {}
                    try {
                        $s = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
                        $r.SignStatus = [string]$s.Status
                        if ($s.SignerCertificate) { $r.Signer = $s.SignerCertificate.Subject }
                    } catch { $r.SignStatus = 'Error' }
                }
            } catch {}
            [pscustomobject]$r
        }
    }
    $out = @{}
    if (-not $Paths -or $Paths.Count -eq 0) { return $out }
    $n = [Math]::Max(2, [Math]::Min(12, [Environment]::ProcessorCount))
    $pool = [runspacefactory]::CreateRunspacePool(1, $n)
    $pool.Open()
    $jobs = @()
    $chunk = [Math]::Max(4, [Math]::Ceiling($Paths.Count / ($n * 3)))
    for ($i = 0; $i -lt $Paths.Count; $i += $chunk) {
        $end = [Math]::Min($i + $chunk, $Paths.Count) - 1
        $ps = [powershell]::Create(); $ps.RunspacePool = $pool
        [void]$ps.AddScript($worker).AddArgument([string[]]$Paths[$i..$end])
        $jobs += @{ PS = $ps; H = $ps.BeginInvoke() }
    }
    foreach ($j in $jobs) {
        try { foreach ($r in $j.PS.EndInvoke($j.H)) { $out[$r.Path] = $r } } catch {}
        $j.PS.Dispose()
    }
    $pool.Close(); $pool.Dispose()
    return $out
}

function Get-PssBootPerf {
    $res = [pscustomobject]@{ Available = $false; Error = ''; Boots = @(); Delays = @(); LastBootMs = 0; LastMainMs = 0; LastPostMs = 0; LastBootTime = $null }
    try {
        $events = @(Get-WinEvent -LogName 'Microsoft-Windows-Diagnostics-Performance/Operational' -FilterXPath '*[System[(EventID>=100 and EventID<=110)]]' -MaxEvents 800 -ErrorAction Stop)
    } catch {
        $res.Error = if ($_.Exception.Message -match 'No events') { 'No boot performance events recorded yet.' } else { 'Boot performance log unavailable (run elevated).' }
        return $res
    }
    $res.Available = $true
    $boots = @(); $delays = @()
    foreach ($e in $events) {
        $d = @{}
        try { foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $d[$n.Name] = $n.'#text' } } catch { continue }
        if ($e.Id -eq 100) {
            $boots += [pscustomobject]@{ Time = $e.TimeCreated; BootSec = [math]::Round([double]$d.BootTime / 1000, 1); MainPathSec = [math]::Round([double]$d.MainPathBootTime / 1000, 1); PostBootSec = [math]::Round([double]$d.BootPostBootTime / 1000, 1); Degraded = ($e.LevelDisplayName -ne 'Information' -or [int]$e.Level -le 3) }
        } elseif ($d.Name -or $d.FriendlyName) {
            $type = switch ($e.Id) { 101 { 'App' } 102 { 'Driver' } 103 { 'Service' } 104 { 'Core' } 105 { 'Device' } 106 { 'Background' } 107 { 'Resume' } 108 { 'Cache' } 109 { 'Device' } 110 { 'Session' } default { 'Other' } }
            $delays += [pscustomobject]@{ Time = $e.TimeCreated; Type = $type; Name = [string]$d.Name; FriendlyName = [string]$d.FriendlyName; TotalMs = [int]([double]('0' + $d.TotalTime)); DegradationMs = [int]([double]('0' + $d.DegradationTime)) }
        }
    }
    $res.Boots = $boots | Sort-Object Time -Descending
    $res.Delays = $delays | Sort-Object Time -Descending
    if ($res.Boots) { $b = @($res.Boots)[0]; $res.LastBootMs = $b.BootSec * 1000; $res.LastMainMs = $b.MainPathSec * 1000; $res.LastPostMs = $b.PostBootSec * 1000; $res.LastBootTime = $b.Time }
    return $res
}

function Measure-PssRisk($it) {
    $flags = New-Object System.Collections.Generic.List[string]
    $score = 0
    $cmd = [string]$it.Command
    $img = [string]$it.ImagePath
    $leaf = ''; $dir = ''
    try { $leaf = [IO.Path]::GetFileName($img).ToLowerInvariant(); $dir = ([IO.Path]::GetDirectoryName($img) + '\').ToLowerInvariant() } catch {}
    $win = ($env:SystemRoot + '\').ToLowerInvariant()
    $ext = ''; try { $ext = [IO.Path]::GetExtension($img).ToLowerInvariant() } catch {}
    $isPE = $ext -in '.exe', '.dll', '.sys', '.ocx', '.cpl', '.scr', '.com', '.drv', '.efi', '.tsp', '.ax'
    $isScript = $ext -in '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.bat', '.cmd', '.ps1', '.hta', '.pif'

    if (-not $it.NoImage -and $img) {
        $alias = $img -match '(?i)\\Microsoft\\WindowsApps\\[^\\]+\.exe$'
        if ($alias) { }
        elseif (-not $it.FileExists) { $flags.Add('File not found (orphaned entry)'); $score += 2 }
        elseif ($isPE) {
            switch ($it.SignStatus) {
                'Valid' { }
                'NotSigned' { $flags.Add('Unsigned binary'); $score += 3 }
                'HashMismatch' { $flags.Add('Signature does not match file (tampered?)'); $score += 6 }
                'NotTrusted' { $flags.Add('Signed by an untrusted certificate'); $score += 4 }
                { $_ -in 'Error', 'UnknownError' } { $flags.Add('Signature could not be checked'); $score += 1 }
                default { $flags.Add("Signature: $($it.SignStatus)"); $score += 3 }
            }
        }
        if ($isScript) { $flags.Add("Runs a script file ($ext)"); $score += 2 }
        if ($dir -match '\\appdata\\local\\temp\\|\\windows\\temp\\|\\users\\public\\|\\downloads\\|\\\$recycle\.bin\\|\\perflogs\\') { $flags.Add('Runs from a temp/public/downloads folder'); $score += 4 }
        elseif ($dir -match '\\appdata\\' -and $it.SignStatus -eq 'NotSigned' -and $it.FileExists) { $flags.Add('Unsigned file in user AppData'); $score += 2 }
        elseif ($dir -match '^[a-z]:\\programdata\\([^\\]+\\)?$' -and $it.SignStatus -ne 'Valid' -and $it.FileExists) { $flags.Add('Unsigned file in a top-level ProgramData folder'); $score += 2 }
        $sysNames = 'svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe', 'services.exe', 'smss.exe', 'explorer.exe', 'rundll32.exe', 'dllhost.exe', 'conhost.exe', 'taskhostw.exe', 'spoolsv.exe', 'wininit.exe', 'lsm.exe', 'taskhost.exe', 'ctfmon.exe', 'sihost.exe'
        if ($leaf -in $sysNames -and -not $dir.StartsWith($win)) { $flags.Add("Windows process name outside the Windows folder ($leaf)"); $score += 6 }
        if ($leaf -match '\.(pdf|doc|docx|xls|xlsx|jpg|png|txt|zip)\.(exe|scr|com|pif|bat|cmd|vbs|js)$') { $flags.Add('Double file extension'); $score += 5 }
        if ($it.Hidden -and -not $dir.StartsWith($win)) { $flags.Add('Hidden file'); $score += 1 }
        if ($it.Created -and $it.SignStatus -ne 'Valid' -and ((Get-Date) - $it.Created).TotalDays -lt 7 -and $it.FileExists) { $flags.Add('Unsigned file created in the last 7 days'); $score += 1 }
    }
    if ($cmd) {
        if ($cmd -match '(?i)\s-e(nc|ncodedcommand|c)?\s+[A-Za-z0-9+/=]{20,}') { $flags.Add('Encoded PowerShell command'); $score += 6 }
        if ($cmd -match '(?i)(downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|net\.webclient|start-bitstransfer|frombase64string|invoke-expression|\biex\b)') { $flags.Add('Downloads or evaluates code'); $score += 5 }
        if ($cmd -match '(?i)-w(indowstyle)?\s+h(idden)?\b') { $flags.Add('Hidden window'); $score += 2 }
        if ($cmd -match '(?i)\b(javascript|vbscript):') { $flags.Add('Inline script protocol'); $score += 6 }
        if ($cmd -match '(?i)\bmshta(\.exe)?\b') { $flags.Add('Uses mshta'); $score += 4 }
        if ($cmd -match '(?i)regsvr32.*(/i:|scrobj)') { $flags.Add('regsvr32 script loading'); $score += 6 }
        if ($cmd -match '(?i)certutil.*(-urlcache|-decode)') { $flags.Add('certutil download/decode'); $score += 6 }
        if ($cmd -match '(?i)bitsadmin.*/transfer') { $flags.Add('bitsadmin download'); $score += 5 }
        if ($cmd -match '(?i)https?://' -and $it.Category -notin 'Service', 'Driver') { $flags.Add('URL in command line'); $score += 3 }
        if ($cmd -match '(?i)\b(wscript|cscript)(\.exe)?\b') { $flags.Add('Uses Windows Script Host'); $score += 2 }
        if ($cmd -match '[A-Za-z0-9+/]{120,}={0,2}') { $flags.Add('Long encoded string'); $score += 3 }
    }
    if ($it.Category -in 'Service', 'Driver' -and $img -and $it.Command -and $it.Command -notmatch '^\s*"' -and $it.Command -match '^\s*[a-zA-Z]:\\[^"]*\s[^"]*\.exe' ) {
        $flags.Add('Unquoted service path with spaces'); $score += 2
    }
    switch ($it.Category) {
        'IFEO' { if (-not $it.IsMicrosoft) { $flags.Add('Program hijack (IFEO)'); $score += 5 } else { $flags.Add('IFEO entry (review)'); $score += 2 } }
        'WMI' { $flags.Add('WMI persistence (common malware technique)'); $score += 5 }
        'AppInit' { $flags.Add('AppInit DLL injected into every app'); $score += 4 }
        'Cmd AutoRun' { $flags.Add('Runs with every cmd.exe'); $score += 3 }
        'Winlogon' { if ($it.Kind -eq 'Modified') { $flags.Add('Winlogon value changed from default'); $score += 6 } }
        'Boot Execute' { if ($it.Kind -eq 'Modified') { $flags.Add('Non-default boot execute'); $score += 4 } }
        'Run Key' { if ($it.Name -match '^Windows\\(Load|Run)$') { $flags.Add('Legacy load point'); $score += 3 } }
    }
    # The scanner's own boot-test tasks (hidden PowerShell running a script in ProgramData would otherwise be flagged)
    if ($it.Category -eq 'Scheduled Task' -and $it.Name -like '\PAX Startup Scanner\*' -and $cmd -match '(?i)\\PaxStartupScanner\\boot-probe\.ps1') {
        $flags.Clear(); $score = 0
        $it.Extra = 'PAX Startup Scanner boot test. It runs once at the next restart and then removes itself.'
    }
    $it.FlagList = @($flags)
    $it.Flags = ($flags -join '; ')
    $it.RiskScore = $score
    $it.Risk = if ($score -ge 6) { 'High' } elseif ($score -ge 3) { 'Medium' } elseif ($score -ge 1) { 'Low' } else { 'OK' }
}

function Invoke-PssScan {
    param($Status)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Initialize-Pss
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $script:PssUsers = @(Get-PssUserHives)

    $steps = @(
        @{ N = 'Registry Run keys'; F = { Get-PssRunKeys } }
        @{ N = 'Startup folders'; F = { Get-PssStartupFolders } }
        @{ N = 'Scheduled tasks'; F = { Get-PssTasks } }
        @{ N = 'Services and drivers'; F = { Get-PssServices } }
        @{ N = 'Winlogon'; F = { Get-PssWinlogon } }
        @{ N = 'System hooks and scripts'; F = { Get-PssMisc } }
        @{ N = 'WMI subscriptions'; F = { Get-PssWmi } }
    )
    $i = 0
    foreach ($s in $steps) {
        Set-PssStatus "Scanning $($s.N)..." ([int](5 + 45 * $i / $steps.Count)) $Status
        try { & $s.F } catch { $script:PssErrors.Add("$($s.N): $($_.Exception.Message)") }
        $i++
    }
    $items = $script:PssItems

    Set-PssStatus "Checking signatures and file details ($($items.Count) items)..." 55 $Status
    $paths = @($items | Where-Object { $_.ImagePath -and -not $_.NoImage } | ForEach-Object { $_.ImagePath } | Sort-Object -Unique)
    $info = Invoke-PssFileInfo $paths

    Set-PssStatus 'Reading running processes...' 82 $Status
    $procMap = @{}; $procByLeaf = @{}
    try {
        foreach ($p in (Get-CimInstance Win32_Process -Property ProcessId, ExecutablePath, WorkingSetSize, KernelModeTime, UserModeTime -ErrorAction Stop)) {
            if (-not $p.ExecutablePath) { continue }
            $key = $p.ExecutablePath.ToLowerInvariant()
            if (-not $procMap.ContainsKey($key)) {
                $procMap[$key] = @{ Count = 0; WS = 0; Cpu = 0 }
                $leafKey = [IO.Path]::GetFileName($key)
                if (-not $procByLeaf.ContainsKey($leafKey)) { $procByLeaf[$leafKey] = New-Object System.Collections.Generic.List[string] }
                $procByLeaf[$leafKey].Add($key)
            }
            $procMap[$key].Count++; $procMap[$key].WS += [double]$p.WorkingSetSize; $procMap[$key].Cpu += ([double]$p.KernelModeTime + [double]$p.UserModeTime) / 1e7
        }
    } catch {}

    Set-PssStatus 'Reading boot performance history...' 90 $Status
    $boot = Get-PssBootPerf
    # Boot-delay events name a process (or a service); generic host processes can't be pinned on one item
    $hostExe = 'svchost.exe', 'rundll32.exe', 'dllhost.exe', 'taskhostw.exe', 'taskhost.exe', 'conhost.exe', 'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'regsvr32.exe', 'msiexec.exe', 'runtimebroker.exe', 'sihost.exe', 'wmiprvse.exe', 'backgroundtaskhost.exe'
    $delayMap = @{}
    foreach ($d in $boot.Delays) {
        if (-not $d.Name) { continue }
        $key = ([IO.Path]::GetFileName($d.Name)).ToLowerInvariant()
        if ($key -in $hostExe) { continue }
        if (-not $delayMap.ContainsKey($key)) { $delayMap[$key] = @{ Max = 0; Count = 0; Last = $null } }
        $delayMap[$key].Count++
        if ($d.DegradationMs -gt $delayMap[$key].Max) { $delayMap[$key].Max = $d.DegradationMs }
        if (-not $delayMap[$key].Last -or $d.Time -gt $delayMap[$key].Last) { $delayMap[$key].Last = $d.Time }
    }

    Set-PssStatus 'Scoring...' 96 $Status
    foreach ($it in $items) {
        $fi = $null
        if ($it.ImagePath -and $info.ContainsKey($it.ImagePath)) { $fi = $info[$it.ImagePath] }
        if ($fi) {
            $it.FileExists = $fi.Exists; $it.Size = $fi.Size; $it.Created = $fi.Created; $it.Modified = $fi.Modified; $it.Hidden = $fi.Hidden
            $it.Company = $fi.Company; $it.Description = $fi.Description; $it.Product = $fi.Product; $it.Version = $fi.Version
            $it.SignStatus = $fi.SignStatus; $it.Signer = $fi.Signer
        }
        $cn = ''
        if ($it.Signer -match 'CN=("[^"]+"|[^,]+)') { $cn = $Matches[1].Trim('"') }
        if (-not $it.NoImage) {
            $it.IsMicrosoft = ($it.SignStatus -eq 'Valid' -and $it.Signer -match 'O=Microsoft Corporation')
            if ($it.SignStatus -eq 'Valid' -and $cn) { $it.Publisher = $cn }
            elseif ($it.Company) { $it.Publisher = "$($it.Company) (not verified)" }
            elseif ($it.ImagePath -match '(?i)\\Microsoft\\WindowsApps\\[^\\]+\.exe$') { $it.Publisher = 'Store app (execution alias)'; $it.SignText = 'n/a' }
            elseif (-not $it.FileExists -and $it.ImagePath) { $it.Publisher = '(file missing)' }
            elseif ($it.FileExists) { $it.Publisher = '(unknown publisher)' }
        }
        $it.SignText = switch ($it.SignStatus) { 'Valid' { 'Signed' } 'NotSigned' { 'Unsigned' } '' { $(if ($it.NoImage) { 'n/a' } else { '-' }) } default { $it.SignStatus } }
        if ($it.ImagePath -and $it.ImagePath -notmatch '(?i)\\(svchost|rundll32|dllhost|explorer)\.exe$') {
            $pm = $procMap[[string]$it.ImagePath.ToLowerInvariant()]
            if (-not $pm -and $it.AltExe) {
                # Launcher items: look for the launched exe under the launcher's folder
                $base = ''; try { $base = ([IO.Path]::GetDirectoryName($it.ImagePath) + '\').ToLowerInvariant() } catch {}
                if ($base -and $procByLeaf.ContainsKey($it.AltExe.ToLowerInvariant())) {
                    foreach ($k in $procByLeaf[$it.AltExe.ToLowerInvariant()]) { if ($k.StartsWith($base)) { $pm = $procMap[$k]; break } }
                }
            }
            if ($pm) {
                $it.Running = $true; $it.ProcCount = $pm.Count; $it.MemoryMB = [int][math]::Round($pm.WS / 1MB, 0); $it.CpuSec = [int][math]::Round($pm.Cpu, 0)
            }
        }
        $it.RunText = if ($it.ProcCount) { '{0} MB' -f $it.MemoryMB } elseif ($it.Running) { 'Running' } else { '' }
        $keys = @()
        if ($it.AltExe) { $keys += $it.AltExe.ToLowerInvariant() }
        if ($it.ImagePath) { try { $keys += [IO.Path]::GetFileName($it.ImagePath).ToLowerInvariant() } catch {} }
        if ($it.ServiceName) { $keys += $it.ServiceName.ToLowerInvariant() }
        foreach ($key in $keys) { if ($delayMap.ContainsKey($key)) { $it.BootDelayMs = $delayMap[$key].Max; $it.BootDelayCount = $delayMap[$key].Count; $it.BootDelayLast = $delayMap[$key].Last; break } }
        if ($it.BootDelayMs) { $it.BootDelayText = '{0:N1}s' -f ($it.BootDelayMs / 1000) }
        $it.Impact = if ($it.BootDelayMs -ge 3000 -or $it.MemoryMB -ge 400) { 'High' } elseif ($it.BootDelayMs -ge 1000 -or $it.MemoryMB -ge 150 -or $it.CpuSec -ge 600) { 'Medium' } elseif ($it.Running -or $it.BootDelayMs) { 'Low' } else { '' }
        Measure-PssRisk $it
        Set-PssPermissions $it
        Set-PssFacets $it
    }
    $rank = @{ High = 0; Medium = 1; Low = 2; OK = 3 }
    $sorted = @($items | Sort-Object @{ E = { $rank[$_.Risk] } }, @{ E = { $_.IsMicrosoft } }, Category, Name)
    $n = 1; foreach ($it in $sorted) { $it.Id = $n++ }

    # Profiles whose registry hive isn't loaded (user not logged on)
    $notLoaded = @()
    $pl = Open-PssKey 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    if ($pl) {
        foreach ($sid in $pl.GetSubKeyNames()) {
            if ($sid -notmatch '^S-1-(5-21|12-1)-') { continue }
            if ($script:PssUsers.Sid -notcontains $sid) {
                $sk = (Open-PssSub $pl $sid); $pp = [string]$sk.GetValue('ProfileImagePath'); $sk.Close()
                if ($pp) { $notLoaded += (Split-Path $pp -Leaf) }
            }
        }
        $pl.Close()
    }
    $os = ''
    try { $cv = Open-PssKey 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; $os = '{0} {1} (build {2})' -f $cv.GetValue('ProductName'), $cv.GetValue('DisplayVersion'), $cv.GetValue('CurrentBuild'); if ([int]$cv.GetValue('CurrentBuild') -ge 22000) { $os = $os -replace 'Windows 10', 'Windows 11' }; $cv.Close() } catch {}
    $uptime = $null
    try { $uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem -Property LastBootUpTime -ErrorAction Stop).LastBootUpTime } catch {}
    $sw.Stop()
    Set-PssStatus 'Done' 100 $Status
    return [pscustomobject]@{
        Items = $sorted; Boot = $boot; Errors = @($script:PssErrors); Computer = $env:COMPUTERNAME; OS = $os
        IsAdmin = $isAdmin; Users = @($script:PssUsers | ForEach-Object { $_.User }); NotLoadedProfiles = $notLoaded
        Uptime = $uptime; Duration = $sw.Elapsed.TotalSeconds; ScannedAt = Get-Date; Version = $script:PssVersion
    }
}

# ======================================================================================
#  Shared helpers (details, export)
# ======================================================================================

function Format-PssSize($b) {
    if ($null -eq $b) { return '' }
    if ($b -ge 1GB) { return '{0:N1} GB' -f ($b / 1GB) } elseif ($b -ge 1MB) { return '{0:N1} MB' -f ($b / 1MB) } elseif ($b -ge 1KB) { return '{0:N0} KB' -f ($b / 1KB) } else { return "$b B" }
}

function Get-PssDetailFields($it) {
    $f = [ordered]@{}
    $f['Category'] = $it.Category
    $f['Enabled'] = $it.EnabledText
    if ($it.User) { $f['User / account'] = $it.User }
    if ($it.Trigger) { $f['Starts'] = $it.Trigger }
    $f['Command'] = $it.Command
    if (-not $it.NoImage) {
        $img = $it.ImagePath; if ($it.Via) { $img += "   (via $($it.Via))" }
        $f['File'] = $img
        if ($it.FileExists) {
            $f['File info'] = '{0}, created {1:yyyy-MM-dd}, modified {2:yyyy-MM-dd}{3}' -f (Format-PssSize $it.Size), $it.Created, $it.Modified, $(if ($it.Hidden) { ', HIDDEN' } else { '' })
        } elseif ($it.ImagePath) { $f['File info'] = 'NOT FOUND on disk' }
        $f['Publisher'] = $it.Publisher
        $f['Signature'] = $(if ($it.SignStatus) { $it.SignStatus } else { '-' })
        if ($it.Description) { $f['Description'] = $it.Description }
        if ($it.Product -and $it.Product -ne $it.Description) { $f['Product'] = $it.Product }
        if ($it.Version) { $f['Version'] = $it.Version }
    } elseif ($it.Publisher) { $f['Publisher'] = $it.Publisher }
    $loc = $it.Location; if ($it.ValueName) { $loc += "  ->  value '$($it.ValueName)'" }
    $f['Location'] = $loc
    if ($it.Extra) { $f['Notes'] = $it.Extra }
    if ($it.ProcCount) { $f['Running'] = '{0} process(es), {1} MB RAM, {2}s CPU since start' -f $it.ProcCount, $it.MemoryMB, $it.CpuSec }
    elseif ($it.Running) { $f['Running'] = 'Yes' }
    if ($it.BootDelayMs) {
        $f['Boot delay'] = '{0:N1}s worst case, flagged by Windows {1} time(s)' -f ($it.BootDelayMs / 1000), $it.BootDelayCount
        if ($it.BootDelayLast) { $f['Boot delay'] += (', last on {0:yyyy-MM-dd}' -f $it.BootDelayLast) }
    }
    if ($it.Sha256) { $f['SHA-256'] = $it.Sha256 }
    $ch = @()
    if ($it.CanDisable) { $ch += $(if ($it.Enabled) { 'Disable' } else { 'Enable' }) }
    if ($it.CanDelete) { $ch += 'Delete' }
    if ($ch) { $f['Changes'] = ($ch -join ', ') + ' available' } elseif ($it.ActionNote) { $f['Changes'] = $it.ActionNote }
    $f['Risk'] = "$($it.Risk) (score $($it.RiskScore))"
    if ($it.Flags) { $f['Flags'] = $it.Flags }
    return $f
}

function Get-PssDetailText($it) {
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("#$($it.Id)  $($it.Name)")
    $f = Get-PssDetailFields $it
    foreach ($k in $f.Keys) { [void]$sb.AppendLine(('{0,-15} {1}' -f $k, $f[$k])) }
    return $sb.ToString()
}

function Get-PssHash($it) {
    # SHA-256 via .NET (shares read/write so files that are in use can still be hashed)
    $script:PssHashError = ''
    if ($it.Sha256) { return $it.Sha256 }
    if (-not $it.FileExists) { $script:PssHashError = 'There is no file on disk to hash.'; return '' }
    $fs = $null; $sha = $null
    try {
        $fs = [IO.File]::Open($it.ImagePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        $sha = [Security.Cryptography.SHA256]::Create()
        $it.Sha256 = [BitConverter]::ToString($sha.ComputeHash($fs)).Replace('-', '')
    } catch { $script:PssHashError = "Could not hash the file: $($_.Exception.Message)" }
    finally { if ($fs) { $fs.Dispose() }; if ($sha) { $sha.Dispose() } }
    return $it.Sha256
}

function Open-PssLocation($it) {
    if ($it.RegKey) {
        $full = $it.RegKey -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\' -replace '^HKU\\', 'HKEY_USERS\'
        if ($script:PssReadOnly) {
            # Jumping Regedit to a key means writing its LastKey setting; read-only mode copies the path instead
            try { Set-Clipboard -Value "Computer\$full" } catch {}
            $script:PssLastNote = 'Read-only mode: the registry path was copied to the clipboard (paste it into Regedit''s address bar).'
            Start-Process regedit.exe -ArgumentList '/m'
            return
        }
        try {
            $k = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Software\Microsoft\Windows\CurrentVersion\Applets\Regedit')
            $k.SetValue('LastKey', "Computer\$full"); $k.Close()
            Start-Process regedit.exe -ArgumentList '/m'
        } catch {}
    } elseif ($it.Kind -eq 'Task') { Start-Process taskschd.msc }
    elseif ($it.Kind -eq 'File' -and (Test-Path -LiteralPath $it.Location)) { Start-Process explorer.exe -ArgumentList "/select,`"$($it.Location)`"" }
    else { Open-PssFolder $it }
}

function Open-PssFolder($it) {
    if ($it.FileExists) { Start-Process explorer.exe -ArgumentList "/select,`"$($it.ImagePath)`"" }
    elseif ($it.ImagePath) { $d = Split-Path $it.ImagePath -Parent; if ($d -and (Test-Path -LiteralPath $d)) { Start-Process explorer.exe -ArgumentList "`"$d`"" } }
}

function Open-PssWebSearch($it) {
    $term = if ($it.ImagePath) { [IO.Path]::GetFileName($it.ImagePath) } else { $it.Name }
    Start-Process ('https://www.bing.com/search?q=' + [uri]::EscapeDataString("`"$term`" startup"))
}

function Open-PssVirusTotal($it) {
    $h = Get-PssHash $it
    if ($h) { Start-Process "https://www.virustotal.com/gui/file/$h"; return $true }
    return $false
}

function Export-PssReport($Scan, [string]$Path, [string]$Note = '') {
    # $Note describes a filtered export ("Showing 12 of 507 items - Publisher: ...")
    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    $cols = 'Id', 'Risk', 'RiskScore', 'Category', 'Name', 'EnabledText', 'User', 'Scope', 'Trigger', 'Command', 'ImagePath', 'Publisher', 'Vendor', 'SignStatus', 'Description', 'Version', 'FileExists', 'Created', 'Modified', 'Location', 'ValueName', 'Running', 'MemoryMB', 'BootDelayMs', 'Impact', 'IsMicrosoft', 'Flags', 'Extra'
    if ($ext -eq '.csv') { $Scan.Items | Select-Object $cols | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8; return }
    if ($ext -eq '.json') {
        [pscustomobject]@{ Computer = $Scan.Computer; OS = $Scan.OS; ScannedAt = $Scan.ScannedAt; Admin = $Scan.IsAdmin; Filter = $Note; Items = @($Scan.Items | Select-Object $cols); Boots = $Scan.Boot.Boots; BootDelays = $Scan.Boot.Delays } |
            ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Path -Encoding UTF8
        return
    }
    $e = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $sb = New-Object System.Text.StringBuilder
    $items = $Scan.Items
    $flagged = @($items | Where-Object { $_.Risk -in 'High', 'Medium' })
    [void]$sb.Append(@"
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PAX Startup Scanner - $(& $e $Scan.Computer)</title>
<style>
:root{--bg:#0f1115;--card:#171a21;--line:#262b36;--fg:#e6e8ee;--mut:#8b93a5;--hi:#ef4444;--me:#f59e0b;--lo:#38bdf8;--ok:#22c55e}
@media (prefers-color-scheme: light){:root{--bg:#f6f7f9;--card:#fff;--line:#e3e6ec;--fg:#151821;--mut:#5d6575}}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 Segoe UI,system-ui,sans-serif}
main{max-width:1400px;margin:0 auto;padding:24px 16px}h1{margin:0 0 4px;font-size:22px}h2{font-size:16px;margin:28px 0 10px}
.mut{color:var(--mut)}.tiles{display:flex;flex-wrap:wrap;gap:10px;margin-top:16px}.t{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px;min-width:120px}
.t b{display:block;font-size:22px}table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
td.p{font-family:Consolas,monospace;font-size:12px;word-break:break-all}.r{font-weight:600}.High{color:var(--hi)}.Medium{color:var(--me)}.Low{color:var(--lo)}.OK{color:var(--ok)}
tr.ms{opacity:.6}.bar{display:flex;gap:12px;align-items:center;margin:8px 0;flex-wrap:wrap}input[type=search]{padding:6px 10px;border-radius:6px;border:1px solid var(--line);background:var(--card);color:var(--fg);min-width:260px}
.wrap{overflow-x:auto}
</style></head><body><main>
<h1>PAX Startup Scanner report</h1>
<div class="mut">$(& $e $Scan.Computer) &middot; $(& $e $Scan.OS) &middot; scanned $('{0:yyyy-MM-dd HH:mm}' -f $Scan.ScannedAt) &middot; elevated: $(if ($Scan.IsAdmin) { 'yes' } else { 'no' }) &middot; v$($Scan.Version)</div>
$(if ($Note) { "<div class=`"mut`">Filtered view: $(& $e $Note)</div>" })
<div class="tiles">
<div class="t"><b>$($items.Count)</b>startup items</div>
<div class="t"><b>$(@($items | Where-Object { -not $_.IsMicrosoft }).Count)</b>third-party</div>
<div class="t"><b class="High">$(@($items | Where-Object Risk -eq 'High').Count)</b>high risk</div>
<div class="t"><b class="Medium">$(@($items | Where-Object Risk -eq 'Medium').Count)</b>medium risk</div>
<div class="t"><b>$(if ($Scan.Boot.LastBootMs) { '{0:N1}s' -f ($Scan.Boot.LastBootMs / 1000) } else { 'n/a' })</b>last boot$(if ($Scan.Boot.LastBootTime) { ' ({0:yyyy-MM-dd})' -f $Scan.Boot.LastBootTime })</div>
</div>
"@)
    $row = {
        param($it)
        "<tr class=`"$(if ($it.IsMicrosoft) { 'ms' })`"><td>$($it.Id)</td><td class=`"r $($it.Risk)`">$($it.Risk)</td><td>$(& $e $it.Category)</td><td>$(& $e $it.Name)<div class=`"mut`">$(& $e $it.Trigger)</div></td><td>$(& $e $it.EnabledText)</td><td>$(& $e $it.Publisher)<div class=`"mut`">$(& $e $it.SignText)</div></td><td class=`"p`">$(& $e $it.ImagePath)<div class=`"mut`">$(& $e $it.Command)</div></td><td class=`"p`">$(& $e $it.Location)</td><td>$(& $e $it.BootDelayText) $(& $e $it.RunText)</td><td>$(& $e $it.Flags)</td></tr>"
    }
    $head = '<tr><th>#</th><th>Risk</th><th>Category</th><th>Name</th><th>On</th><th>Publisher</th><th>File / command</th><th>Location</th><th>Impact</th><th>Flags</th></tr>'
    [void]$sb.Append("<h2>Needs review ($($flagged.Count))</h2><div class=`"wrap`"><table>$head")
    foreach ($it in $flagged) { [void]$sb.Append((& $row $it)) }
    if (-not $flagged) { [void]$sb.Append('<tr><td colspan="10" class="mut">Nothing flagged as medium or high risk.</td></tr>') }
    [void]$sb.Append('</table></div>')
    if ($Scan.Boot.Available -and $Scan.Boot.Boots) {
        [void]$sb.Append('<h2>Recent boots</h2><div class="wrap"><table><tr><th>When</th><th>Total boot</th><th>Main path</th><th>Post boot</th></tr>')
        foreach ($b in @($Scan.Boot.Boots | Select-Object -First 10)) { [void]$sb.Append("<tr><td>$('{0:yyyy-MM-dd HH:mm}' -f $b.Time)</td><td>$($b.BootSec)s</td><td>$($b.MainPathSec)s</td><td>$($b.PostBootSec)s</td></tr>") }
        [void]$sb.Append('</table></div>')
        $top = @($Scan.Boot.Delays | Group-Object Name | ForEach-Object { $g = $_.Group | Sort-Object DegradationMs -Descending | Select-Object -First 1; [pscustomobject]@{ Name = $g.FriendlyName; File = $g.Name; Type = $g.Type; Max = $g.DegradationMs; Count = $_.Count } } | Sort-Object Max -Descending | Select-Object -First 15)
        if ($top) {
            [void]$sb.Append('<h2>What Windows says slowed boot</h2><div class="wrap"><table><tr><th>Name</th><th>Type</th><th>Worst delay</th><th>Times</th></tr>')
            foreach ($t in $top) { [void]$sb.Append("<tr><td>$(& $e $t.Name)<div class=`"mut`">$(& $e $t.File)</div></td><td>$($t.Type)</td><td>$('{0:N1}s' -f ($t.Max / 1000))</td><td>$($t.Count)</td></tr>") }
            [void]$sb.Append('</table></div>')
        }
    }
    [void]$sb.Append("<h2>All startup items</h2><div class=`"bar`"><input type=`"search`" id=`"q`" placeholder=`"Filter...`"><label><input type=`"checkbox`" id=`"ms`"> show Microsoft items</label></div><div class=`"wrap`"><table id=`"all`">$head")
    foreach ($it in $items) { [void]$sb.Append((& $row $it)) }
    [void]$sb.Append(@'
</table></div></main><script>
const q=document.getElementById('q'),ms=document.getElementById('ms'),rows=[...document.querySelectorAll('#all tr')].slice(1);
function f(){const t=q.value.toLowerCase();rows.forEach(r=>{const m=r.classList.contains('ms');r.style.display=((!m||ms.checked)&&r.textContent.toLowerCase().includes(t))?'':'none'})}
q.oninput=f;ms.onchange=f;f();
</script></body></html>
'@)
    [IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object System.Text.UTF8Encoding $false))
}

# ======================================================================================
#  Changes: Disable / Enable / Delete with backups, and Undo
#  Every change writes an undo record to %ProgramData%\PaxStartupScanner\Backups before
#  anything is touched; the record is removed again if the change fails.
# ======================================================================================

function Set-PssFacets($it) {
    # The values the GUI filters and the console browse lists group by
    $it.Vendor = if ($it.IsMicrosoft) { 'Microsoft' } elseif ($it.Publisher) { [string]$it.Publisher } else { '(no file)' }
    $it.SigGroup = if ($it.NoImage) { 'No file to check' }
    elseif ($it.ImagePath -match '(?i)\\Microsoft\\WindowsApps\\') { "Couldn't check" }
    elseif (-not $it.FileExists) { 'File missing' }
    else {
        switch ($it.SignStatus) { 'Valid' { 'Signed' } 'NotSigned' { 'Unsigned' } { $_ -in 'Error', 'UnknownError', '' } { "Couldn't check" } default { 'Bad signature' } }
    }
    $scope = 'Machine (all users)'
    if ($it.RegKey -like 'HKU\*' -or ($it.Category -eq 'Startup Folder' -and $it.User -and $it.User -ne 'All users')) {
        $u = [string]$it.User; if ($u -match '\\') { $u = $u.Split('\')[-1] }
        if ($u) { $scope = "User: $u" }
    }
    $it.Scope = $scope
}

function Get-PssFacetKeys($it) {
    return @{
        Status    = $(if ($it.State -eq 'Removed') { 'Removed' } elseif ($it.Enabled) { 'On' } else { 'Off' })
        Risk      = $it.Risk
        Category  = $it.Category
        Publisher = $it.Vendor
        Signature = $it.SigGroup
        Running   = $(if ($it.Running) { 'Running now' } else { 'Not running' })
        Scope     = $it.Scope
    }
}

function Set-PssPermissions($it) {
    # Decides what may be changed. Windows' own parts are protected; user-level autostarts are not.
    $it.CanDisable = $false; $it.CanDelete = $false; $it.ActionNote = ''
    $op = $it.Op
    if ($it.State -eq 'Removed') { $it.ActionNote = 'Removed in this session. Undo can bring it back.'; return }
    if (-not $op) { $it.ActionNote = "This entry can't be changed from here."; return }
    if ($op.Type -eq 'Blocked') { $it.ActionNote = $op.Note; return }
    if ($script:PssReadOnly) { $it.ActionNote = 'Read-only mode: nothing on this PC is changed.'; return }
    $cleanMs = $it.IsMicrosoft -and $it.Risk -eq 'OK'
    switch ($it.Category) {
        { $_ -in 'Run Key', 'RunOnce', 'Policy Run' } { $it.CanDelete = $true; $it.CanDisable = [bool]$op.ApprovedKind; break }
        'Startup Folder' { $it.CanDelete = $true; $it.CanDisable = [bool]$op.ApprovedRoot; break }
        'Store App' { if ($op.ByPolicy) { $it.ActionNote = 'Controlled by policy.' } else { $it.CanDisable = $true }; break }
        'Scheduled Task' {
            if ($cleanMs -and $it.Name -like '\Microsoft\Windows\*') { $it.ActionNote = 'Windows system task, left alone to keep Windows healthy.' }
            else { $it.CanDisable = $true; $it.CanDelete = $true }
            break
        }
        'Service' { if ($cleanMs) { $it.ActionNote = 'Windows service, left alone to keep Windows healthy.' } else { $it.CanDisable = $true }; break }
        'Driver' {
            if ($op.Start -eq 'boot') { $it.ActionNote = "Boot driver. Windows may not start without it, so it can't be changed here." }
            elseif ($cleanMs) { $it.ActionNote = 'Windows driver, left alone to keep Windows healthy.' }
            else { $it.CanDisable = $true }
            break
        }
        { $_ -in 'Winlogon', 'Boot Execute' } { if ($it.Kind -eq 'Default') { $it.ActionNote = 'Windows default value. Windows needs it.' } else { $it.CanDelete = $true }; break }
        { $_ -in 'LSA', 'Explorer', 'Print Monitor', 'Netsh', 'Active Setup' } { if ($cleanMs) { $it.ActionNote = 'Part of Windows, left alone.' } else { $it.CanDelete = $true }; break }
        default { $it.CanDelete = $true }
    }
    if (-not $it.CanDisable -and -not $it.CanDelete -and -not $it.ActionNote) { $it.ActionNote = "This entry can't be changed from here." }
}

function Get-PssDataPath { return (Join-Path $env:ProgramData 'PaxStartupScanner') }

function Get-PssBackupPath { return (Join-Path (Get-PssDataPath) 'Backups') }

function Get-PssBackupDir {
    $d = Get-PssBackupPath
    if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force -ErrorAction Stop | Out-Null }
    return $d
}

function New-PssBackupName([string]$Suffix) {
    # Sortable to 100 ns so the newest change is always listed first
    return ('{0:yyyyMMdd-HHmmss-fffffff}-{1}{2}' -f (Get-Date), ([guid]::NewGuid().ToString('N').Substring(0, 4)), $Suffix)
}

function Open-PssKeyW([string]$Path, [switch]$Create) {
    Initialize-PssRegistry
    $i = $Path.IndexOf('\')
    $hive = $Path.Substring(0, $i); $sub = $Path.Substring($i + 1)
    $base = $null
    if ($hive -eq 'HKLM') { $base = $script:PssHKLM } elseif ($hive -eq 'HKU') { $base = $script:PssHKU }
    if (-not $base) { throw "Unsupported registry path: $Path" }
    $k = if ($Create) { $base.CreateSubKey($sub) } else { $base.OpenSubKey($sub, $true) }
    if (-not $k) { throw "Registry key not found: $Path" }
    return $k
}

function Backup-PssRegValue($Key, [string]$KeyPath, [string]$Name) {
    $step = @{ T = 'RegValue'; Key = $KeyPath; Name = $Name; Existed = $false; Kind = ''; Data = $null }
    if ($Key.GetValueNames() -contains $Name) {
        $kind = $Key.GetValueKind($Name)
        $data = $Key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $step.Existed = $true; $step.Kind = [string]$kind
        switch ([string]$kind) {
            'Binary' { $step.Data = [Convert]::ToBase64String([byte[]]$data) }
            'MultiString' { $step.Data = @([string[]]$data) }
            'DWord' { $step.Data = [int]$data }
            'QWord' { $step.Data = [long]$data }
            default { $step.Data = [string]$data }
        }
    }
    return $step
}

function Restore-PssRegValue($s) {
    $k = Open-PssKeyW $s.Key -Create
    try {
        if ($s.Existed) {
            $kind = [Microsoft.Win32.RegistryValueKind]$s.Kind
            switch ($s.Kind) {
                'Binary' { $k.SetValue($s.Name, [byte[]][Convert]::FromBase64String([string]$s.Data), $kind) }
                'MultiString' { $k.SetValue($s.Name, [string[]]@($s.Data | Where-Object { $null -ne $_ }), $kind) }
                'DWord' { $k.SetValue($s.Name, [int]$s.Data, $kind) }
                'QWord' { $k.SetValue($s.Name, [long]$s.Data, $kind) }
                default { $k.SetValue($s.Name, [string]$s.Data, $kind) }
            }
        } else { $k.DeleteValue($s.Name, $false) }
    } finally { $k.Close() }
}

function Save-PssUndo($it, [string]$Action, $Steps) {
    # $Steps is a List[object]; use ToArray() because @($list) on a List[object] throws
    # "Argument types do not match" in Windows PowerShell 5.1
    $rec = [pscustomobject][ordered]@{
        Version = 1; Time = (Get-Date).ToString('o'); Computer = $env:COMPUTERNAME; RunBy = "$env:USERDOMAIN\$env:USERNAME"
        Action = $Action; Category = $it.Category; Name = $it.Name; Location = $it.Location; ValueName = $it.ValueName; Command = $it.Command
        Steps = $Steps.ToArray()
    }
    $file = Join-Path (Get-PssBackupDir) (New-PssBackupName '.json')
    $rec | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $file -Encoding UTF8 -ErrorAction Stop
    return $file
}

function Complete-PssChange([string]$Record, [scriptblock]$Apply, [string[]]$Cleanup = @()) {
    # Runs the change; if it fails, the undo record (and any backup files) are removed so nothing is left half-done
    try { $null = & $Apply }
    catch {
        Remove-Item -LiteralPath $Record -ErrorAction SilentlyContinue
        foreach ($c in $Cleanup) { if ($c) { Remove-Item -LiteralPath $c -ErrorAction SilentlyContinue } }
        throw
    }
}

function Set-PssApprovedFlag($it, [string]$Action, [string]$Root, [string]$Kind, [string]$Name, $Steps) {
    # Task Manager's switch: byte 0 = 2 enabled, 3 disabled (+ FILETIME of when it was disabled)
    $path = "$Root\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\$Kind"
    $k = Open-PssKeyW $path -Create
    try {
        $Steps.Add((Backup-PssRegValue $k $path $Name))
        $rec = Save-PssUndo $it $Action $Steps
        $bytes = New-Object byte[] 12
        if ($Action -eq 'Enable') { $bytes[0] = 2 } else { $bytes[0] = 3; [BitConverter]::GetBytes((Get-Date).ToFileTime()).CopyTo($bytes, 4) }
        Complete-PssChange $rec { $k.SetValue($Name, $bytes, [Microsoft.Win32.RegistryValueKind]::Binary) }
        return $rec
    } finally { $k.Close() }
}

function Get-PssTask([string]$Path) {
    $svc = New-Object -ComObject Schedule.Service
    $svc.Connect()
    $i = $Path.LastIndexOf('\')
    $folderPath = if ($i -le 0) { '\' } else { $Path.Substring(0, $i) }
    $name = $Path.Substring($i + 1)
    $folder = $svc.GetFolder($folderPath)
    return @{ Folder = $folder; FolderPath = $folderPath; Name = $name; Task = $folder.GetTask($name) }
}

function Set-PssServiceStart([string]$Name, [string]$Start) {
    $out = & sc.exe config "$Name" start= $Start 2>&1
    if ($LASTEXITCODE -ne 0) { throw ((($out | Out-String) -replace '\s+', ' ').Trim()) }
}

function Get-PssListWithout($Key, $Op) {
    # The value with this item's part removed: @{ Value = new data or $null to delete; Kind }
    if ($Key.GetValueNames() -notcontains $Op.Name) { throw "The $($Op.Name) value is already gone." }
    $kind = $Key.GetValueKind($Op.Name)
    $cur = $Key.GetValue($Op.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    $part = ([string]$Op.Part).Trim()
    $empty = $(if ($Op.Default) { $Op.Default } else { $null })
    if ($kind -eq [Microsoft.Win32.RegistryValueKind]::MultiString) {
        $list = New-Object System.Collections.Generic.List[string]; $found = $false
        foreach ($e in @($cur)) {
            $e2 = [string]$e
            if (-not $found -and $e2.Trim() -ieq $part) { $found = $true; continue }
            if (-not $found) {
                $tokens = @($e2 -split '\s+' | Where-Object { $_ })
                if ($tokens.Count -gt 1 -and ($tokens -icontains $part)) { $e2 = (@($tokens | Where-Object { $_ -ine $part }) -join ' '); $found = $true }
            }
            if ($e2) { $list.Add($e2) }
        }
        if (-not $found) { throw "'$part' isn't in $($Op.Name) any more." }
        if ($list.Count -eq 0) { return @{ Value = $null; Kind = $kind } }
        return @{ Value = [string[]]$list.ToArray(); Kind = $kind }
    }
    $s = [string]$cur
    if ($Op.Sep -eq 'multi') {
        if ($s.Trim() -ine $part) { throw "'$part' isn't in $($Op.Name) any more." }
        return @{ Value = $empty; Kind = $kind }
    }
    $splitter = if ($Op.Sep -eq ' ') { '[,\s]+' } else { ',' }
    $trail = $s.TrimEnd().EndsWith(',')
    $parts = @($s -split $splitter | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $idx = -1
    for ($i = 0; $i -lt $parts.Count; $i++) { if ($parts[$i] -ieq $part) { $idx = $i; break } }
    if ($idx -lt 0) { throw "'$part' isn't in $($Op.Name) any more." }
    $rest = @(for ($i = 0; $i -lt $parts.Count; $i++) { if ($i -ne $idx) { $parts[$i] } })
    if ($rest.Count -eq 0) { return @{ Value = $empty; Kind = $kind } }
    $joined = $rest -join $(if ($Op.Sep -eq ' ') { ' ' } else { ',' })
    if ($trail) { $joined += ',' }
    return @{ Value = $joined; Kind = $kind }
}

function Format-PssError($Err) {
    $ex = $Err.Exception
    while ($ex.InnerException) { $ex = $ex.InnerException }
    $msg = [string]$ex.Message
    if ($ex -is [UnauthorizedAccessException] -or $ex -is [System.Security.SecurityException] -or $msg -match '(?i)access (is )?denied|0x80070005|FAILED 5:') {
        return 'Access denied. Run PowerShell as Administrator to change this item.'
    }
    return $msg.Trim()
}

function Get-PssConfirmText($it, [string]$Action) {
    $where = $it.Location; if ($it.ValueName) { $where += " -> $($it.ValueName)" }
    $what = "$($it.Name)`n$($it.Category): $where"
    $sys = $it.Category -in 'Winlogon', 'Boot Execute', 'LSA', 'AppInit', 'Print Monitor', 'Explorer', 'Netsh', 'Driver'
    switch ($Action) {
        'Disable' {
            $t = "Disable this startup item?`n`n$what`n`n"
            if ($it.Category -in 'Service', 'Driver') { $t += "Windows won't start it at boot any more. It keeps running until the next restart. Software that relies on it may stop working.`n`n" }
            else { $t += "It stays installed but won't start automatically. You can enable it again later.`n`n" }
        }
        'Enable' { $t = "Enable this startup item again?`n`n$what`n`n" }
        default {
            $t = "Delete this startup entry?`n`n$what`n`nThe program itself isn't uninstalled; only the entry that starts it is removed.`n"
            if ($sys) { $t += "This is a sensitive system setting. Only remove it if you're sure it doesn't belong there.`n" }
            if ($it.Category -eq 'WMI') { $t += "WMI subscriptions can't be restored automatically; the definition is saved for reference.`n" }
            $t += "`n"
        }
    }
    $t += "A backup is saved to $(Get-PssBackupPath) so you can undo this."
    return $t
}

function Invoke-PssChange($it, [string]$Action) {
    # Action: Disable | Enable | Delete. Returns @{ Ok; Message; Record }
    if ($it.State -eq 'Removed') { return @{ Ok = $false; Message = 'This item was already removed.'; Record = '' } }
    if ($Action -eq 'Delete' -and -not $it.CanDelete) { return @{ Ok = $false; Message = $(if ($it.ActionNote) { $it.ActionNote } else { "This entry can't be deleted here." }); Record = '' } }
    if ($Action -ne 'Delete' -and -not $it.CanDisable) { return @{ Ok = $false; Message = $(if ($it.ActionNote) { $it.ActionNote } else { "This entry can't be disabled, only deleted." }); Record = '' } }
    $op = $it.Op
    $steps = New-Object System.Collections.Generic.List[object]
    $rec = ''
    try {
        Initialize-PssRegistry
        $null = Get-PssBackupDir
        switch ($op.Type) {
            'RegValue' {
                if ($Action -eq 'Delete') {
                    $k = Open-PssKeyW $op.Key
                    try {
                        if ($k.GetValueNames() -notcontains $op.Name) { throw 'The entry is already gone.' }
                        $steps.Add((Backup-PssRegValue $k $op.Key $op.Name))
                        $rec = Save-PssUndo $it $Action $steps
                        Complete-PssChange $rec { $k.DeleteValue($op.Name) }
                    } finally { $k.Close() }
                } else { $rec = Set-PssApprovedFlag $it $Action $op.ApprovedRoot $op.ApprovedKind $op.Name $steps }
            }
            'File' {
                if ($Action -eq 'Delete') {
                    if (-not (Test-Path -LiteralPath $op.Path)) { throw 'The file is already gone.' }
                    $dest = Join-Path (Get-PssBackupDir) (New-PssBackupName ('_' + [IO.Path]::GetFileName($op.Path)))
                    $steps.Add(@{ T = 'File'; From = $dest; To = $op.Path })
                    $rec = Save-PssUndo $it $Action $steps
                    Complete-PssChange $rec { Move-Item -LiteralPath $op.Path -Destination $dest -ErrorAction Stop }
                } else { $rec = Set-PssApprovedFlag $it $Action $op.ApprovedRoot 'StartupFolder' $op.ApprovedName $steps }
            }
            'Task' {
                $t = Get-PssTask $op.Path
                if ($Action -eq 'Delete') {
                    $steps.Add(@{ T = 'Task'; Path = $op.Path; Xml = [string]$t.Task.Xml })
                    $rec = Save-PssUndo $it $Action $steps
                    Complete-PssChange $rec { $t.Folder.DeleteTask($t.Name, 0) }
                } else {
                    $steps.Add(@{ T = 'TaskEnabled'; Path = $op.Path; Enabled = [bool]$t.Task.Enabled })
                    $rec = Save-PssUndo $it $Action $steps
                    Complete-PssChange $rec { $t.Task.Enabled = ($Action -eq 'Enable') }
                }
            }
            'Service' {
                $target = if ($Action -eq 'Disable') { 'disabled' } else { $op.Start }
                $steps.Add(@{ T = 'Service'; Name = $op.Name; Start = $(if ($Action -eq 'Disable') { $op.Start } else { 'disabled' }) })
                $rec = Save-PssUndo $it $Action $steps
                Complete-PssChange $rec { Set-PssServiceStart $op.Name $target }
            }
            'StoreApp' {
                $k = Open-PssKeyW $op.Key
                try {
                    $steps.Add((Backup-PssRegValue $k $op.Key 'State'))
                    $rec = Save-PssUndo $it $Action $steps
                    Complete-PssChange $rec { $k.SetValue('State', $(if ($Action -eq 'Enable') { 2 } else { 1 }), [Microsoft.Win32.RegistryValueKind]::DWord) }
                } finally { $k.Close() }
            }
            'RegKey' {
                $file = Join-Path (Get-PssBackupDir) (New-PssBackupName '.reg')
                $out = & reg.exe export $op.Key $file /y /reg:64 2>&1
                if ($LASTEXITCODE -ne 0) { throw "Couldn't back up $($op.Key): $((($out | Out-String) -replace '\s+', ' ').Trim())" }
                $steps.Add(@{ T = 'RegImport'; File = $file; Key = $op.Key })
                $rec = Save-PssUndo $it $Action $steps
                $i = $op.Key.LastIndexOf('\')
                Complete-PssChange $rec {
                    $parent = Open-PssKeyW $op.Key.Substring(0, $i)
                    try { $parent.DeleteSubKeyTree($op.Key.Substring($i + 1), $false) } finally { $parent.Close() }
                } @($file)
            }
            'ListPart' {
                $k = Open-PssKeyW $op.Key
                try {
                    $steps.Add((Backup-PssRegValue $k $op.Key $op.Name))
                    $new = Get-PssListWithout $k $op
                    $rec = Save-PssUndo $it $Action $steps
                    Complete-PssChange $rec {
                        if ($null -eq $new.Value) { $k.DeleteValue($op.Name, $false) } else { $k.SetValue($op.Name, $new.Value, $new.Kind) }
                    }
                } finally { $k.Close() }
            }
            'Wmi' {
                $ns = 'root\subscription'
                $consumer = @(Get-CimInstance -Namespace $ns -ClassName $op.Class -ErrorAction Stop | Where-Object { $_.Name -eq $op.Name }) | Select-Object -First 1
                if (-not $consumer) { throw 'The WMI subscription is already gone.' }
                $bindings = @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction Stop | Where-Object { $_.Consumer.Name -eq $op.Name })
                $allFilters = @(Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction SilentlyContinue)
                $filters = @($allFilters | Where-Object { $bindings.Filter.Name -contains $_.Name })
                $info = @{
                    ConsumerClass = $op.Class; ConsumerName = $op.Name
                    CommandLineTemplate = [string]$consumer.CommandLineTemplate; ExecutablePath = [string]$consumer.ExecutablePath
                    ScriptingEngine = [string]$consumer.ScriptingEngine; ScriptFileName = [string]$consumer.ScriptFileName; ScriptText = [string]$consumer.ScriptText
                    Filters = @($filters | ForEach-Object { @{ Name = $_.Name; Query = $_.Query; QueryLanguage = $_.QueryLanguage; EventNamespace = $_.EventNamespace } })
                }
                $steps.Add(@{ T = 'Wmi'; Info = $info })
                $rec = Save-PssUndo $it $Action $steps
                foreach ($b in $bindings) { Remove-CimInstance -InputObject $b -ErrorAction Stop }
                foreach ($f in $filters) {
                    $still = @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object { $_.Filter.Name -eq $f.Name })
                    if (-not $still) { Remove-CimInstance -InputObject $f -ErrorAction Stop }
                }
                Remove-CimInstance -InputObject $consumer -ErrorAction Stop
            }
            default { throw "This entry can't be changed from here." }
        }
    } catch {
        # A WMI record stays even after a partial removal: it is the only copy of what was there
        if ($rec -and $op.Type -ne 'Wmi') { Remove-Item -LiteralPath $rec -ErrorAction SilentlyContinue }
        return @{ Ok = $false; Message = (Format-PssError $_); Record = '' }
    }
    switch ($Action) {
        'Disable' { $it.Enabled = $false; $it.EnabledText = 'No' }
        'Enable' { $it.Enabled = $true; $it.EnabledText = 'Yes' }
        default { $it.State = 'Removed'; $it.Enabled = $false; $it.EnabledText = 'Removed' }
    }
    Set-PssPermissions $it
    $msg = switch ($Action) {
        'Disable' { if ($it.Category -in 'Service', 'Driver') { "Disabled $($it.Name). It won't start with Windows after the next restart." } else { "Disabled $($it.Name). It won't start automatically any more." } }
        'Enable' { "Enabled $($it.Name) again." }
        default { if ($op.Type -eq 'Wmi') { "Removed the WMI subscription $($it.Name). Its definition is saved in the backup folder." } else { "Deleted the startup entry for $($it.Name). Undo can put it back." } }
    }
    return @{ Ok = $true; Message = $msg; Record = $rec }
}

function Get-PssUndoRecords {
    $dir = Get-PssBackupPath
    if (-not (Test-Path -LiteralPath $dir)) { return @() }
    $out = @()
    foreach ($f in (Get-ChildItem -LiteralPath $dir -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object Name -Descending)) {
        try {
            $r = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
            $when = ''; try { $when = ([datetime]::Parse([string]$r.Time)).ToString('yyyy-MM-dd HH:mm') } catch {}
            $r | Add-Member -NotePropertyName File -NotePropertyValue $f.FullName -Force
            $r | Add-Member -NotePropertyName When -NotePropertyValue $when -Force
            $out += $r
        } catch {}
    }
    return $out
}

function Invoke-PssStep($s) {
    # Puts one saved piece of state back (used by Undo and by full-backup restore)
    switch ($s.T) {
        'RegValue' { Restore-PssRegValue $s }
        'File' {
            if (Test-Path -LiteralPath $s.To) { throw "A file already exists at $($s.To)." }
            if (-not (Test-Path -LiteralPath $s.From)) { throw "The backup file is missing: $($s.From)" }
            $parent = Split-Path -Parent $s.To
            if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null }
            Move-Item -LiteralPath $s.From -Destination $s.To -ErrorAction Stop
        }
        'FileContent' {
            # full backups carry the file itself; it is only written when missing or different
            $same = $false
            if (Test-Path -LiteralPath $s.Path) { $same = [Convert]::ToBase64String([IO.File]::ReadAllBytes($s.Path)) -eq [string]$s.Data }
            if (-not $same) {
                $parent = Split-Path -Parent $s.Path
                if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null }
                [IO.File]::WriteAllBytes($s.Path, [Convert]::FromBase64String([string]$s.Data))
            }
        }
        'Task' {
            $i = $s.Path.LastIndexOf('\')
            $folder = if ($i -le 0) { '\' } else { $s.Path.Substring(0, $i) + '\' }
            Register-ScheduledTask -Xml ([string]$s.Xml) -TaskName $s.Path.Substring($i + 1) -TaskPath $folder -Force -ErrorAction Stop | Out-Null
        }
        'TaskEnabled' { $t = Get-PssTask $s.Path; $t.Task.Enabled = [bool]$s.Enabled }
        'Service' { Set-PssServiceStart $s.Name $s.Start }
        'RegImport' {
            $out = & reg.exe import $s.File /reg:64 2>&1
            if ($LASTEXITCODE -ne 0) { throw "reg import failed: $((($out | Out-String) -replace '\s+', ' ').Trim())" }
        }
        'RegText' {
            # a .reg export carried inside a full backup
            $tmp = Join-Path $env:TEMP ('pss-restore-' + [guid]::NewGuid().ToString('N') + '.reg')
            try {
                [IO.File]::WriteAllText($tmp, [string]$s.Text, [Text.Encoding]::Unicode)
                $out = & reg.exe import $tmp /reg:64 2>&1
                if ($LASTEXITCODE -ne 0) { throw "reg import failed: $((($out | Out-String) -replace '\s+', ' ').Trim())" }
            } finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
        }
        default { throw "Unknown backup step '$($s.T)'." }
    }
}

function Get-PssSnapshotSteps($it) {
    # The current state of one entry, captured without changing anything
    $op = $it.Op
    $steps = New-Object System.Collections.Generic.List[object]
    $addValue = {
        param([string]$Path, [string]$Name)
        $k = Open-PssKey $Path
        if ($k) { try { $steps.Add((Backup-PssRegValue $k $Path $Name)) } finally { $k.Close() } }
        else { $steps.Add(@{ T = 'RegValue'; Key = $Path; Name = $Name; Existed = $false; Kind = ''; Data = $null }) }
    }
    switch ($op.Type) {
        'RegValue' {
            & $addValue $op.Key $op.Name
            if ($op.ApprovedKind) { & $addValue "$($op.ApprovedRoot)\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\$($op.ApprovedKind)" $op.Name }
        }
        'File' {
            if (Test-Path -LiteralPath $op.Path) { $steps.Add(@{ T = 'FileContent'; Path = $op.Path; Data = [Convert]::ToBase64String([IO.File]::ReadAllBytes($op.Path)) }) }
            if ($op.ApprovedRoot) { & $addValue "$($op.ApprovedRoot)\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder" $op.ApprovedName }
        }
        'Task' {
            $t = Get-PssTask $op.Path
            $steps.Add(@{ T = 'Task'; Path = $op.Path; Xml = [string]$t.Task.Xml })
            $steps.Add(@{ T = 'TaskEnabled'; Path = $op.Path; Enabled = [bool]$t.Task.Enabled })
        }
        'Service' { $steps.Add(@{ T = 'Service'; Name = $op.Name; Start = $(if ($it.Enabled) { $op.Start } else { 'disabled' }) }) }
        'StoreApp' { & $addValue $op.Key 'State' }
        'ListPart' { & $addValue $op.Key $op.Name }
        'RegKey' {
            $tmp = Join-Path $env:TEMP ('pss-export-' + [guid]::NewGuid().ToString('N') + '.reg')
            try {
                $null = & reg.exe export $op.Key $tmp /y /reg:64 2>&1
                if ($LASTEXITCODE -eq 0) { $steps.Add(@{ T = 'RegText'; Key = $op.Key; Text = [IO.File]::ReadAllText($tmp) }) }
            } finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
        }
    }
    return , $steps.ToArray()
}

function New-PssSnapshot($Scan) {
    # Full backup of every entry the scanner could change, as JSON text. Protected Windows parts
    # are left out: they can't be changed here, so there is nothing to restore.
    $ro = $script:PssReadOnly; $script:PssReadOnly = $false
    $entries = New-Object System.Collections.Generic.List[object]
    $skipped = 0
    try {
        Initialize-PssRegistry
        foreach ($it in $Scan.Items) {
            if ($it.State -eq 'Removed' -or -not $it.Op -or $it.Op.Type -in 'Blocked', 'Wmi') { continue }
            $keep = @($it.CanDisable, $it.CanDelete, $it.ActionNote)
            Set-PssPermissions $it
            $changeable = $it.CanDisable -or $it.CanDelete
            $it.CanDisable = $keep[0]; $it.CanDelete = $keep[1]; $it.ActionNote = $keep[2]
            if (-not $changeable) { continue }
            try {
                $steps = Get-PssSnapshotSteps $it
                if ($steps.Count) { $entries.Add([pscustomobject][ordered]@{ Category = $it.Category; Name = $it.Name; Location = $it.Location; Command = $it.Command; Enabled = [bool]$it.Enabled; Steps = $steps }) }
            } catch { $skipped++ }
        }
    } finally { $script:PssReadOnly = $ro }
    $snap = [pscustomobject][ordered]@{
        Format = 'PaxStartupScanner.Backup'; Version = 1; Computer = $env:COMPUTERNAME; Time = (Get-Date).ToString('o')
        RunBy = "$env:USERDOMAIN\$env:USERNAME"; ScannerVersion = $script:PssVersion; Count = $entries.Count; Skipped = $skipped
        Items = $entries.ToArray()
    }
    return ($snap | ConvertTo-Json -Depth 8)
}

function Read-PssSnapshot([string]$Json) {
    $s = $null
    try { $s = $Json | ConvertFrom-Json } catch {}
    if (-not $s -or $s.Format -ne 'PaxStartupScanner.Backup') { throw "That isn't a PAX Startup Scanner backup." }
    return $s
}

function Restore-PssSnapshot($Snap) {
    # Puts every entry in a full backup back the way it was. Returns @{ Ok; Message; Failed }
    if ($script:PssReadOnly) { return @{ Ok = $false; Message = 'Read-only mode: nothing on this PC is changed.'; Failed = @() } }
    Initialize-PssRegistry
    $failed = @(); $done = 0
    foreach ($e in @($Snap.Items)) {
        try { foreach ($s in @($e.Steps)) { Invoke-PssStep $s }; $done++ }
        catch { $failed += ('{0} ({1}): {2}' -f $e.Name, $e.Category, (Format-PssError $_)) }
    }
    $when = ''; try { $when = ([datetime]::Parse([string]$Snap.Time)).ToString('yyyy-MM-dd HH:mm') } catch {}
    $msg = "Restored $done of $(@($Snap.Items).Count) startup entries from the backup of $($Snap.Computer) taken $when."
    if ($failed) { $msg += " $($failed.Count) could not be restored." }
    return @{ Ok = (-not $failed); Message = $msg; Failed = $failed }
}

function Invoke-PssUndo($Rec) {
    # Replays the record's backup steps in reverse, then files the record under Backups\Restored
    if ($script:PssReadOnly) { return @{ Ok = $false; Message = 'Read-only mode: nothing on this PC is changed.' } }
    $steps = @($Rec.Steps)
    [array]::Reverse($steps)
    try {
        Initialize-PssRegistry
        foreach ($s in $steps) {
            if ($s.T -eq 'Wmi') { throw "WMI subscriptions aren't restored automatically. The removed definition is saved in $($Rec.File)." }
            Invoke-PssStep $s
        }
    } catch { return @{ Ok = $false; Message = (Format-PssError $_) } }
    try {
        $done = Join-Path (Get-PssBackupPath) 'Restored'
        if (-not (Test-Path -LiteralPath $done)) { New-Item -ItemType Directory -Path $done -Force | Out-Null }
        Move-Item -LiteralPath $Rec.File -Destination $done -Force -ErrorAction Stop
    } catch {}
    $verb = switch ($Rec.Action) { 'Delete' { 'deletion' } 'Disable' { 'disabling' } 'Enable' { 'enabling' } default { 'change' } }
    return @{ Ok = $true; Message = "Undid the $verb of $($Rec.Name). Rescan to see it in the list again." }
}

# ======================================================================================
#  Boot tests: time real restarts before and after changes and compare them
#  Arming writes boot-probe.ps1 to %ProgramData%\PaxStartupScanner and registers two one-shot
#  SYSTEM tasks (at startup, at sign-in). They record when Windows went idle at the sign-in
#  screen and when the desktop went idle after sign-in (time spent typing the password is not
#  counted), save the result to BootTests\, then remove the tasks and the probe.
# ======================================================================================

$script:PssProbeScript = @'
# PAX Startup Scanner boot test probe (runs once at the next startup and sign-in, then removes itself)
param([ValidateSet('startup', 'logon')][string]$Phase = 'logon', [string]$OutDir = '', [int]$MaxSeconds = 600, [switch]$NoDisarm, [string]$TestStart = '')
$ErrorActionPreference = 'Continue'
$root = Join-Path $env:ProgramData 'PaxStartupScanner'
if (-not $OutDir) { $OutDir = Join-Path $root 'BootTests' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$id = $boot.ToString('yyyyMMdd-HHmmss')
$test = if ($TestStart) { [datetime]::Parse($TestStart) } else { $null }
$label = ''
try { $label = [string](Get-Content -LiteralPath (Join-Path $root 'boot-test.json') -Raw -ErrorAction Stop | ConvertFrom-Json).Label } catch {}

function Get-Load {
    $cpu = $null; $diskIdle = $null
    try { $cpu = [double](@(Get-CimInstance Win32_Processor -ErrorAction Stop) | Measure-Object -Property LoadPercentage -Average).Average } catch {}
    try { $diskIdle = [double](Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'" -ErrorAction Stop).PercentIdleTime } catch {}
    return @{ Cpu = $cpu; DiskIdle = $diskIdle }
}

function Test-SignedIn {
    # the user's desktop shell has started since boot
    return [bool](Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CreationDate -gt $boot })
}

function Get-SignIn {
    # newest real user sign-in since boot (skips the Window Manager / Font Driver Host sessions Windows creates itself)
    $ids = @{}
    foreach ($l in @(Get-CimInstance Win32_LoggedOnUser -ErrorAction SilentlyContinue)) {
        if ([string]$l.Antecedent.Domain -in 'Window Manager', 'Font Driver Host') { continue }
        $ids[[string]$l.Dependent.LogonId] = $true
    }
    $s = @(Get-CimInstance Win32_LogonSession -ErrorAction SilentlyContinue | Where-Object { $_.LogonType -in 2, 10, 11 -and $_.StartTime -gt $boot -and $ids.ContainsKey([string]$_.LogonId) })
    if ($s) { return ($s | Sort-Object StartTime | Select-Object -Last 1).StartTime }
    $shell = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CreationDate -gt $boot } | Sort-Object CreationDate | Select-Object -First 1
    if ($shell) { return $shell.CreationDate }
    return $null
}

function Wait-Quiet([datetime]$From, [switch]$StopAtSignIn) {
    # the first moment the PC stayed quiet (CPU under 20%, disk mostly idle) for 10 seconds
    $quietSince = $null
    while (((Get-Date) - $From).TotalSeconds -lt $MaxSeconds) {
        if ($StopAtSignIn -and (Test-SignedIn)) { return @{ Time = $null; SignedIn = $true } }
        $l = Get-Load
        $quiet = ($null -ne $l.Cpu -and $l.Cpu -lt 20) -and ($null -eq $l.DiskIdle -or $l.DiskIdle -ge 80)
        if ($quiet) {
            if (-not $quietSince) { $quietSince = Get-Date }
            if (((Get-Date) - $quietSince).TotalSeconds -ge 10) { return @{ Time = $quietSince; SignedIn = $false } }
        } else { $quietSince = $null }
        Start-Sleep -Seconds 1
    }
    return @{ Time = $null; SignedIn = $false }
}

$rec = [ordered]@{ Version = 1; Phase = $Phase; Computer = $env:COMPUTERNAME; BootTime = $boot.ToString('o'); Label = $label; Started = (Get-Date).ToString('o') }
if ($Phase -eq 'startup') {
    $from = if ($test) { $test } else { $boot }
    $r = Wait-Quiet $from -StopAtSignIn:(-not $test)
    $rec.IdleBeforeSignIn = $(if ($r.Time) { $r.Time.ToString('o') } else { $null })
    $rec.SignedInFirst = [bool]$r.SignedIn
} else {
    $signIn = if ($test) { $test } else { Get-SignIn }
    if (-not $signIn) { $signIn = Get-Date }
    $shell = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CreationDate -gt $boot } | Sort-Object CreationDate | Select-Object -First 1
    $r = Wait-Quiet $signIn
    $rec.SignIn = $signIn.ToString('o')
    $rec.ShellStart = $(if ($shell) { $shell.CreationDate.ToString('o') } else { $null })
    $rec.DesktopIdle = $(if ($r.Time) { $r.Time.ToString('o') } else { $null })
    # what used the CPU after sign-in
    $since = $signIn.AddSeconds(-10)
    $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CreationDate -ge $since -and $_.ExecutablePath })
    $rec.ProcessesStarted = $procs.Count
    $rec.TopProcesses = @($procs | Group-Object ExecutablePath | ForEach-Object {
            $cpu = 0; foreach ($p in $_.Group) { $cpu += ([double]$p.KernelModeTime + [double]$p.UserModeTime) / 1e7 }
            $first = ($_.Group | Sort-Object CreationDate | Select-Object -First 1).CreationDate
            [pscustomobject]@{ Name = $_.Group[0].Name; Path = $_.Name; CpuSec = [math]::Round($cpu, 1); Count = $_.Count; StartedAfterSec = [math]::Round(($first - $signIn).TotalSeconds, 1) }
        } | Sort-Object CpuSec -Descending | Select-Object -First 15)
}
$rec.Finished = (Get-Date).ToString('o')
$rec | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $OutDir "$id-$Phase.json") -Encoding UTF8

if ($Phase -eq 'logon' -and -not $NoDisarm) {
    foreach ($t in 'Boot test - startup', 'Boot test - sign-in') { Unregister-ScheduledTask -TaskName $t -TaskPath '\PAX Startup Scanner\' -Confirm:$false -ErrorAction SilentlyContinue }
    try { $svc = New-Object -ComObject Schedule.Service; $svc.Connect(); $svc.GetFolder('\').DeleteFolder('PAX Startup Scanner', 0) } catch {}
    Remove-Item -LiteralPath (Join-Path $root 'boot-test.json') -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $PSCommandPath -ErrorAction SilentlyContinue
}
'@

function Format-PssSec($s) {
    if ($null -eq $s) { return '-' }
    if ($s -ge 60) { return ('{0}m {1:N0}s' -f [math]::Floor($s / 60), ($s % 60)) }
    return ('{0:N1}s' -f $s)
}

function Get-PssBootTestState {
    # The armed test (label, when) or $null
    $f = Join-Path (Get-PssDataPath) 'boot-test.json'
    if (-not (Test-Path -LiteralPath $f)) { return $null }
    try { return (Get-Content -LiteralPath $f -Raw | ConvertFrom-Json) } catch { return $null }
}

function Stop-PssBootTest {
    foreach ($t in 'Boot test - startup', 'Boot test - sign-in') { Unregister-ScheduledTask -TaskName $t -TaskPath '\PAX Startup Scanner\' -Confirm:$false -ErrorAction SilentlyContinue }
    try { $svc = New-Object -ComObject Schedule.Service; $svc.Connect(); $svc.GetFolder('\').DeleteFolder('PAX Startup Scanner', 0) } catch {}
    $root = Get-PssDataPath
    Remove-Item -LiteralPath (Join-Path $root 'boot-test.json') -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (Join-Path $root 'boot-probe.ps1') -ErrorAction SilentlyContinue
    return @{ Ok = $true; Message = 'Boot test cancelled. Nothing will run at the next restart.' }
}

function Start-PssBootTest([string]$Label) {
    # Arms a one-shot timing of the next restart (needs admin: the tasks run as SYSTEM)
    if ($script:PssReadOnly) { return @{ Ok = $false; Message = 'Read-only mode: boot tests are off (they need scheduled tasks on this PC).' } }
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { return @{ Ok = $false; Message = 'Timing a restart needs an elevated PowerShell (Run as Administrator).' } }
    if (-not $Label) { $Label = 'Boot test {0:yyyy-MM-dd HH:mm}' -f (Get-Date) }
    try {
        $root = Get-PssDataPath
        if (-not (Test-Path -LiteralPath $root)) { New-Item -ItemType Directory -Path $root -Force -ErrorAction Stop | Out-Null }
        $probe = Join-Path $root 'boot-probe.ps1'
        Set-Content -LiteralPath $probe -Value $script:PssProbeScript -Encoding UTF8 -ErrorAction Stop
        [pscustomobject]@{ Label = $Label; ArmedAt = (Get-Date).ToString('o'); ArmedBy = "$env:USERDOMAIN\$env:USERNAME" } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'boot-test.json') -Encoding UTF8 -ErrorAction Stop
        $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
        $defs = @(
            @{ Name = 'Boot test - startup'; Phase = 'startup'; Trigger = (New-ScheduledTaskTrigger -AtStartup) }
            @{ Name = 'Boot test - sign-in'; Phase = 'logon'; Trigger = (New-ScheduledTaskTrigger -AtLogOn) }
        )
        foreach ($d in $defs) {
            $act = New-ScheduledTaskAction -Execute $ps -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Phase {1}' -f $probe, $d.Phase)
            Register-ScheduledTask -TaskName $d.Name -TaskPath '\PAX Startup Scanner\' -Action $act -Trigger $d.Trigger -Principal $principal -Settings $settings -Description 'PAX Startup Scanner: times the next restart, then removes itself.' -Force -ErrorAction Stop | Out-Null
        }
        return @{ Ok = $true; Message = "Boot test '$Label' is ready. Restart the PC (Restart, not Shut down) and sign in. The result shows up here once the desktop has settled." }
    } catch {
        $err = Format-PssError $_
        $null = Stop-PssBootTest
        return @{ Ok = $false; Message = $err }
    }
}

function Restart-PssNow {
    # Full restart (a "Shut down" with Fast Startup would skip the startup measurement)
    if ($script:PssReadOnly) { return @{ Ok = $false; Message = 'Read-only mode: the scanner does not restart the PC.' } }
    $out = & shutdown.exe /r /t 15 /c "PAX Startup Scanner boot test: restarting in 15 seconds." 2>&1
    if ($LASTEXITCODE -ne 0) { return @{ Ok = $false; Message = ((($out | Out-String) -replace '\s+', ' ').Trim()) } }
    return @{ Ok = $true; Message = 'Restarting in 15 seconds. To stop it, run: shutdown /a' }
}

function Get-PssBootTests {
    # Joins the start-up and sign-in halves of each timed restart; newest first
    $dir = Join-Path (Get-PssDataPath) 'BootTests'
    if (-not (Test-Path -LiteralPath $dir)) { return @() }
    $out = @()
    foreach ($g in (Get-ChildItem -LiteralPath $dir -Filter '*.json' -File -ErrorAction SilentlyContinue | Group-Object { $_.BaseName -replace '-(startup|logon)$', '' })) {
        $st = $null; $lg = $null
        foreach ($f in $g.Group) {
            try {
                $j = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json
                if ($j.Phase -eq 'startup') { $st = $j } elseif ($j.Phase -eq 'logon') { $lg = $j }
            } catch {}
        }
        $src = if ($lg) { $lg } else { $st }
        if (-not $src) { continue }
        $boot = [datetime]::Parse([string]$src.BootTime)
        $idle = if ($st -and $st.IdleBeforeSignIn) { [datetime]::Parse([string]$st.IdleBeforeSignIn) } else { $null }
        $signIn = if ($lg -and $lg.SignIn) { [datetime]::Parse([string]$lg.SignIn) } else { $null }
        $desk = if ($lg -and $lg.DesktopIdle) { [datetime]::Parse([string]$lg.DesktopIdle) } else { $null }
        $first = [bool]($st -and $st.SignedInFirst)
        # with a quick sign-in the start-up clock runs to the sign-in instead (no waiting at the sign-in screen to subtract)
        $bootSec = if ($idle) { [math]::Round(($idle - $boot).TotalSeconds, 1) } elseif ($first -and $signIn) { [math]::Round(($signIn - $boot).TotalSeconds, 1) } else { $null }
        $signSec = if ($signIn -and $desk) { [math]::Round(($desk - $signIn).TotalSeconds, 1) } else { $null }
        $total = if ($null -ne $bootSec -and $null -ne $signSec) { [math]::Round($bootSec + $signSec, 1) } else { $null }
        $label = if ($lg -and $lg.Label) { [string]$lg.Label } elseif ($st -and $st.Label) { [string]$st.Label } else { '' }
        $notes = @()
        if (-not $st) { $notes += 'start-up half missing' }
        if (-not $lg) { $notes += $(if ($st) { 'waiting for sign-in' } else { 'sign-in half missing' }) }
        if ($first) { $notes += 'signed in before Windows went idle' }
        if ($lg -and -not $desk) { $notes += "desktop didn't settle within 10 minutes" }
        if ($st -and -not $idle -and -not $first) { $notes += "Windows didn't settle within 10 minutes" }
        $out += [pscustomobject]@{
            Id = $g.Name; Boot = $boot; When = $boot.ToString('yyyy-MM-dd HH:mm'); Label = $label
            BootToIdleSec = $bootSec; SignInToIdleSec = $signSec; TotalSec = $total
            BootText = (Format-PssSec $bootSec); SignInText = (Format-PssSec $signSec); TotalText = (Format-PssSec $total)
            SignedInFirst = $first; SignIn = $signIn
            ProcessesStarted = $(if ($lg) { $lg.ProcessesStarted } else { $null })
            TopProcesses = $(if ($lg) { @($lg.TopProcesses) } else { @() })
            Notes = ($notes -join '; ')
        }
    }
    return @($out | Sort-Object Boot -Descending)
}

function Get-PssChangeHistory {
    # Every change saved by the scanner (still undoable or already undone), oldest first
    $out = @()
    $base = Get-PssBackupPath
    foreach ($d in @($base, (Join-Path $base 'Restored'))) {
        if (-not (Test-Path -LiteralPath $d)) { continue }
        foreach ($f in (Get-ChildItem -LiteralPath $d -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
            try {
                $r = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json
                $out += [pscustomobject]@{ Time = [datetime]::Parse([string]$r.Time); Action = [string]$r.Action; Category = [string]$r.Category; Name = [string]$r.Name; Undone = ($d -ne $base) }
            } catch {}
        }
    }
    return @($out | Sort-Object Time)
}

function Compare-PssBootTests($Old, $New) {
    # Before/after comparison as display lines: @{ Text; Color }
    $lines = New-Object System.Collections.Generic.List[object]
    $add = { param([string]$t, [string]$c = 'Gray') $lines.Add([pscustomobject]@{ Text = $t; Color = $c }) }
    $on = if ($Old.Label) { $Old.Label } else { 'Earlier test' }
    $nn = if ($New.Label) { $New.Label } else { 'Later test' }
    & $add ('{0} ({1})  ->  {2} ({3})' -f $on, $Old.When, $nn, $New.When) 'White'
    & $add ''
    $rows = @(
        @('Windows start-up (power-on to idle sign-in screen)', 'BootToIdleSec'),
        @('Sign-in to desktop ready', 'SignInToIdleSec'),
        @('Total start-up time (not counting time at the sign-in screen)', 'TotalSec')
    )
    foreach ($m in $rows) {
        $a = $Old.($m[1]); $b = $New.($m[1])
        if ($null -eq $a -or $null -eq $b) { & $add ('  {0,-64}{1,9} ->{2,9}' -f $m[0], (Format-PssSec $a), (Format-PssSec $b)) 'DarkGray'; continue }
        $d = [math]::Round($b - $a, 1)
        $pct = if ($a -gt 0) { [math]::Round(100 * [math]::Abs($d) / $a) } else { 0 }
        $verdict = if ([math]::Abs($d) -lt 2) { 'about the same' } elseif ($d -lt 0) { '{0:N1}s faster (-{1}%)' -f (-$d), $pct } else { '{0:N1}s slower (+{1}%)' -f $d, $pct }
        $color = if ([math]::Abs($d) -lt 2) { 'Gray' } elseif ($d -lt 0) { 'Green' } else { 'Red' }
        & $add ('  {0,-64}{1,9} ->{2,9}   {3}' -f $m[0], (Format-PssSec $a), (Format-PssSec $b), $verdict) $color
    }
    if ($null -ne $Old.ProcessesStarted -and $null -ne $New.ProcessesStarted) {
        & $add ('  {0,-64}{1,9} ->{2,9}' -f 'Programs started after sign-in', $Old.ProcessesStarted, $New.ProcessesStarted) 'Gray'
    }
    & $add ''
    & $add 'Changes made with PAX Startup Scanner between the two tests:' 'White'
    $changes = @(Get-PssChangeHistory | Where-Object { $_.Time -gt $Old.Boot -and $_.Time -lt $New.Boot })
    if (-not $changes) { & $add '  None recorded. Windows updates, new software and other changes also affect start-up time.' 'DarkGray' }
    foreach ($c in $changes) { & $add ('  {0,-8} {1,-15} {2}{3}' -f $c.Action, $c.Category, $c.Name, $(if ($c.Undone) { '   (undone later)' } else { '' })) $(if ($c.Action -eq 'Delete') { 'Red' } else { 'Yellow' }) }
    & $add ''
    & $add 'Busiest programs after sign-in (CPU seconds used until the desktop was ready):' 'White'
    $fmt = { param($t) if ($t.TopProcesses) { (@($t.TopProcesses | Select-Object -First 6 | ForEach-Object { '{0} {1:N1}s' -f $_.Name, $_.CpuSec }) -join ', ') } else { '-' } }
    & $add ('  Before: ' + (& $fmt $Old)) 'Gray'
    & $add ('  After:  ' + (& $fmt $New)) 'Gray'
    & $add ''
    & $add 'Start-up times vary by a few seconds between restarts. For a fair comparison, time two or three restarts each way.' 'DarkGray'
    return $lines
}

# ======================================================================================
#  Console interface
# ======================================================================================

$script:PssRiskColor = @{ High = 'Red'; Medium = 'Yellow'; Low = 'Cyan'; OK = 'Green' }
$script:PssShowMicrosoft = $false

function Get-PssWidth {
    $w = 120
    try { $w = $Host.UI.RawUI.WindowSize.Width } catch {}
    if (-not $w -or $w -lt 60) { $w = 120 }
    return $w - 1
}

function Format-PssCell([string]$s, [int]$w) {
    if ($null -eq $s) { $s = '' }
    $s = $s -replace '\s+', ' '
    if ($s.Length -gt $w) { if ($w -le 3) { return $s.Substring(0, $w) }; return $s.Substring(0, $w - 2) + '..' }
    return $s.PadRight($w)
}

function Write-PssRule([string]$Title = '', [string]$Color = 'DarkCyan') {
    $w = Get-PssWidth
    $h = [string][char]0x2500
    if ($Title) {
        Write-Host ''
        Write-Host ('  ' + $Title.ToUpper() + ' ') -NoNewline -ForegroundColor White
        Write-Host ($h * [Math]::Max(3, $w - $Title.Length - 3)) -ForegroundColor $Color
    } else { Write-Host ('  ' + ($h * ($w - 2))) -ForegroundColor $Color }
}

function Write-PssHeader($Scan) {
    try { Clear-Host 2>$null } catch {}
    $w = Get-PssWidth
    $h = [string][char]0x2550
    $inner = [Math]::Min($w - 4, 100)
    Write-Host ''
    Write-Host ('  ' + [char]0x2554 + ($h * $inner) + [char]0x2557) -ForegroundColor DarkCyan
    $t1 = "  PAX STARTUP SCANNER  v$($script:PssVersion)"
    $t2 = if ($script:PssReadOnly) { 'READ-ONLY  -  IT diagnostics  ' } else { 'IT diagnostics  ' }
    Write-Host ('  ' + [char]0x2551) -NoNewline -ForegroundColor DarkCyan
    Write-Host $t1 -NoNewline -ForegroundColor White
    Write-Host ($t2.PadLeft($inner - $t1.Length)) -NoNewline -ForegroundColor DarkGray
    Write-Host ([char]0x2551) -ForegroundColor DarkCyan
    Write-Host ('  ' + [char]0x255A + ($h * $inner) + [char]0x255D) -ForegroundColor DarkCyan
    if ($Scan) {
        Write-Host '   ' -NoNewline
        Write-Host $Scan.Computer -NoNewline -ForegroundColor White
        Write-Host "  $([char]0x00B7)  $($Scan.OS)  $([char]0x00B7)  " -NoNewline -ForegroundColor Gray
        if ($Scan.IsAdmin) { Write-Host 'Elevated' -ForegroundColor Green } else { Write-Host 'NOT elevated (partial results)' -ForegroundColor Yellow }
    }
}

function Write-PssKV([string]$Key, [string]$Value, [string]$Color = 'Gray', [int]$KeyWidth = 15) {
    $w = Get-PssWidth
    $avail = [Math]::Max(20, $w - $KeyWidth - 5)
    $lines = @()
    $text = [string]$Value
    while ($text.Length -gt $avail) {
        $cut = $text.LastIndexOfAny(@(' ', '\', ';', ','), $avail)
        if ($cut -lt $avail / 2) { $cut = $avail }
        $lines += $text.Substring(0, $cut); $text = $text.Substring($cut).TrimStart()
    }
    $lines += $text
    Write-Host ('   ' + $Key.PadRight($KeyWidth)) -NoNewline -ForegroundColor DarkGray
    Write-Host $lines[0] -ForegroundColor $Color
    for ($i = 1; $i -lt $lines.Count; $i++) { Write-Host ((' ' * ($KeyWidth + 3)) + $lines[$i]) -ForegroundColor $Color }
}

function Write-PssDashboard($Scan) {
    $items = $Scan.Items
    $third = @($items | Where-Object { -not $_.IsMicrosoft })
    $hi = @($items | Where-Object Risk -eq 'High').Count
    $me = @($items | Where-Object Risk -eq 'Medium').Count
    $lo = @($items | Where-Object Risk -eq 'Low').Count
    Write-Host ('   Scanned {0} startup items in {1:N1}s  -  {2} third-party, {3} Microsoft' -f $items.Count, $Scan.Duration, $third.Count, ($items.Count - $third.Count)) -ForegroundColor Gray

    Write-PssRule 'Risk summary'
    $max = [Math]::Max(1, [Math]::Max($hi, [Math]::Max($me, $lo)))
    foreach ($r in @(@('High', $hi, 'Needs attention now'), @('Medium', $me, 'Worth a look'), @('Low', $lo, 'Minor notes (missing files, new files...)'))) {
        $bar = ([string][char]0x2588) * [Math]::Ceiling(24 * $r[1] / $max)
        if ($r[1] -eq 0) { $bar = [string][char]0x00B7 }
        Write-Host ('   {0,-8}{1,4}  ' -f $r[0], $r[1]) -NoNewline -ForegroundColor $script:PssRiskColor[$r[0]]
        Write-Host $bar.PadRight(26) -NoNewline -ForegroundColor $script:PssRiskColor[$r[0]]
        Write-Host $r[2] -ForegroundColor DarkGray
    }

    Write-PssRule 'Where things start from'
    $groups = $items | Group-Object Category | Sort-Object Count -Descending
    Write-Host ('   {0,-18}{1,7}{2,6}{3,6}{4,13}{5,10}' -f 'Category', 'Total', 'On', 'Off', 'Third-party', 'Flagged') -ForegroundColor DarkGray
    foreach ($g in $groups) {
        $on = @($g.Group | Where-Object { $_.Enabled -and $_.State -ne 'Removed' }).Count
        $tp = @($g.Group | Where-Object { -not $_.IsMicrosoft }).Count
        $fl = @($g.Group | Where-Object { $_.Risk -in 'High', 'Medium' }).Count
        Write-Host ('   {0,-18}{1,7}{2,6}' -f $g.Name, $g.Count, $on) -NoNewline -ForegroundColor Gray
        Write-Host ('{0,6}' -f ($g.Count - $on)) -NoNewline -ForegroundColor $(if ($g.Count - $on) { 'DarkYellow' } else { 'DarkGray' })
        Write-Host ('{0,13}' -f $tp) -NoNewline -ForegroundColor $(if ($tp) { 'White' } else { 'DarkGray' })
        Write-Host ('{0,10}' -f $fl) -ForegroundColor $(if ($fl) { 'Yellow' } else { 'DarkGray' })
    }

    Write-PssRule 'Boot and performance'
    $b = $Scan.Boot
    if ($b.LastBootMs) {
        $col = if ($b.LastBootMs -gt 90000) { 'Red' } elseif ($b.LastBootMs -gt 45000) { 'Yellow' } else { 'Green' }
        $old = $b.LastBootTime -and ((Get-Date) - $b.LastBootTime).TotalDays -gt 30
        Write-Host '   Last boot      ' -NoNewline -ForegroundColor DarkGray
        Write-Host ('{0:N1}s' -f ($b.LastBootMs / 1000)) -NoNewline -ForegroundColor $col
        Write-Host ('   (to desktop {0:N1}s, settling {1:N1}s)  ' -f ($b.LastMainMs / 1000), ($b.LastPostMs / 1000)) -NoNewline -ForegroundColor Gray
        if ($b.LastBootTime) { Write-Host ('recorded {0:yyyy-MM-dd}' -f $b.LastBootTime) -ForegroundColor $(if ($old) { 'DarkYellow' } else { 'DarkGray' }) } else { Write-Host '' }
        if ($old) { Write-Host '                  Windows has not logged a newer boot timing, so treat these numbers as old.' -ForegroundColor DarkYellow }
        $avg = ($b.Boots | Select-Object -First 10 | Measure-Object BootSec -Average).Average
        if ($avg) { Write-Host ('   Avg last 10    {0:N1}s' -f $avg) -ForegroundColor Gray }
    } else { Write-Host "   $($b.Error)" -ForegroundColor DarkGray }
    if ($Scan.Uptime) { Write-Host ('   Uptime         {0}d {1}h {2}m' -f $Scan.Uptime.Days, $Scan.Uptime.Hours, $Scan.Uptime.Minutes) -ForegroundColor Gray }
    $heavy = @($items | Where-Object { $_.Impact -in 'High', 'Medium' -and -not $_.IsMicrosoft } | Sort-Object BootDelayMs, MemoryMB -Descending | Select-Object -First 5)
    if ($heavy) {
        Write-Host '   Heaviest third-party items:' -ForegroundColor DarkGray
        foreach ($it in $heavy) {
            $bits = @(); if ($it.BootDelayMs) { $bits += "boot delay $($it.BootDelayText)" }; if ($it.MemoryMB) { $bits += "$($it.MemoryMB) MB RAM" }
            if ($it.CpuSec -ge 60) { $bits += ('{0:N0} min CPU' -f ($it.CpuSec / 60)) }
            Write-Host ('     #{0,-4} ' -f $it.Id) -NoNewline -ForegroundColor DarkGray
            Write-Host (Format-PssCell $it.Name 40) -NoNewline -ForegroundColor White
            Write-Host ('  ' + ($bits -join ', ')) -ForegroundColor Yellow
        }
    }
    $runCount = @($items | Where-Object { $_.Category -in 'Run Key', 'Startup Folder', 'Store App' -and $_.Enabled }).Count
    Write-Host ('   Logon apps     {0} enabled in Run keys / Startup folders / Store apps' -f $runCount) -ForegroundColor Gray

    if ($Scan.NotLoadedProfiles -or $Scan.Errors) { Write-PssRule 'Notes' 'DarkYellow' }
    if ($Scan.NotLoadedProfiles) { Write-Host ("   Users not logged on (their registry Run keys were not read): " + ($Scan.NotLoadedProfiles -join ', ')) -ForegroundColor DarkYellow }
    foreach ($er in $Scan.Errors) { Write-Host "   $er" -ForegroundColor DarkYellow }
}

function Write-PssTable($Items, [string]$Title, [switch]$NoPaging) {
    $Items = @($Items)
    Write-PssRule ("$Title ($($Items.Count))")
    if (-not $Items) { Write-Host '   Nothing to show.' -ForegroundColor DarkGray; return }
    $w = Get-PssWidth
    $fixed = 3 + 5 + 7 + 15 + 3
    $rest = [Math]::Max(40, $w - $fixed - 3)
    $wName = [int]($rest * 0.30); $wPub = [int]($rest * 0.22); $wPath = $rest - $wName - $wPub - 2
    Write-Host ('   {0}{1}{2}{3} {4} {5}' -f 'ID'.PadRight(5), 'RISK'.PadRight(7), 'CATEGORY'.PadRight(15), (Format-PssCell 'NAME' $wName), (Format-PssCell 'PUBLISHER' $wPub), 'FILE') -ForegroundColor DarkGray
    $pageSize = 20
    try { $pageSize = [Math]::Max(10, $Host.UI.RawUI.WindowSize.Height - 8) } catch {}
    $n = 0
    foreach ($it in $Items) {
        $risk = if ($it.Risk -eq 'OK') { '' } else { $it.Risk }
        $dim = $it.IsMicrosoft -and $it.Risk -eq 'OK'
        Write-Host ('   ' + ([string]$it.Id).PadRight(5)) -NoNewline -ForegroundColor DarkGray
        Write-Host $risk.PadRight(7) -NoNewline -ForegroundColor $script:PssRiskColor[$it.Risk]
        Write-Host (Format-PssCell $it.Category 14) -NoNewline -ForegroundColor DarkCyan
        Write-Host ' ' -NoNewline
        $nameCol = if ($dim) { 'DarkGray' } elseif (-not $it.Enabled) { 'DarkGray' } else { 'White' }
        $nm = $it.Name; if ($it.State -eq 'Removed') { $nm = "$nm [removed]" } elseif (-not $it.Enabled) { $nm = "$nm [off]" }
        Write-Host (Format-PssCell $nm $wName) -NoNewline -ForegroundColor $nameCol
        Write-Host ' ' -NoNewline
        $pubCol = if ($it.SignStatus -eq 'Valid') { 'Gray' } elseif ($it.NoImage) { 'DarkGray' } else { 'Yellow' }
        Write-Host (Format-PssCell $it.Publisher $wPub) -NoNewline -ForegroundColor $(if ($dim) { 'DarkGray' } else { $pubCol })
        Write-Host ' ' -NoNewline
        $p = if ($it.NoImage) { $it.Command } else { $it.ImagePath }
        if ($p -and $p.Length -gt $wPath) { $p = '..' + $p.Substring($p.Length - $wPath + 2) }
        Write-Host (Format-PssCell $p $wPath) -ForegroundColor $(if (-not $it.NoImage -and -not $it.FileExists) { 'DarkYellow' } else { 'DarkGray' })
        if ($it.Flags -and $it.Risk -in 'High', 'Medium') {
            Write-Host ('          ' + [char]0x2514 + ' ' + (Format-PssCell $it.Flags ($w - 13)).TrimEnd()) -ForegroundColor $script:PssRiskColor[$it.Risk]
            $n++
        }
        $n++
        if (-not $NoPaging -and $n -ge $pageSize -and $it -ne $Items[-1]) {
            Write-Host '   -- more: Enter = next page, # = details, Q = stop --' -NoNewline -ForegroundColor DarkCyan
            $k = Read-PssKey
            if ($k -match '^\d+$') { return [int]$k }
            if ($k -match '^(?i)q' -or $script:PssEof) { return $null }
            $n = 0
        }
    }
}

function Show-PssDetails($Scan, [int]$Id) {
    $it = $Scan.Items | Where-Object Id -eq $Id | Select-Object -First 1
    if (-not $it) { Write-Host "   No item #$Id" -ForegroundColor Yellow; Start-Sleep -Milliseconds 800; return }
    while ($true) {
        Write-PssHeader $Scan
        Write-Host ''
        Write-Host "   #$($it.Id)  " -NoNewline -ForegroundColor DarkGray
        Write-Host $it.Name -NoNewline -ForegroundColor White
        Write-Host "   [$($it.Risk.ToUpper())]" -ForegroundColor $script:PssRiskColor[$it.Risk]
        Write-PssRule
        $f = Get-PssDetailFields $it
        foreach ($k in @($f.Keys)) {
            $c = 'Gray'
            if ($k -eq 'Flags' -or $k -eq 'Risk') { $c = $script:PssRiskColor[$it.Risk] }
            elseif ($k -eq 'Signature') { $c = if ($it.SignStatus -eq 'Valid') { 'Green' } else { 'Yellow' } }
            elseif ($k -eq 'File info' -and -not $it.FileExists) { $c = 'DarkYellow' }
            elseif ($k -in 'Command', 'File') { $c = 'White' }
            if ($k -eq 'Flags') { $f[$k] = ($it.FlagList | ForEach-Object { "! $_" }) -join '   ' }
            Write-PssKV $k $f[$k] $c
        }
        Write-PssRule
        Write-Host '   [O] Open location  [F] Show file  [H] SHA-256  [V] VirusTotal  [S] Search web  [C] Copy  [Enter] Back' -ForegroundColor Cyan
        if ($it.CanDisable -or $it.CanDelete) {
            Write-Host '   ' -NoNewline
            if ($it.CanDisable) { Write-Host ('[D] ' + $(if ($it.Enabled) { 'Disable at startup' } else { 'Enable at startup' }) + '   ') -NoNewline -ForegroundColor Yellow }
            if ($it.CanDelete) { Write-Host '[X] Delete entry   ' -NoNewline -ForegroundColor Red }
            Write-Host 'Backups and Undo: [U] in the main menu' -ForegroundColor DarkGray
        }
        Write-Host '   > ' -NoNewline -ForegroundColor Cyan
        $k = Read-PssKey
        switch -Regex ($k) {
            '^(?i)[dx]$' {
                $action = if ($k -match '^(?i)x$') { 'Delete' } elseif ($it.Enabled) { 'Disable' } else { 'Enable' }
                $allowed = if ($action -eq 'Delete') { $it.CanDelete } else { $it.CanDisable }
                if (-not $allowed) {
                    $why = if ($it.ActionNote) { $it.ActionNote } elseif ($action -eq 'Delete') { "This entry can't be deleted here." } else { "This entry can't be disabled, only deleted." }
                    Write-Host "   $why" -ForegroundColor Yellow; Start-Sleep 2; break
                }
                # Disable/Enable are reversible and happen straight away; only Delete asks first
                $go = $true
                if ($action -eq 'Delete') {
                    Write-Host ''
                    $lines = (Get-PssConfirmText $it $action) -split "`n"
                    Write-Host "   $($lines[0])" -ForegroundColor Red
                    foreach ($l in ($lines | Select-Object -Skip 1)) { Write-Host "   $l" -ForegroundColor Gray }
                    Write-Host ''
                    Write-Host '   Type Y to confirm > ' -NoNewline -ForegroundColor Cyan
                    $go = (Read-PssKey) -match '^(?i)y(es)?$'
                }
                if ($go) {
                    $res = Invoke-PssChange $it $action
                    Write-Host "   $($res.Message)" -ForegroundColor $(if ($res.Ok) { 'Green' } else { 'Red' })
                    if ($res.Ok) { Start-Sleep -Milliseconds 1200 } else { Write-Host '   Press Enter to continue > ' -NoNewline -ForegroundColor Cyan; $null = Read-PssKey }
                }
            }
            '^(?i)o$' { Open-PssLocation $it }
            '^(?i)f$' { Open-PssFolder $it }
            '^(?i)h$' { if (-not (Get-PssHash $it)) { Write-Host "   $($script:PssHashError)" -ForegroundColor Yellow; Start-Sleep 2 } }
            '^(?i)v$' { if (-not (Open-PssVirusTotal $it)) { Write-Host "   $($script:PssHashError)" -ForegroundColor Yellow; Start-Sleep 2 } }
            '^(?i)s$' { Open-PssWebSearch $it }
            '^(?i)c$' { try { Set-Clipboard -Value (Get-PssDetailText $it); Write-Host '   Copied.' -ForegroundColor Green; Start-Sleep -Milliseconds 600 } catch {} }
            '^\d+$' { $n = $Scan.Items | Where-Object Id -eq ([int]$k) | Select-Object -First 1; if ($n) { $it = $n } }
            default { return }
        }
    }
}

function Read-PssKey {
    # Read-Host returns $null when input is piped and runs out; treat that as "quit"
    $v = Read-Host
    if ($null -eq $v) { $script:PssEof = $true; return '' }
    return $v.Trim()
}

function Read-PssPick($Scan, $Result) {
    # after a list: Enter = back, number = details
    if ($Result -is [int]) { Show-PssDetails $Scan $Result; return }
    Write-Host ''
    Write-Host '   Item # for details, or Enter to go back > ' -NoNewline -ForegroundColor Cyan
    $k = Read-PssKey
    if ($k -match '^\d+$') { Show-PssDetails $Scan ([int]$k) }
}

function Select-PssView($Items, [switch]$Browse) {
    # Console view filters: [A] only items that are on (every list), [M] clean Microsoft items (browse/search lists)
    $out = @($Items | Where-Object { $_ })
    if ($Browse -and -not $script:PssShowMicrosoft) { $out = @($out | Where-Object { -not $_.IsMicrosoft -or $_.Risk -ne 'OK' }) }
    if ($script:PssOnlyEnabled) { $out = @($out | Where-Object { $_.Enabled -and $_.State -ne 'Removed' }) }
    return , $out
}

function Write-PssViewNote {
    $bits = @()
    if ($script:PssOnlyEnabled) { $bits += 'only items that are on' }
    if (-not $script:PssShowMicrosoft) { $bits += 'clean Microsoft items hidden in browse/search' }
    if ($bits) { Write-Host ('   View: ' + ($bits -join ', ') + '   ([A] / [M] in the main menu)') -ForegroundColor DarkGray }
}

function Show-PssGroups($Scan, [string]$Property, [string]$Title, [string]$Label) {
    # Category / publisher lists with counts; pick one to list its items
    Write-PssHeader $Scan
    $items = Select-PssView $Scan.Items -Browse
    $groups = @($items | Group-Object -Property $Property | Sort-Object @{ E = { $_.Count }; Descending = $true }, Name)
    Write-PssRule "$Title ($($groups.Count))"
    $nameW = [Math]::Max(24, [Math]::Min(52, (Get-PssWidth) - 46))
    Write-Host ('   {0,-5}{1}{2,7}{3,6}{4,6}{5,9}' -f '#', (Format-PssCell $Label $nameW), 'Items', 'On', 'Off', 'Flagged') -ForegroundColor DarkGray
    for ($i = 0; $i -lt $groups.Count; $i++) {
        $g = $groups[$i]
        $on = @($g.Group | Where-Object { $_.Enabled -and $_.State -ne 'Removed' }).Count
        $fl = @($g.Group | Where-Object { $_.Risk -in 'High', 'Medium' }).Count
        Write-Host ('   [{0,2}] ' -f ($i + 1)) -NoNewline -ForegroundColor Cyan
        Write-Host (Format-PssCell ([string]$g.Name) $nameW) -NoNewline -ForegroundColor White
        Write-Host ('{0,7}{1,6}' -f $g.Count, $on) -NoNewline -ForegroundColor Gray
        Write-Host ('{0,6}' -f ($g.Count - $on)) -NoNewline -ForegroundColor $(if ($g.Count - $on) { 'DarkYellow' } else { 'DarkGray' })
        Write-Host ('{0,9}' -f $fl) -ForegroundColor $(if ($fl) { 'Yellow' } else { 'DarkGray' })
    }
    Write-Host ''
    Write-PssViewNote
    Write-Host "   Number to list those items, or Enter to go back > " -NoNewline -ForegroundColor Cyan
    $k = Read-PssKey
    if ($k -match '^\d+$' -and [int]$k -ge 1 -and [int]$k -le $groups.Count) {
        $g = $groups[[int]$k - 1]
        Write-PssHeader $Scan
        $r = Write-PssTable $g.Group "$($Label): $($g.Name)"
        Read-PssPick $Scan $r
    }
}

function Write-PssBootTests {
    # The timed restarts table; returns the tests (newest first)
    Write-PssRule 'Boot tests (restarts timed by PAX Startup Scanner)'
    $state = Get-PssBootTestState
    if ($state) { Write-Host ("   Ready: '{0}'. Restart the PC and sign in to run it ([C] cancels it)." -f $state.Label) -ForegroundColor Yellow }
    $tests = @(Get-PssBootTests)
    if (-not $tests) {
        Write-Host '   No timed restarts yet. Press T to time the next restart, make your changes, then time another restart and compare.' -ForegroundColor DarkGray
        return , $tests
    }
    Write-Host ('   {0,-5}{1,-18}{2}{3,11}{4,12}{5,10}  {6}' -f '#', 'Restarted', (Format-PssCell 'Name' 22), 'Start-up', 'Sign-in', 'Total', 'Notes') -ForegroundColor DarkGray
    for ($i = 0; $i -lt [Math]::Min($tests.Count, 8); $i++) {
        $t = $tests[$i]
        Write-Host ('   [{0}] ' -f ($i + 1)) -NoNewline -ForegroundColor Cyan
        Write-Host ('{0,-18}' -f $t.When) -NoNewline -ForegroundColor Gray
        Write-Host (Format-PssCell $t.Label 22) -NoNewline -ForegroundColor White
        Write-Host ('{0,11}{1,12}' -f $t.BootText, $t.SignInText) -NoNewline -ForegroundColor Gray
        Write-Host ('{0,10}' -f $t.TotalText) -NoNewline -ForegroundColor White
        Write-Host ('  ' + $t.Notes) -ForegroundColor DarkYellow
    }
    Write-Host '   Start-up = power-on until Windows is idle at the sign-in screen. Sign-in = sign-in until the desktop is idle.' -ForegroundColor DarkGray
    return , $tests
}

function Show-PssBoot($Scan) {
    while ($true) {
        Write-PssHeader $Scan
        $tests = Write-PssBootTests
        Write-PssBootLog $Scan
        Write-Host ''
        Write-Host '   [T] Time the next restart   [V] Compare two tests   [C] Cancel a ready test   [S] Restart now   [Enter] Back' -ForegroundColor Cyan
        Write-Host '   > ' -NoNewline -ForegroundColor Cyan
        $k = Read-PssKey
        switch -Regex ($k) {
            '^(?i)t$' {
                $def = if ($tests) { 'After changes' } else { 'Before changes' }
                Write-Host "   Name for this test [$def] > " -NoNewline -ForegroundColor Cyan
                $lbl = Read-PssKey; if (-not $lbl) { $lbl = $def }
                $r = Start-PssBootTest $lbl
                Write-Host "   $($r.Message)" -ForegroundColor $(if ($r.Ok) { 'Green' } else { 'Red' })
                if ($r.Ok) {
                    Write-Host '   Restart now? Save your work first. Type Y to restart in 15 seconds, or Enter to restart later > ' -NoNewline -ForegroundColor Yellow
                    if ((Read-PssKey) -match '^(?i)y(es)?$') { $rr = Restart-PssNow; Write-Host "   $($rr.Message)" -ForegroundColor $(if ($rr.Ok) { 'Yellow' } else { 'Red' }); Start-Sleep 2 }
                } else { Write-Host '   Press Enter to continue > ' -NoNewline -ForegroundColor Cyan; $null = Read-PssKey }
                break
            }
            '^(?i)c$' { $r = Stop-PssBootTest; Write-Host "   $($r.Message)" -ForegroundColor Green; Start-Sleep -Milliseconds 1200; break }
            '^(?i)v$' {
                if ($tests.Count -lt 2) { Write-Host '   Two timed restarts are needed for a comparison.' -ForegroundColor Yellow; Start-Sleep 2; break }
                Write-Host '   Compare which two tests? e.g. "2 1". Enter compares the latest two > ' -NoNewline -ForegroundColor Cyan
                $nums = @([regex]::Matches((Read-PssKey), '\d+') | ForEach-Object { [int]$_.Value })
                if ($nums.Count -ge 2 -and $nums[0] -ge 1 -and $nums[1] -ge 1 -and $nums[0] -le $tests.Count -and $nums[1] -le $tests.Count -and $nums[0] -ne $nums[1]) {
                    $a = $tests[$nums[0] - 1]; $b = $tests[$nums[1] - 1]
                } else { $a = $tests[1]; $b = $tests[0] }
                if ($a.Boot -gt $b.Boot) { $tmp = $a; $a = $b; $b = $tmp }
                Write-PssHeader $Scan
                Write-PssRule 'Boot test comparison'
                foreach ($l in (Compare-PssBootTests $a $b)) { Write-Host ('   ' + $l.Text) -ForegroundColor $l.Color }
                Write-Host ''
                Write-Host '   Press Enter to go back > ' -NoNewline -ForegroundColor Cyan; $null = Read-PssKey
                break
            }
            '^(?i)s$' {
                Write-Host '   Restart the PC in 15 seconds? Save your work first. Type Y to confirm > ' -NoNewline -ForegroundColor Yellow
                if ((Read-PssKey) -match '^(?i)y(es)?$') { $rr = Restart-PssNow; Write-Host "   $($rr.Message)" -ForegroundColor $(if ($rr.Ok) { 'Yellow' } else { 'Red' }); Start-Sleep 2 }
                break
            }
            '^\d+$' { Show-PssDetails $Scan ([int]$k); break }
            default { return }
        }
    }
}

function Write-PssBootLog($Scan) {
    # What Windows' own Diagnostics-Performance log recorded, plus the heaviest running startup items
    $b = $Scan.Boot
    if (-not $b.Available) { Write-Host ''; Write-Host "   Windows' boot log: $($b.Error)" -ForegroundColor DarkYellow }
    else {
        Write-PssRule "Recent boots (Windows' own log)"
        Write-Host ('   {0,-18}{1,10}{2,12}{3,12}' -f 'When', 'Total', 'To desktop', 'Settling') -ForegroundColor DarkGray
        foreach ($x in @($b.Boots | Select-Object -First 10)) {
            $c = if ($x.BootSec -gt 90) { 'Red' } elseif ($x.BootSec -gt 45) { 'Yellow' } else { 'Green' }
            Write-Host ('   {0,-18}' -f ('{0:yyyy-MM-dd HH:mm}' -f $x.Time)) -NoNewline -ForegroundColor Gray
            Write-Host ('{0,10}' -f ('{0:N1}s' -f $x.BootSec)) -NoNewline -ForegroundColor $c
            Write-Host ('{0,12}{1,12}' -f ('{0:N1}s' -f $x.MainPathSec), ('{0:N1}s' -f $x.PostBootSec)) -ForegroundColor Gray
        }
        if ($b.LastBootTime -and ((Get-Date) - $b.LastBootTime).TotalDays -gt 30) {
            Write-Host ('   The newest boot timing Windows logged is from {0:yyyy-MM-dd}.' -f $b.LastBootTime) -ForegroundColor DarkYellow
        }
        Write-PssRule 'What Windows says slowed boot (worst delay per item)'
        if ($b.Delays) {
            $span = $b.Delays | Measure-Object -Property Time -Minimum -Maximum
            Write-Host ('   Logged between {0:yyyy-MM-dd} and {1:yyyy-MM-dd}' -f $span.Minimum, $span.Maximum) -ForegroundColor DarkGray
        }
        $top = @($b.Delays | Group-Object { "$($_.Type)|$($_.Name)" } | ForEach-Object {
                $g = $_.Group | Sort-Object DegradationMs -Descending | Select-Object -First 1
                [pscustomobject]@{ Name = $(if ($g.FriendlyName) { $g.FriendlyName } else { $g.Name }); File = $g.Name; Type = $g.Type; Max = $g.DegradationMs; Count = $_.Count; Last = ($_.Group | Sort-Object Time -Descending | Select-Object -First 1).Time }
            } | Sort-Object Max -Descending | Select-Object -First 20)
        if (-not $top) { Write-Host '   No slow-boot items recorded.' -ForegroundColor Green }
        else {
            $w = Get-PssWidth
            Write-Host ('   {0,-9}{1}{2,10}{3,7}  {4}' -f 'Type', (Format-PssCell 'Name' 40), 'Worst', 'Times', 'File') -ForegroundColor DarkGray
            foreach ($t in $top) {
                $c = if ($t.Max -ge 3000) { 'Red' } elseif ($t.Max -ge 1000) { 'Yellow' } else { 'Gray' }
                Write-Host ('   {0,-9}' -f $t.Type) -NoNewline -ForegroundColor DarkCyan
                Write-Host (Format-PssCell $t.Name 40) -NoNewline -ForegroundColor White
                Write-Host ('{0,10}' -f ('{0:N1}s' -f ($t.Max / 1000))) -NoNewline -ForegroundColor $c
                Write-Host ('{0,7}  ' -f $t.Count) -NoNewline -ForegroundColor Gray
                Write-Host (Format-PssCell $t.File ([Math]::Max(10, $w - 72))) -ForegroundColor DarkGray
            }
        }
    }
    $heavy = @($Scan.Items | Where-Object { $_.Running -and $_.ProcCount } | Sort-Object MemoryMB -Descending | Select-Object -First 10)
    Write-PssRule 'Startup items using the most memory right now'
    foreach ($it in $heavy) {
        $c = if ($it.MemoryMB -ge 400) { 'Red' } elseif ($it.MemoryMB -ge 150) { 'Yellow' } else { 'Gray' }
        Write-Host ('   #{0,-5}' -f $it.Id) -NoNewline -ForegroundColor DarkGray
        Write-Host (Format-PssCell $it.Name 44) -NoNewline -ForegroundColor $(if ($it.IsMicrosoft) { 'DarkGray' } else { 'White' })
        Write-Host ('{0,8} MB' -f $it.MemoryMB) -NoNewline -ForegroundColor $c
        Write-Host ('{0,9}s CPU  {1} proc' -f $it.CpuSec, $it.ProcCount) -ForegroundColor DarkGray
    }
}

function Invoke-PssExportPrompt($Scan) {
    if ($script:PssReadOnly) { Write-Host '   Read-only mode: reports are not saved. Run without -ReadOnly to export.' -ForegroundColor Yellow; Start-Sleep 2; return }
    $desk = [Environment]::GetFolderPath('Desktop')
    $def = Join-Path $desk ('PAX-Startup-{0}-{1:yyyyMMdd-HHmm}.html' -f $Scan.Computer, $Scan.ScannedAt)
    Write-Host ''
    Write-Host "   Save report as (.html .csv .json)" -ForegroundColor Gray
    Write-Host "   [$def]" -ForegroundColor DarkGray
    Write-Host '   > ' -NoNewline -ForegroundColor Cyan
    $p = Read-PssKey
    if ($script:PssEof) { return }
    if (-not $p) { $p = $def }
    if ($p -notmatch '\.(html?|csv|json)$') { $p += '.html' }
    try {
        Export-PssReport $Scan $p
        Write-Host "   Saved: $p" -ForegroundColor Green
        if ($p -match '\.html?$') { Write-Host '   Open it now? [Y/n] ' -NoNewline -ForegroundColor Cyan; if ((Read-PssKey) -notmatch '^(?i)n' -and -not $script:PssEof) { Start-Process $p } }
        else { Start-Sleep 1 }
    } catch { Write-Host "   Could not save: $($_.Exception.Message)" -ForegroundColor Red; Start-Sleep 2 }
}

function Invoke-PssConsoleScan {
    $script:PssConsoleProgress = $true
    Write-Host ''
    $scan = Invoke-PssScan
    $script:PssConsoleProgress = $false
    Write-Host ("`r" + (' ' * 92) + "`r") -NoNewline
    return $scan
}

function Confirm-PssRestoreText($Snap) {
    # Summary + warnings shown before a full restore (console and GUI)
    $when = ''; try { $when = ([datetime]::Parse([string]$Snap.Time)).ToString('yyyy-MM-dd HH:mm') } catch {}
    $t = "Restore $(@($Snap.Items).Count) startup entries from the backup of $($Snap.Computer) taken $when by $($Snap.RunBy)?`n`n"
    $t += "Entries that were deleted come back, and disabled or enabled entries go back to how they were then. Entries added since the backup are not touched.`n"
    if ($Snap.Computer -ne $env:COMPUTERNAME) { $t += "`nWARNING: this backup is from a different PC ($($Snap.Computer)), not $($env:COMPUTERNAME).`n" }
    return $t
}

function Show-PssBackupMenu($Scan) {
    # Full backup of the startup settings: save to a file or the clipboard (handy over remote sessions), and restore.
    # Returns $true when something was restored, so the caller can rescan.
    while ($true) {
        Write-PssHeader $Scan
        Write-PssRule 'Full backup of startup settings'
        Write-Host '   Takes a copy of every startup entry the scanner can change (Run keys, startup folders, tasks,' -ForegroundColor Gray
        Write-Host '   services, Store apps and the rest) so you can put them all back later. Each single change is also' -ForegroundColor Gray
        Write-Host '   backed up automatically ([U] Undo); this is the "everything as it is now" copy before you start.' -ForegroundColor Gray
        Write-Host '   Over a remote session, copy it to the clipboard and paste it into a text file on your own PC.' -ForegroundColor DarkGray
        Write-Host ''
        Write-Host '   [1] Save a backup to a file   [2] Copy a backup to the clipboard' -ForegroundColor Cyan
        Write-Host '   [3] Restore from a file       [4] Restore from the clipboard       [Enter] Back' -ForegroundColor Cyan
        Write-Host '   > ' -NoNewline -ForegroundColor Cyan
        $k = Read-PssKey
        switch -Regex ($k) {
            '^[12]$' {
                if ($k -eq '1' -and $script:PssReadOnly) { Write-Host '   Read-only mode: no files are written. Use [2] to copy it to the clipboard instead.' -ForegroundColor Yellow; Start-Sleep 2; break }
                Write-Host '   Collecting the current startup settings...' -ForegroundColor DarkGray
                $json = New-PssSnapshot $Scan
                $n = ($json | ConvertFrom-Json).Count
                if ($k -eq '1') {
                    $def = Join-Path ([Environment]::GetFolderPath('Desktop')) ('PAX-Startup-Backup-{0}-{1:yyyyMMdd-HHmm}.json' -f $env:COMPUTERNAME, (Get-Date))
                    Write-Host "   Save as [$def] > " -NoNewline -ForegroundColor Cyan
                    $p = Read-PssKey; if (-not $p) { $p = $def }
                    try { [IO.File]::WriteAllText($p, $json, (New-Object Text.UTF8Encoding $false)); Write-Host ("   Saved {0} entries ({1:N0} KB) to {2}" -f $n, ($json.Length / 1KB), $p) -ForegroundColor Green }
                    catch { Write-Host "   Could not save: $($_.Exception.Message)" -ForegroundColor Red }
                } else {
                    try { Set-Clipboard -Value $json; Write-Host ("   Copied {0} entries ({1:N0} KB of text) to the clipboard. Paste it into a text file and save it as .json." -f $n, ($json.Length / 1KB)) -ForegroundColor Green }
                    catch { Write-Host "   Could not use the clipboard: $($_.Exception.Message)" -ForegroundColor Red }
                }
                Write-Host '   Press Enter to continue > ' -NoNewline -ForegroundColor Cyan; $null = Read-PssKey
                break
            }
            '^[34]$' {
                try {
                    if ($k -eq '3') {
                        Write-Host '   Path of the backup file > ' -NoNewline -ForegroundColor Cyan
                        $p = (Read-PssKey).Trim('"')
                        if (-not $p) { break }
                        $snap = Read-PssSnapshot ([IO.File]::ReadAllText($p))
                    } else { $snap = Read-PssSnapshot ((Get-Clipboard -Raw) | Out-String) }
                } catch { Write-Host "   $($_.Exception.Message)" -ForegroundColor Red; Start-Sleep 2; break }
                Write-Host ''
                foreach ($l in ((Confirm-PssRestoreText $snap) -split "`n")) { Write-Host "   $l" -ForegroundColor $(if ($l -like 'WARNING*') { 'Red' } else { 'Yellow' }) }
                Write-Host '   Type Y to restore > ' -NoNewline -ForegroundColor Cyan
                if ((Read-PssKey) -notmatch '^(?i)y(es)?$') { break }
                $r = Restore-PssSnapshot $snap
                Write-Host "   $($r.Message)" -ForegroundColor $(if ($r.Ok) { 'Green' } else { 'Yellow' })
                foreach ($f in $r.Failed) { Write-Host "     $f" -ForegroundColor Red }
                Write-Host '   Press Enter to rescan > ' -NoNewline -ForegroundColor Cyan; $null = Read-PssKey
                if ($r.Message -notlike 'Read-only*') { return $true }
                break
            }
            default { return $false }
        }
    }
}

function Show-PssUndo($Scan) {
    # Lists saved changes; returns $true when something was restored (so the caller can rescan)
    $restored = $false
    while ($true) {
        Write-PssHeader $Scan
        $recs = @(Get-PssUndoRecords)
        Write-PssRule "Saved changes ($($recs.Count))"
        if (-not $recs) {
            Write-Host '   No saved changes on this PC.' -ForegroundColor DarkGray
            Write-Host ''
            Write-Host '   Press Enter to go back > ' -NoNewline -ForegroundColor Cyan; $null = Read-PssKey
            return $restored
        }
        Write-Host ('   {0,-5}{1,-18}{2,-9}{3,-16}{4}' -f '#', 'When', 'Change', 'Category', 'Name') -ForegroundColor DarkGray
        for ($i = 0; $i -lt $recs.Count; $i++) {
            $r = $recs[$i]
            Write-Host ('   [{0,2}] ' -f ($i + 1)) -NoNewline -ForegroundColor Cyan
            Write-Host ('{0,-18}' -f $r.When) -NoNewline -ForegroundColor Gray
            Write-Host ('{0,-9}' -f $r.Action) -NoNewline -ForegroundColor $(if ($r.Action -eq 'Delete') { 'Red' } else { 'Yellow' })
            Write-Host (Format-PssCell $r.Category 15) -NoNewline -ForegroundColor DarkCyan
            Write-Host (' ' + $r.Name) -ForegroundColor White
        }
        Write-Host ''
        Write-Host "   Backups are kept in $(Get-PssBackupPath)" -ForegroundColor DarkGray
        Write-Host '   Number to undo, or Enter to go back > ' -NoNewline -ForegroundColor Cyan
        $k = Read-PssKey
        if ($k -notmatch '^\d+$' -or [int]$k -lt 1 -or [int]$k -gt $recs.Count) { return $restored }
        $r = $recs[[int]$k - 1]
        Write-Host "   Undo the $($r.Action.ToLower()) of '$($r.Name)'? Type Y to confirm > " -NoNewline -ForegroundColor Yellow
        if ((Read-PssKey) -match '^(?i)y(es)?$') {
            $res = Invoke-PssUndo $r
            Write-Host "   $($res.Message)" -ForegroundColor $(if ($res.Ok) { 'Green' } else { 'Red' })
            if ($res.Ok) { $restored = $true; Start-Sleep -Milliseconds 1500 } else { Write-Host '   Press Enter to continue > ' -NoNewline -ForegroundColor Cyan; $null = Read-PssKey }
        }
    }
}

function Start-PssConsole($Scan) {
    while ($true) {
        Write-PssHeader $Scan
        Write-PssDashboard $Scan
        $flagged = Select-PssView ($Scan.Items | Where-Object { $_.Risk -in 'High', 'Medium' })
        $third = Select-PssView ($Scan.Items | Where-Object { -not $_.IsMicrosoft })
        $all = Select-PssView $Scan.Items
        $browse = Select-PssView $Scan.Items -Browse
        $nCat = @($browse | Group-Object Category).Count; $nPub = @($browse | Group-Object Vendor).Count
        $tests = @(Get-PssBootTests).Count
        Write-PssRule 'Menu'
        $menu = @(
            @('1', "Review flagged items ($($flagged.Count))"), @('5', "Browse by publisher ($nPub)"),
            @('2', "Third-party startup items ($($third.Count))"), @('6', 'Search'),
            @('3', "All items incl. Microsoft ($($all.Count))"), @('7', "Boot times and boot tests ($tests)"),
            @('4', "Browse by category ($nCat)"), @('E', 'Export report (HTML/CSV/JSON)'),
            @('A', $(if ($script:PssOnlyEnabled) { 'Show items that are on AND off' } else { 'Show only items that are on' })), @('G', 'Open GUI view'),
            @('M', $(if ($script:PssShowMicrosoft) { 'Browse/search: hide Microsoft' } else { 'Browse/search: show Microsoft' })), @('R', 'Rescan'),
            @('B', 'Back up / restore all startup settings'), @('U', "Undo a change ($(@(Get-PssUndoRecords).Count) saved)"),
            @('Q', 'Quit'), @('', '')
        )
        for ($i = 0; $i -lt $menu.Count; $i += 2) {
            foreach ($m in $menu[$i], $menu[$i + 1]) {
                if (-not $m[0]) { continue }
                Write-Host ('   [' ) -NoNewline -ForegroundColor DarkGray
                Write-Host $m[0] -NoNewline -ForegroundColor Cyan
                Write-Host ('] ' + $m[1].PadRight(36)) -NoNewline -ForegroundColor Gray
            }
            Write-Host ''
        }
        Write-PssViewNote
        Write-Host '   Type an item number at any prompt to see its details, then D to disable or X to delete it' -ForegroundColor DarkGray
        Write-Host ''
        Write-Host '   > ' -NoNewline -ForegroundColor Cyan
        $k = Read-PssKey
        if ($script:PssEof) { Write-Host ''; return }
        $on = if ($script:PssOnlyEnabled) { ' - only items that are on' } else { '' }
        switch -Regex ($k) {
            '^1$' { Write-PssHeader $Scan; $r = Write-PssTable $flagged "Flagged items (high and medium risk)$on"; Read-PssPick $Scan $r ; break }
            '^2$' { Write-PssHeader $Scan; $r = Write-PssTable $third "Third-party startup items$on"; Read-PssPick $Scan $r ; break }
            '^3$' { Write-PssHeader $Scan; $r = Write-PssTable $all "All startup items$on"; Read-PssPick $Scan $r ; break }
            '^4$' { Show-PssGroups $Scan 'Category' 'Startup items by category' 'Category' ; break }
            '^5$' { Show-PssGroups $Scan 'Vendor' 'Startup items by publisher' 'Publisher' ; break }
            '^6$' {
                Write-Host '   Search name, file, publisher or command > ' -NoNewline -ForegroundColor Cyan
                $q = Read-PssKey
                if ($q) {
                    $hits = Select-PssView ($Scan.Items | Where-Object { "$($_.Name) $($_.ImagePath) $($_.Publisher) $($_.Command) $($_.Location) $($_.Description)" -like "*$q*" }) -Browse
                    Write-PssHeader $Scan; $r = Write-PssTable $hits "Search: $q$on"; Read-PssPick $Scan $r
                }
            ; break }
            '^7$' { Show-PssBoot $Scan ; break }
            '^(?i)a$' { $script:PssOnlyEnabled = -not $script:PssOnlyEnabled ; break }
            '^(?i)e$' { Invoke-PssExportPrompt $Scan ; break }
            '^(?i)g$' { $Scan = Show-PssGui $Scan ; break }
            '^(?i)m$' { $script:PssShowMicrosoft = -not $script:PssShowMicrosoft ; break }
            '^(?i)r$' { Write-PssHeader $null; $Scan = Invoke-PssConsoleScan ; break }
            '^(?i)u$' { if (Show-PssUndo $Scan) { Write-PssHeader $null; $Scan = Invoke-PssConsoleScan }; break }
            '^(?i)b$' { if (Show-PssBackupMenu $Scan) { Write-PssHeader $null; $Scan = Invoke-PssConsoleScan }; break }
            '^(?i)(q|quit|exit)$' { Write-Host ''; return }
            '^\d+$' { Show-PssDetails $Scan ([int]$k) }
        }
    }
}

# ======================================================================================
#  GUI (WPF)
# ======================================================================================

function Show-PssGui($Scan, [string]$Snapshot, [int]$SnapshotTab = 0) {
    # -Snapshot <png>: render the window off-screen to an image instead of showing it (self-test, README screenshots)
    if ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
        Write-Host '   The GUI needs an STA thread. Opening it in Windows PowerShell...' -ForegroundColor Yellow
        if ($script:PssSelfPath) { $cmd = "& '$($script:PssSelfPath)' -Gui" } else { $cmd = "& ([scriptblock]::Create((irm '$($script:PssUrl)'))) -Gui" }
        Start-Process powershell.exe -ArgumentList '-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-Command', $cmd
        return $Scan
    }
    try { Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase -ErrorAction Stop } catch { Write-Host '   WPF is not available on this system.' -ForegroundColor Red; Start-Sleep 2; return $Scan }

    [xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="PAX Startup Scanner" Width="1280" Height="800" MinWidth="900" MinHeight="560" WindowStartupLocation="CenterScreen"
        Background="#0F1115" Foreground="#E6E8EE" FontFamily="Segoe UI" FontSize="13" UseLayoutRounding="True">
  <Window.Resources>
    <SolidColorBrush x:Key="Card" Color="#171A21"/>
    <SolidColorBrush x:Key="Line" Color="#262B36"/>
    <SolidColorBrush x:Key="Mut" Color="#8B93A5"/>
    <Style TargetType="Button">
      <Setter Property="Foreground" Value="#E6E8EE"/><Setter Property="Background" Value="#222734"/><Setter Property="BorderBrush" Value="#30364A"/>
      <Setter Property="Padding" Value="12,5"/><Setter Property="Margin" Value="0,0,6,0"/><Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="Button">
        <Border x:Name="b" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="5" Padding="{TemplateBinding Padding}">
          <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/></Border>
        <ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#2E3547"/></Trigger>
        <Trigger Property="IsEnabled" Value="False"><Setter TargetName="b" Property="Opacity" Value="0.45"/></Trigger></ControlTemplate.Triggers>
      </ControlTemplate></Setter.Value></Setter>
    </Style>
    <Style x:Key="Danger" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="#3A1D22"/><Setter Property="BorderBrush" Value="#7A2E38"/><Setter Property="Foreground" Value="#FFC9CE"/>
    </Style>
    <Style TargetType="CheckBox"><Setter Property="Foreground" Value="#C9CEDA"/><Setter Property="VerticalAlignment" Value="Center"/><Setter Property="Margin" Value="0,0,14,0"/></Style>
    <Style TargetType="ListBox">
      <Setter Property="Background" Value="Transparent"/><Setter Property="BorderThickness" Value="0"/><Setter Property="Foreground" Value="#C9CEDA"/>
      <Setter Property="ScrollViewer.HorizontalScrollBarVisibility" Value="Disabled"/>
    </Style>
    <Style TargetType="ListBoxItem">
      <Setter Property="Padding" Value="7,2"/><Setter Property="Cursor" Value="Hand"/><Setter Property="HorizontalContentAlignment" Value="Stretch"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="ListBoxItem">
        <Border x:Name="b" Background="Transparent" CornerRadius="4" Padding="{TemplateBinding Padding}"><ContentPresenter/></Border>
        <ControlTemplate.Triggers>
          <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#20252F"/></Trigger>
          <Trigger Property="IsSelected" Value="True"><Setter TargetName="b" Property="Background" Value="#1E3A5F"/><Setter Property="Foreground" Value="#FFFFFF"/></Trigger>
        </ControlTemplate.Triggers>
      </ControlTemplate></Setter.Value></Setter>
    </Style>
    <DataTemplate x:Key="FacetItem">
      <Grid>
        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
        <TextBlock Text="{Binding Label}" TextTrimming="CharacterEllipsis" ToolTip="{Binding Label}"/>
        <TextBlock Grid.Column="1" Text="{Binding Count}" Foreground="#8B93A5" Margin="8,0,0,0"/>
      </Grid>
    </DataTemplate>
    <Style TargetType="ContextMenu"><Setter Property="Background" Value="#1B1F27"/><Setter Property="Foreground" Value="#E6E8EE"/><Setter Property="BorderBrush" Value="#30364A"/></Style>
    <Style TargetType="MenuItem"><Setter Property="Foreground" Value="#E6E8EE"/><Setter Property="Padding" Value="6,4"/></Style>
    <Style TargetType="TextBox"><Setter Property="Background" Value="#171A21"/><Setter Property="Foreground" Value="#E6E8EE"/><Setter Property="BorderBrush" Value="#30364A"/><Setter Property="CaretBrush" Value="#E6E8EE"/><Setter Property="Padding" Value="6,4"/></Style>
    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="#171A21"/><Setter Property="Foreground" Value="#8B93A5"/><Setter Property="Padding" Value="8,6"/>
      <Setter Property="BorderBrush" Value="#262B36"/><Setter Property="BorderThickness" Value="0,0,1,1"/><Setter Property="FontSize" Value="12"/>
    </Style>
    <Style TargetType="DataGridCell">
      <Setter Property="BorderThickness" Value="0"/><Setter Property="Padding" Value="6,0"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="DataGridCell">
        <Border Padding="{TemplateBinding Padding}" Background="Transparent"><ContentPresenter VerticalAlignment="Center"/></Border>
      </ControlTemplate></Setter.Value></Setter>
    </Style>
    <Style TargetType="DataGrid">
      <Setter Property="Background" Value="#171A21"/><Setter Property="Foreground" Value="#E6E8EE"/><Setter Property="BorderBrush" Value="#262B36"/>
      <Setter Property="RowBackground" Value="#171A21"/><Setter Property="AlternatingRowBackground" Value="#1A1E26"/><Setter Property="GridLinesVisibility" Value="None"/>
      <Setter Property="HeadersVisibility" Value="Column"/><Setter Property="AutoGenerateColumns" Value="False"/><Setter Property="IsReadOnly" Value="True"/>
      <Setter Property="SelectionMode" Value="Single"/><Setter Property="RowHeight" Value="26"/><Setter Property="CanUserResizeRows" Value="False"/>
      <Setter Property="EnableRowVirtualization" Value="True"/><Setter Property="VirtualizingPanel.IsVirtualizing" Value="True"/><Setter Property="VirtualizingPanel.VirtualizationMode" Value="Recycling"/>
    </Style>
    <Style TargetType="DataGridRow">
      <Style.Triggers>
        <DataTrigger Binding="{Binding IsMicrosoft}" Value="True"><Setter Property="Foreground" Value="#7D8597"/></DataTrigger>
        <DataTrigger Binding="{Binding Risk}" Value="High"><Setter Property="Foreground" Value="#FF7B7B"/></DataTrigger>
        <DataTrigger Binding="{Binding Risk}" Value="Medium"><Setter Property="Foreground" Value="#FBBF24"/></DataTrigger>
        <DataTrigger Binding="{Binding State}" Value="Removed"><Setter Property="Foreground" Value="#59606F"/><Setter Property="FontStyle" Value="Italic"/></DataTrigger>
        <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="#1E3A5F"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style TargetType="TabItem">
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="TabItem">
        <Border x:Name="b" Padding="14,7" Margin="0,0,4,0" CornerRadius="5,5,0,0" Background="Transparent">
          <ContentPresenter ContentSource="Header"/></Border>
        <ControlTemplate.Triggers><Trigger Property="IsSelected" Value="True"><Setter TargetName="b" Property="Background" Value="#171A21"/></Trigger></ControlTemplate.Triggers>
      </ControlTemplate></Setter.Value></Setter>
      <Setter Property="Foreground" Value="#E6E8EE"/>
    </Style>
    <ControlTemplate x:Key="ThumbT" TargetType="Thumb"><Border Background="#3A4152" CornerRadius="4" Margin="2"/></ControlTemplate>
    <Style TargetType="ScrollBar">
      <Setter Property="Background" Value="#14171D"/><Setter Property="Width" Value="12"/><Setter Property="MinWidth" Value="12"/>
      <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="ScrollBar">
        <Border Background="{TemplateBinding Background}">
          <Track x:Name="PART_Track" Orientation="Vertical" IsDirectionReversed="True">
            <Track.DecreaseRepeatButton><RepeatButton Command="ScrollBar.PageUpCommand" Opacity="0" Focusable="False"/></Track.DecreaseRepeatButton>
            <Track.IncreaseRepeatButton><RepeatButton Command="ScrollBar.PageDownCommand" Opacity="0" Focusable="False"/></Track.IncreaseRepeatButton>
            <Track.Thumb><Thumb Template="{StaticResource ThumbT}"/></Track.Thumb>
          </Track>
        </Border>
      </ControlTemplate></Setter.Value></Setter>
      <Style.Triggers>
        <Trigger Property="Orientation" Value="Horizontal">
          <Setter Property="Width" Value="Auto"/><Setter Property="MinWidth" Value="0"/><Setter Property="Height" Value="12"/><Setter Property="MinHeight" Value="12"/>
          <Setter Property="Template"><Setter.Value><ControlTemplate TargetType="ScrollBar">
            <Border Background="{TemplateBinding Background}">
              <Track x:Name="PART_Track" Orientation="Horizontal">
                <Track.DecreaseRepeatButton><RepeatButton Command="ScrollBar.PageLeftCommand" Opacity="0" Focusable="False"/></Track.DecreaseRepeatButton>
                <Track.IncreaseRepeatButton><RepeatButton Command="ScrollBar.PageRightCommand" Opacity="0" Focusable="False"/></Track.IncreaseRepeatButton>
                <Track.Thumb><Thumb Template="{StaticResource ThumbT}"/></Track.Thumb>
              </Track>
            </Border>
          </ControlTemplate></Setter.Value></Setter>
        </Trigger>
      </Style.Triggers>
    </Style>
  </Window.Resources>
  <Grid Margin="16,12,16,8">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <DockPanel Grid.Row="0">
      <StackPanel DockPanel.Dock="Left">
        <TextBlock FontSize="20" FontWeight="SemiBold">PAX Startup Scanner</TextBlock>
        <TextBlock x:Name="SubTitle" Foreground="{StaticResource Mut}" Margin="0,2,0,0"/>
      </StackPanel>
      <StackPanel x:Name="Tiles" Orientation="Horizontal" HorizontalAlignment="Right" DockPanel.Dock="Right"/>
    </DockPanel>
    <DockPanel Grid.Row="1" Margin="0,12,0,8" LastChildFill="False">
      <Grid DockPanel.Dock="Left" Width="280" Margin="0,0,10,0">
        <TextBox x:Name="Search" ToolTip="Filter by name, file, publisher, command"/>
        <TextBlock x:Name="SearchHint" Text="Search name, file, publisher, command..." Foreground="#6B7385" Margin="9,0,0,0" VerticalAlignment="Center" IsHitTestVisible="False"/>
      </Grid>
      <CheckBox x:Name="HideMs" IsChecked="True" DockPanel.Dock="Left">Hide clean Microsoft items</CheckBox>
      <Button x:Name="BtnClear" DockPanel.Dock="Left" ToolTip="Show everything again (keeps the Microsoft switch)">Clear filters</Button>
      <Button x:Name="BtnExport" DockPanel.Dock="Right" Margin="0">Export report</Button>
      <Button x:Name="BtnRescan" DockPanel.Dock="Right">Rescan</Button>
      <Button x:Name="BtnBackup" DockPanel.Dock="Right" ToolTip="Save or restore a full copy of the startup settings">Backup</Button>
    </DockPanel>
    <TextBlock x:Name="Banner" Grid.Row="2" Foreground="#FBBF24" Margin="0,0,0,6" TextWrapping="Wrap" Visibility="Collapsed"/>
    <TabControl x:Name="Tabs" Grid.Row="3" Background="Transparent" BorderThickness="0" Padding="0">
      <TabItem Header="Startup items">
        <Grid>
        <Grid.ColumnDefinitions><ColumnDefinition Width="232"/><ColumnDefinition Width="10"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
        <Border Grid.Column="0" Background="{StaticResource Card}" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="6">
          <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="6,2,6,8">
            <StackPanel x:Name="Facets"/>
          </ScrollViewer>
        </Border>
        <Grid Grid.Column="2">
          <Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="5"/><RowDefinition Height="230"/></Grid.RowDefinitions>
          <DataGrid x:Name="Grid">
            <DataGrid.Columns>
              <DataGridTextColumn Header="#" Binding="{Binding Id}" Width="44"/>
              <DataGridTextColumn Header="Risk" Binding="{Binding Risk}" Width="64" SortMemberPath="RiskScore"/>
              <DataGridTextColumn Header="Category" Binding="{Binding Category}" Width="105"/>
              <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="210"/>
              <DataGridTextColumn Header="On" Binding="{Binding EnabledText}" Width="56"/>
              <DataGridTextColumn Header="Publisher" Binding="{Binding Publisher}" Width="150"/>
              <DataGridTextColumn Header="Signed" Binding="{Binding SignText}" Width="74"/>
              <DataGridTextColumn Header="File" Binding="{Binding ImagePath}" Width="*" MinWidth="200"/>
              <DataGridTextColumn Header="Boot delay" Binding="{Binding BootDelayText}" Width="76" SortMemberPath="BootDelayMs"/>
              <DataGridTextColumn Header="Memory" Binding="{Binding RunText}" Width="70" SortMemberPath="MemoryMB"/>
            </DataGrid.Columns>
          </DataGrid>
          <GridSplitter Grid.Row="1" HorizontalAlignment="Stretch" Background="Transparent"/>
          <Border Grid.Row="2" Background="{StaticResource Card}" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="6" Padding="10">
            <DockPanel>
              <DockPanel DockPanel.Dock="Bottom" Margin="0,8,0,0" LastChildFill="False">
                <StackPanel DockPanel.Dock="Left" Orientation="Horizontal">
                  <Button x:Name="BtnLoc">Open location</Button><Button x:Name="BtnFile">Show file</Button>
                  <Button x:Name="BtnVt">VirusTotal</Button><Button x:Name="BtnWeb">Search web</Button><Button x:Name="BtnCopy">Copy details</Button>
                </StackPanel>
                <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
                  <Button x:Name="BtnToggle" ToolTipService.ShowOnDisabled="True" IsEnabled="False">Disable</Button>
                  <Button x:Name="BtnDelete" Style="{StaticResource Danger}" Margin="0" ToolTipService.ShowOnDisabled="True" IsEnabled="False">Delete</Button>
                </StackPanel>
              </DockPanel>
              <TextBox x:Name="Detail" IsReadOnly="True" BorderThickness="0" Background="Transparent" FontFamily="Consolas" FontSize="12" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"/>
            </DockPanel>
          </Border>
        </Grid>
        </Grid>
      </TabItem>
      <TabItem x:Name="BootTestTab" Header="Boot tests">
        <Grid Margin="0,8,0,0">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="190"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <TextBlock Grid.Row="0" TextWrapping="Wrap" Foreground="{StaticResource Mut}" Margin="2,0,0,10" Text="Time a restart before you change anything, make your changes, then time another restart and compare. Start-up is power-on until Windows is idle at the sign-in screen; Sign-in is sign-in until the desktop is idle (time spent typing your password is not counted). Each test runs once and removes itself."/>
          <DockPanel Grid.Row="1" LastChildFill="False" Margin="0,0,0,8">
            <TextBlock DockPanel.Dock="Left" Text="Test name" VerticalAlignment="Center" Margin="2,0,8,0" Foreground="{StaticResource Mut}"/>
            <TextBox x:Name="BtLabel" DockPanel.Dock="Left" Width="190" Margin="0,0,8,0"/>
            <Button x:Name="BtnBtArm" DockPanel.Dock="Left">Time the next restart</Button>
            <Button x:Name="BtnBtCancel" DockPanel.Dock="Left">Cancel test</Button>
            <Button x:Name="BtnBtRestart" DockPanel.Dock="Left">Restart now</Button>
            <TextBlock x:Name="BtState" DockPanel.Dock="Left" VerticalAlignment="Center" Margin="6,0,0,0" Foreground="#FBBF24"/>
            <Button x:Name="BtnBtRefresh" DockPanel.Dock="Right" Margin="0">Refresh</Button>
          </DockPanel>
          <DataGrid x:Name="BtGrid" Grid.Row="2" SelectionMode="Extended">
            <DataGrid.Columns>
              <DataGridTextColumn Header="Restarted" Binding="{Binding When}" Width="130"/>
              <DataGridTextColumn Header="Name" Binding="{Binding Label}" Width="*" MinWidth="200"/>
              <DataGridTextColumn Header="Start-up" Binding="{Binding BootText}" Width="90" SortMemberPath="BootToIdleSec"/>
              <DataGridTextColumn Header="Sign-in" Binding="{Binding SignInText}" Width="90" SortMemberPath="SignInToIdleSec"/>
              <DataGridTextColumn Header="Total" Binding="{Binding TotalText}" Width="90" SortMemberPath="TotalSec"/>
              <DataGridTextColumn Header="Notes" Binding="{Binding Notes}" Width="300"/>
            </DataGrid.Columns>
          </DataGrid>
          <DockPanel Grid.Row="3" Margin="0,8,0,8" LastChildFill="False">
            <Button x:Name="BtnBtCompare" DockPanel.Dock="Left">Compare</Button>
            <TextBlock DockPanel.Dock="Left" VerticalAlignment="Center" Foreground="{StaticResource Mut}" Text="Select two tests (Ctrl+click) to compare them, or one to compare it with the test before it."/>
          </DockPanel>
          <Border Grid.Row="4" Background="{StaticResource Card}" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="6" Padding="10">
            <TextBox x:Name="BtCompare" IsReadOnly="True" BorderThickness="0" Background="Transparent" FontFamily="Consolas" FontSize="12" TextWrapping="NoWrap" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"/>
          </Border>
        </Grid>
      </TabItem>
      <TabItem Header="Boot performance">
        <Grid>
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="200"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <TextBlock Text="Recent boots" Foreground="{StaticResource Mut}" Margin="2,8,0,4"/>
          <DataGrid x:Name="BootGrid" Grid.Row="1">
            <DataGrid.Columns>
              <DataGridTextColumn Header="When" Binding="{Binding Time, StringFormat=yyyy-MM-dd HH:mm}" Width="150"/>
              <DataGridTextColumn Header="Total (s)" Binding="{Binding BootSec}" Width="90"/>
              <DataGridTextColumn Header="To desktop (s)" Binding="{Binding MainPathSec}" Width="110"/>
              <DataGridTextColumn Header="Settling (s)" Binding="{Binding PostBootSec}" Width="100"/>
            </DataGrid.Columns>
          </DataGrid>
          <TextBlock Grid.Row="2" Text="Items Windows recorded as slowing boot" Foreground="{StaticResource Mut}" Margin="2,12,0,4"/>
          <DataGrid x:Name="DelayGrid" Grid.Row="3">
            <DataGrid.Columns>
              <DataGridTextColumn Header="When" Binding="{Binding Time, StringFormat=yyyy-MM-dd HH:mm}" Width="140"/>
              <DataGridTextColumn Header="Type" Binding="{Binding Type}" Width="80"/>
              <DataGridTextColumn Header="Name" Binding="{Binding FriendlyName}" Width="2*"/>
              <DataGridTextColumn Header="File / service" Binding="{Binding Name}" Width="1.5*"/>
              <DataGridTextColumn Header="Delay (ms)" Binding="{Binding DegradationMs}" Width="90"/>
              <DataGridTextColumn Header="Total (ms)" Binding="{Binding TotalMs}" Width="90"/>
            </DataGrid.Columns>
          </DataGrid>
        </Grid>
      </TabItem>
      <TabItem x:Name="UndoTab" Header="Undo changes">
        <DockPanel Margin="0,8,0,0">
          <TextBlock x:Name="UndoNote" DockPanel.Dock="Top" Foreground="{StaticResource Mut}" Margin="2,0,0,8" TextWrapping="Wrap"/>
          <DockPanel DockPanel.Dock="Bottom" Margin="0,8,0,0" LastChildFill="False">
            <Button x:Name="BtnUndoSel" DockPanel.Dock="Left" IsEnabled="False">Undo selected change</Button>
            <Button x:Name="BtnUndoFolder" DockPanel.Dock="Left">Open backup folder</Button>
            <Button x:Name="BtnUndoRefresh" DockPanel.Dock="Left">Refresh</Button>
          </DockPanel>
          <DataGrid x:Name="UndoGrid">
            <DataGrid.Columns>
              <DataGridTextColumn Header="When" Binding="{Binding When}" Width="140"/>
              <DataGridTextColumn Header="Change" Binding="{Binding Action}" Width="80"/>
              <DataGridTextColumn Header="Category" Binding="{Binding Category}" Width="130"/>
              <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="*" MinWidth="380"/>
              <DataGridTextColumn Header="By" Binding="{Binding RunBy}" Width="200"/>
            </DataGrid.Columns>
          </DataGrid>
        </DockPanel>
      </TabItem>
    </TabControl>
    <TextBlock x:Name="Status" Grid.Row="4" Foreground="{StaticResource Mut}" Margin="2,6,0,0"/>
  </Grid>
</Window>
'@
    $win = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xaml))
    $ui = @{}
    foreach ($n in 'SubTitle', 'Tiles', 'Search', 'SearchHint', 'HideMs', 'BtnClear', 'Facets', 'BootTestTab', 'BtLabel', 'BtnBtArm', 'BtnBtCancel', 'BtnBtRestart', 'BtState', 'BtnBtRefresh', 'BtGrid', 'BtnBtCompare', 'BtCompare', 'BtnExport', 'BtnBackup', 'BtnRescan', 'Banner', 'Grid', 'Detail', 'BtnLoc', 'BtnFile', 'BtnVt', 'BtnWeb', 'BtnCopy', 'BtnToggle', 'BtnDelete', 'BootGrid', 'DelayGrid', 'Tabs', 'UndoTab', 'UndoNote', 'UndoGrid', 'BtnUndoSel', 'BtnUndoFolder', 'BtnUndoRefresh', 'Status') { $ui[$n] = $win.FindName($n) }
    $state = @{ Scan = $Scan; Job = $null }

    $bc = New-Object Windows.Media.BrushConverter
    $makeTile = {
        param($value, $label, $color)
        $b = New-Object Windows.Controls.Border
        $b.Background = $bc.ConvertFrom('#171A21'); $b.BorderBrush = $bc.ConvertFrom('#262B36'); $b.BorderThickness = 1
        $b.CornerRadius = 6; $b.Padding = '12,6'; $b.Margin = '8,0,0,0'
        $sp = New-Object Windows.Controls.StackPanel
        $t1 = New-Object Windows.Controls.TextBlock; $t1.Text = [string]$value; $t1.FontSize = 18; $t1.FontWeight = 'SemiBold'; $t1.Foreground = $bc.ConvertFrom($color)
        $t2 = New-Object Windows.Controls.TextBlock; $t2.Text = $label; $t2.Foreground = $bc.ConvertFrom('#8B93A5'); $t2.FontSize = 11
        [void]$sp.Children.Add($t1); [void]$sp.Children.Add($t2); $b.Child = $sp
        return $b
    }

    # ---- filter sidebar: each list shows what was found with counts; counts follow the other filters ----
    $facetOrder = @('Status', 'Risk', 'Category', 'Publisher', 'Signature', 'Running', 'Scope')
    $facetTitles = @{ Status = 'Status'; Risk = 'Risk'; Category = 'Category'; Publisher = 'Publisher'; Signature = 'Signature'; Running = 'Running now'; Scope = 'Applies to' }
    $facetFixed = @{ Status = @('On', 'Off', 'Removed'); Risk = @('Flagged', 'High', 'Medium', 'Low', 'OK'); Signature = @('Signed', 'Unsigned', 'Bad signature', "Couldn't check", 'File missing', 'No file to check'); Running = @('Running now', 'Not running') }
    $facetLabels = @{ Flagged = 'Flagged (high + medium)'; On = 'On (starts automatically)'; Off = 'Off (disabled)' }
    $state.Filter = @{}; $state.Lists = @{}; $state.Updating = $false
    foreach ($f in $facetOrder) {
        $state.Filter[$f] = '*'
        $h = New-Object Windows.Controls.TextBlock
        $h.Text = $facetTitles[$f].ToUpper(); $h.Foreground = $bc.ConvertFrom('#8B93A5'); $h.FontSize = 11; $h.FontWeight = 'SemiBold'; $h.Margin = '6,10,0,3'
        [void]$ui.Facets.Children.Add($h)
        $lb = New-Object Windows.Controls.ListBox
        $lb.ItemTemplate = $win.Resources['FacetItem']; $lb.Tag = $f
        if ($f -in 'Category', 'Publisher') { $lb.MaxHeight = 220 }
        $lb.Add_SelectionChanged({
                param($s, $e)
                if ($state.Updating) { return }
                $entry = $s.SelectedItem
                if ($entry) { $state.Filter[$s.Tag] = $entry.Key; & $applyFilter }
            })
        [void]$ui.Facets.Children.Add($lb)
        $state.Lists[$f] = $lb
    }
    $updateFacets = {
        param($counts)
        $state.Updating = $true
        try {
            foreach ($f in $facetOrder) {
                $c = $counts[$f]
                if ($f -eq 'Risk') { $c['Flagged'] = [int]$c['High'] + [int]$c['Medium'] }
                $keys = if ($facetFixed.ContainsKey($f)) { $facetFixed[$f] } else { @($c.Keys | Where-Object { $_ -ne '*' } | Sort-Object @{ E = { [int]$c[$_] }; Descending = $true }, @{ E = { $_ } }) }
                $selKey = $state.Filter[$f]
                $entries = New-Object System.Collections.ArrayList
                [void]$entries.Add([pscustomobject]@{ Key = '*'; Label = 'All'; Count = [int]$c['*'] })
                foreach ($k in $keys) {
                    $n = [int]$c[$k]
                    if ($n -eq 0 -and $k -ne $selKey) { continue }
                    [void]$entries.Add([pscustomobject]@{ Key = $k; Label = $(if ($facetLabels.ContainsKey($k)) { $facetLabels[$k] } else { $k }); Count = $n })
                }
                $pick = $null; foreach ($en in $entries) { if ($en.Key -eq $selKey) { $pick = $en } }
                if (-not $pick) { $pick = [pscustomobject]@{ Key = $selKey; Label = $selKey; Count = 0 }; [void]$entries.Add($pick) }
                $state.Lists[$f].ItemsSource = $entries
                $state.Lists[$f].SelectedItem = $pick
            }
        } finally { $state.Updating = $false }
    }
    $applyFilter = {
        $s = $state.Scan; if (-not $s) { return }
        $q = $ui.Search.Text; $hide = [bool]$ui.HideMs.IsChecked
        $shown = New-Object System.Collections.ArrayList
        $counts = @{}; foreach ($f in $facetOrder) { $counts[$f] = @{ '*' = 0 } }
        foreach ($it in $s.Items) {
            if ($hide -and $it.IsMicrosoft -and $it.Risk -eq 'OK') { continue }
            if ($q -and "$($it.Name) $($it.ImagePath) $($it.Publisher) $($it.Command) $($it.Location)" -notlike "*$q*") { continue }
            $keys = Get-PssFacetKeys $it
            $nf = 0; $failed = ''
            foreach ($f in $facetOrder) {
                $want = $state.Filter[$f]
                if ($want -eq '*') { continue }
                $ok = if ($f -eq 'Risk' -and $want -eq 'Flagged') { $keys.Risk -in 'High', 'Medium' } else { $keys[$f] -eq $want }
                if (-not $ok) { $nf++; $failed = $f; if ($nf -gt 1) { break } }
            }
            if ($nf -eq 0) { [void]$shown.Add($it) }
            if ($nf -le 1) {
                # an item counts towards a list when it passes every OTHER filter
                foreach ($f in $facetOrder) {
                    if ($nf -eq 1 -and $f -ne $failed) { continue }
                    $c = $counts[$f]; $c['*'] = [int]$c['*'] + 1
                    $k = [string]$keys[$f]; $c[$k] = [int]$c[$k] + 1
                }
            }
        }
        $ui.Grid.ItemsSource = $shown
        & $updateFacets $counts
        $active = @($facetOrder | Where-Object { $state.Filter[$_] -ne '*' } | ForEach-Object { '{0}: {1}' -f $facetTitles[$_], $(if ($facetLabels.ContainsKey($state.Filter[$_])) { $facetLabels[$state.Filter[$_]] } else { $state.Filter[$_] }) })
        if ($q) { $active += "search: $q" }
        $ui.Status.Text = "Showing $($shown.Count) of $($s.Items.Count) items" + $(if ($active) { '  -  ' + ($active -join ', ') } else { '' }) + ("  -  scanned in {0:N1}s at {1:HH:mm:ss}" -f $s.Duration, $s.ScannedAt)
    }
    $clearFilters = {
        foreach ($f in $facetOrder) { $state.Filter[$f] = '*' }
        if ($ui.Search.Text) { $ui.Search.Text = '' } else { & $applyFilter }
    }

    # ---- boot tests tab ----
    $loadBootTests = {
        $tests = @(Get-PssBootTests)
        $ui.BtGrid.ItemsSource = $tests
        $st = Get-PssBootTestState
        $ui.BtState.Text = $(if ($st) { "Ready: '$($st.Label)'. Restart and sign in to run it." } else { '' })
        $ui.BtnBtCancel.IsEnabled = [bool]$st
        if (-not $ui.BtLabel.Text) { $ui.BtLabel.Text = $(if ($tests) { 'After changes' } else { 'Before changes' }) }
        $ui.BootTestTab.Header = $(if ($tests) { "Boot tests ($($tests.Count))" } else { 'Boot tests' })
    }
    $ui.BtnBtArm.Add_Click({
            $r = Start-PssBootTest $ui.BtLabel.Text
            $ui.Status.Text = $r.Message
            & $loadBootTests
            if (-not $r.Ok) { [void][Windows.MessageBox]::Show($win, $r.Message, 'PAX Startup Scanner', 'OK', 'Error'); return }
            $q = "$($r.Message)`n`nRestart now? Save your work first. Windows restarts 15 seconds after you choose Yes."
            if ([string][Windows.MessageBox]::Show($win, $q, 'PAX Startup Scanner', 'YesNo', 'Question') -eq 'Yes') { $ui.Status.Text = (Restart-PssNow).Message }
        })
    $ui.BtnBtCancel.Add_Click({ $ui.Status.Text = (Stop-PssBootTest).Message; & $loadBootTests })
    $ui.BtnBtRefresh.Add_Click({ & $loadBootTests })
    $ui.BtnBtRestart.Add_Click({
            if ([string][Windows.MessageBox]::Show($win, 'Restart the PC now? Save your work first. Windows restarts 15 seconds after you choose Yes.', 'PAX Startup Scanner', 'YesNo', 'Warning') -eq 'Yes') { $ui.Status.Text = (Restart-PssNow).Message }
        })
    $ui.BtnBtCompare.Add_Click({
            $all = @($ui.BtGrid.ItemsSource | Sort-Object Boot)
            $picked = @($ui.BtGrid.SelectedItems | ForEach-Object { $_ } | Sort-Object Boot)
            $old = $null; $new = $null
            if ($picked.Count -ge 2) { $old = $picked[0]; $new = $picked[-1] }
            elseif ($picked.Count -eq 1) {
                $i = [array]::IndexOf($all, $picked[0])
                if ($i -gt 0) { $old = $all[$i - 1]; $new = $picked[0] } elseif ($all.Count -ge 2) { $old = $picked[0]; $new = $all[1] }
            } elseif ($all.Count -ge 2) { $old = $all[-2]; $new = $all[-1] }
            if (-not $old) { $ui.BtCompare.Text = 'Two timed restarts are needed for a comparison.'; return }
            $ui.BtCompare.Text = ((Compare-PssBootTests $old $new) | ForEach-Object { $_.Text }) -join "`r`n"
        })

    # ---- right-click a row: every button from the details pane, then quick filters ----
    $cm = New-Object Windows.Controls.ContextMenu
    $mkItem = {
        param([string]$Text, [scriptblock]$Do)
        $mi = New-Object Windows.Controls.MenuItem; $mi.Header = $Text; $mi.Add_Click($Do); [void]$cm.Items.Add($mi)
        return $mi
    }
    # each item presses the matching button, so menu and buttons always behave the same
    $press = { param($btn) $btn.RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent))) }
    $null = & $mkItem 'Open location' { & $press $ui.BtnLoc }
    $null = & $mkItem 'Show file in Explorer' { & $press $ui.BtnFile }
    $null = & $mkItem 'Look up on VirusTotal' { & $press $ui.BtnVt }
    $null = & $mkItem 'Search the web' { & $press $ui.BtnWeb }
    $null = & $mkItem 'Copy details' { & $press $ui.BtnCopy }
    [void]$cm.Items.Add((New-Object Windows.Controls.Separator))
    $state.MiToggle = & $mkItem 'Disable' { & $press $ui.BtnToggle }
    $state.MiDelete = & $mkItem 'Delete...' { & $press $ui.BtnDelete }
    [void]$cm.Items.Add((New-Object Windows.Controls.Separator))
    $cm.Add_Opened({
            # mirror the buttons: same label, same enabled state, same reason when greyed out
            $state.MiToggle.Header = $ui.BtnToggle.Content
            $state.MiToggle.IsEnabled = $ui.BtnToggle.IsEnabled
            $state.MiDelete.IsEnabled = $ui.BtnDelete.IsEnabled
            foreach ($m in $state.MiToggle, $state.MiDelete) { [Windows.Controls.ToolTipService]::SetShowOnDisabled($m, $true) }
            $state.MiToggle.ToolTip = $ui.BtnToggle.ToolTip; $state.MiDelete.ToolTip = $ui.BtnDelete.ToolTip
        })
    $null = & $mkItem 'Show only this publisher' { $it = & $sel; if ($it) { $state.Filter['Publisher'] = $it.Vendor; & $applyFilter } }
    $null = & $mkItem 'Show only this category' { $it = & $sel; if ($it) { $state.Filter['Category'] = $it.Category; & $applyFilter } }
    $null = & $mkItem 'Show only items that are on' { $state.Filter['Status'] = 'On'; & $applyFilter }
    $null = & $mkItem 'Show only flagged items' { $state.Filter['Risk'] = 'Flagged'; & $applyFilter }
    $null = & $mkItem 'Clear filters' { & $clearFilters }
    $ui.Grid.ContextMenu = $cm

    $load = {
        $s = $state.Scan
        $ui.SubTitle.Text = "$($s.Computer)  -  $($s.OS)  -  " + $(if ($s.IsAdmin) { 'elevated' } else { 'not elevated' })
        $ui.Tiles.Children.Clear()
        [void]$ui.Tiles.Children.Add((& $makeTile $s.Items.Count 'startup items' '#E6E8EE'))
        [void]$ui.Tiles.Children.Add((& $makeTile @($s.Items | Where-Object { -not $_.IsMicrosoft }).Count 'third-party' '#E6E8EE'))
        [void]$ui.Tiles.Children.Add((& $makeTile @($s.Items | Where-Object Risk -eq 'High').Count 'high risk' '#FF7B7B'))
        [void]$ui.Tiles.Children.Add((& $makeTile @($s.Items | Where-Object Risk -eq 'Medium').Count 'medium risk' '#FBBF24'))
        [void]$ui.Tiles.Children.Add((& $makeTile $(if ($s.Boot.LastBootMs) { '{0:N1}s' -f ($s.Boot.LastBootMs / 1000) } else { 'n/a' }) $(if ($s.Boot.LastBootTime) { 'last boot, {0:MMM d}' -f $s.Boot.LastBootTime } else { 'last boot' }) '#38BDF8'))
        $notes = @()
        if ($script:PssReadOnly) { $notes += 'Read-only mode: nothing on this PC is written or changed (Disable, Delete, Undo, boot tests and export are off).' }
        if (-not $s.IsAdmin) { $notes += 'Not elevated: services, tasks, WMI and boot history may be incomplete. Run from an elevated PowerShell for full results.' }
        if ($s.NotLoadedProfiles) { $notes += 'Users not logged on (Run keys not read): ' + ($s.NotLoadedProfiles -join ', ') }
        $notes += $s.Errors
        $ui.Banner.Text = ($notes -join "`n"); $ui.Banner.Visibility = $(if ($notes) { 'Visible' } else { 'Collapsed' })
        $ui.BootGrid.ItemsSource = @($s.Boot.Boots)
        $ui.DelayGrid.ItemsSource = @($s.Boot.Delays)
        & $applyFilter
    }

    $sel = { $ui.Grid.SelectedItem }
    $updateButtons = {
        $it = & $sel
        if (-not $it) { $ui.BtnToggle.IsEnabled = $false; $ui.BtnDelete.IsEnabled = $false; $ui.BtnToggle.ToolTip = $null; $ui.BtnDelete.ToolTip = $null; return }
        $ui.BtnToggle.Content = $(if ($it.Enabled -or -not $it.CanDisable) { 'Disable' } else { 'Enable' })
        $ui.BtnToggle.IsEnabled = [bool]$it.CanDisable
        $ui.BtnDelete.IsEnabled = [bool]$it.CanDelete
        $ui.BtnToggle.ToolTip = $(if ($it.CanDisable) { 'Stop it starting automatically. It stays installed and can be enabled again.' } elseif ($it.ActionNote) { $it.ActionNote } elseif ($it.CanDelete) { "This kind of entry can't be disabled, only deleted." } else { $null })
        $ui.BtnDelete.ToolTip = $(if ($it.CanDelete) { "Remove the startup entry (not the program). It's backed up first so you can undo it." } elseif ($it.ActionNote) { $it.ActionNote } else { "This entry can't be deleted here." })
    }
    $ui.Grid.Add_SelectionChanged({
            $it = & $sel
            $ui.Detail.Text = $(if ($it) { Get-PssDetailText $it } else { '' })
            & $updateButtons
        })
    $ui.Search.Add_TextChanged({
            $ui.SearchHint.Visibility = $(if ($ui.Search.Text) { 'Collapsed' } else { 'Visible' })
            & $applyFilter
        })
    $ui.HideMs.Add_Click({ & $applyFilter })
    $ui.BtnClear.Add_Click({ & $clearFilters })
    $ui.BtnLoc.Add_Click({ $it = & $sel; if ($it) { $script:PssLastNote = ''; Open-PssLocation $it; if ($script:PssLastNote) { $ui.Status.Text = $script:PssLastNote } } })
    $ui.BtnFile.Add_Click({ $it = & $sel; if ($it) { Open-PssFolder $it } })
    $ui.BtnWeb.Add_Click({ $it = & $sel; if ($it) { Open-PssWebSearch $it } })
    $ui.BtnVt.Add_Click({ $it = & $sel; if ($it) { if (Open-PssVirusTotal $it) { $ui.Detail.Text = Get-PssDetailText $it } else { $ui.Status.Text = $script:PssHashError } } })
    $ui.BtnCopy.Add_Click({ $it = & $sel; if ($it) { [Windows.Clipboard]::SetText((Get-PssDetailText $it)); $ui.Status.Text = 'Details copied to clipboard.' } })
    $ui.Grid.Add_MouseDoubleClick({ $it = & $sel; if ($it) { $script:PssLastNote = ''; Open-PssLocation $it; if ($script:PssLastNote) { $ui.Status.Text = $script:PssLastNote } } })
    $exportTo = {
        param([bool]$ShownOnly)
        if ($script:PssReadOnly) { $ui.Status.Text = 'Read-only mode: reports are not saved. Copy details instead, or run without -ReadOnly.'; return }
        $d = New-Object Microsoft.Win32.SaveFileDialog
        $d.Filter = 'HTML report|*.html|CSV|*.csv|JSON|*.json'
        $d.FileName = 'PAX-Startup-{0}-{1:yyyyMMdd-HHmm}' -f $state.Scan.Computer, $state.Scan.ScannedAt
        if (-not $d.ShowDialog($win)) { return }
        $out = $state.Scan; $note = ''
        if ($ShownOnly) {
            $out = $state.Scan.PSObject.Copy()
            $out.Items = $ui.Grid.ItemsSource.ToArray()
            $note = ($ui.Status.Text -split '  -  ' | Select-Object -SkipLast 1) -join ' - '
        }
        try { Export-PssReport $out $d.FileName $note; $ui.Status.Text = "Saved $($d.FileName)"; if ($d.FileName -match '\.html$') { Start-Process $d.FileName } }
        catch { [void][Windows.MessageBox]::Show($win, "Could not save: $($_.Exception.Message)", 'PAX Startup Scanner', 'OK', 'Error') }
    }
    $ui.BtnExport.Add_Click({
            $m = New-Object Windows.Controls.ContextMenu
            $a = New-Object Windows.Controls.MenuItem; $a.Header = "All items ($($state.Scan.Items.Count))..."; $a.Add_Click({ & $exportTo $false })
            $b = New-Object Windows.Controls.MenuItem; $b.Header = "Only the $($ui.Grid.Items.Count) items shown now..."; $b.Add_Click({ & $exportTo $true })
            [void]$m.Items.Add($a); [void]$m.Items.Add($b)
            $m.PlacementTarget = $ui.BtnExport; $m.Placement = 'Bottom'; $m.IsOpen = $true
        })

    # ---- full backup of the startup settings: file or clipboard (for remote sessions), and restore ----
    $backupTo = {
        param([bool]$Clipboard)
        if (-not $Clipboard -and $script:PssReadOnly) { $ui.Status.Text = 'Read-only mode: no files are written. Use "Copy a backup to the clipboard" instead.'; return }
        $win.Cursor = [Windows.Input.Cursors]::Wait
        try { $json = New-PssSnapshot $state.Scan } finally { $win.Cursor = $null }
        $n = ($json | ConvertFrom-Json).Count
        if ($Clipboard) {
            [Windows.Clipboard]::SetText($json)
            $ui.Status.Text = "Copied a backup of $n startup entries ({0:N0} KB of text) to the clipboard. Paste it into a text file on your PC and save it as .json." -f ($json.Length / 1KB)
            return
        }
        $d = New-Object Microsoft.Win32.SaveFileDialog
        $d.Filter = 'PAX Startup Scanner backup|*.json'
        $d.FileName = 'PAX-Startup-Backup-{0}-{1:yyyyMMdd-HHmm}' -f $env:COMPUTERNAME, (Get-Date)
        if (-not $d.ShowDialog($win)) { return }
        try { [IO.File]::WriteAllText($d.FileName, $json, (New-Object Text.UTF8Encoding $false)); $ui.Status.Text = "Saved a backup of $n startup entries to $($d.FileName)" }
        catch { [void][Windows.MessageBox]::Show($win, "Could not save: $($_.Exception.Message)", 'PAX Startup Scanner', 'OK', 'Error') }
    }
    $restoreFrom = {
        param([bool]$Clipboard)
        try {
            if ($Clipboard) { $snap = Read-PssSnapshot ([Windows.Clipboard]::GetText()) }
            else {
                $d = New-Object Microsoft.Win32.OpenFileDialog
                $d.Filter = 'PAX Startup Scanner backup|*.json|All files|*.*'
                if (-not $d.ShowDialog($win)) { return }
                $snap = Read-PssSnapshot ([IO.File]::ReadAllText($d.FileName))
            }
        } catch { [void][Windows.MessageBox]::Show($win, $_.Exception.Message, 'PAX Startup Scanner', 'OK', 'Error'); return }
        $icon = if ($snap.Computer -ne $env:COMPUTERNAME) { 'Warning' } else { 'Question' }
        if ([string][Windows.MessageBox]::Show($win, (Confirm-PssRestoreText $snap), 'PAX Startup Scanner', 'YesNo', $icon) -ne 'Yes') { return }
        $win.Cursor = [Windows.Input.Cursors]::Wait
        try { $r = Restore-PssSnapshot $snap } finally { $win.Cursor = $null }
        $ui.Status.Text = $r.Message
        if ($r.Failed) { [void][Windows.MessageBox]::Show($win, ($r.Message + "`n`n" + ($r.Failed -join "`n")), 'PAX Startup Scanner', 'OK', 'Warning') }
        elseif (-not $r.Ok) { [void][Windows.MessageBox]::Show($win, $r.Message, 'PAX Startup Scanner', 'OK', 'Error') }
        if ($r.Message -notlike 'Read-only*' -and -not $state.Job) { & $startRescan }
    }
    $ui.BtnBackup.Add_Click({
            $m = New-Object Windows.Controls.ContextMenu
            $items = @(
                @('Save a backup to a file...', { & $backupTo $false }),
                @('Copy a backup to the clipboard', { & $backupTo $true }),
                $null,
                @('Restore from a backup file...', { & $restoreFrom $false }),
                @('Restore from the clipboard...', { & $restoreFrom $true })
            )
            foreach ($i in $items) {
                if (-not $i) { [void]$m.Items.Add((New-Object Windows.Controls.Separator)); continue }
                $mi = New-Object Windows.Controls.MenuItem; $mi.Header = $i[0]; $mi.Add_Click($i[1]); [void]$m.Items.Add($mi)
            }
            $m.PlacementTarget = $ui.BtnBackup; $m.Placement = 'Bottom'; $m.IsOpen = $true
        })

    $loadUndo = {
        $recs = @(Get-PssUndoRecords)
        $ui.UndoGrid.ItemsSource = $recs
        $ui.UndoTab.Header = $(if ($recs.Count) { "Undo changes ($($recs.Count))" } else { 'Undo changes' })
        $ui.UndoNote.Text = "Every Disable, Enable and Delete made with PAX Startup Scanner on this PC is backed up in $(Get-PssBackupPath). Pick one and choose Undo to put it back the way it was."
        $ui.BtnUndoSel.IsEnabled = $false
    }
    $doChange = {
        param([string]$Action)
        $it = & $sel; if (-not $it) { return }
        # Disable/Enable are reversible and happen straight away; only Delete asks first
        if ($Action -eq 'Delete') {
            $answer = [Windows.MessageBox]::Show($win, (Get-PssConfirmText $it $Action), 'PAX Startup Scanner', 'YesNo', 'Warning')
            if ([string]$answer -ne 'Yes') { return }
        }
        $res = Invoke-PssChange $it $Action
        if (-not $res.Ok) { [void][Windows.MessageBox]::Show($win, $res.Message, 'PAX Startup Scanner', 'OK', 'Error') }
        & $applyFilter
        if ($ui.Grid.Items.Contains($it)) { $ui.Grid.SelectedItem = $it; $ui.Grid.ScrollIntoView($it) }
        $ui.Status.Text = $res.Message + $(if ($res.Ok -and $Action -ne 'Delete') { '  (Undo changes can reverse it.)' } else { '' })
        $ui.Detail.Text = Get-PssDetailText $it
        & $updateButtons
        & $loadUndo
    }
    $ui.BtnToggle.Add_Click({ $it = & $sel; if ($it) { & $doChange $(if ($it.Enabled) { 'Disable' } else { 'Enable' }) } })
    $ui.BtnDelete.Add_Click({ & $doChange 'Delete' })
    $ui.UndoGrid.Add_SelectionChanged({ $ui.BtnUndoSel.IsEnabled = [bool]$ui.UndoGrid.SelectedItem })
    $ui.BtnUndoRefresh.Add_Click({ & $loadUndo })
    $ui.BtnUndoFolder.Add_Click({ $d = Get-PssBackupPath; if (Test-Path -LiteralPath $d) { Start-Process explorer.exe -ArgumentList "`"$d`"" } else { $ui.Status.Text = 'No backups yet.' } })
    $ui.BtnUndoSel.Add_Click({
            $r = $ui.UndoGrid.SelectedItem; if (-not $r) { return }
            $q = "Undo this change?`n`n$($r.Action): $($r.Name)`n$($r.Category): $($r.Location)`nMade $($r.When) by $($r.RunBy)"
            if ([string][Windows.MessageBox]::Show($win, $q, 'PAX Startup Scanner', 'YesNo', 'Question') -ne 'Yes') { return }
            $res = Invoke-PssUndo $r
            $ui.Status.Text = $res.Message
            if (-not $res.Ok) { [void][Windows.MessageBox]::Show($win, $res.Message, 'PAX Startup Scanner', 'OK', 'Error') }
            & $loadUndo
            if ($res.Ok -and -not $state.Job) { & $startRescan }
        })

    $timer = New-Object Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(120)
    $timer.Add_Tick({
            $j = $state.Job; if (-not $j) { $timer.Stop(); return }
            $ui.Status.Text = "$($j.Sync.Stage)  $($j.Sync.Pct)%"
            if ($j.Handle.IsCompleted) {
                $timer.Stop()
                try { $r = @($j.PS.EndInvoke($j.Handle)); if ($r.Count) { $state.Scan = $r[-1] } } catch { $ui.Status.Text = "Scan failed: $($_.Exception.Message)" }
                $j.PS.Dispose(); $j.RS.Close(); $state.Job = $null
                $ui.BtnRescan.IsEnabled = $true; $win.Cursor = $null
                & $load
            }
        })
    $startRescan = {
        $ui.BtnRescan.IsEnabled = $false; $win.Cursor = [Windows.Input.Cursors]::AppStarting
        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        foreach ($f in (Get-ChildItem function: | Where-Object { $_.Name -like '*-Pss*' })) {
            $iss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry $f.Name, $f.Definition))
        }
        $sync = [hashtable]::Synchronized(@{ Stage = 'Starting...'; Pct = 0 })
        $rs = [runspacefactory]::CreateRunspace($iss); $rs.Open()
        $rs.SessionStateProxy.SetVariable('PssVersion', $script:PssVersion)
        $rs.SessionStateProxy.SetVariable('PssReadOnly', [bool]$script:PssReadOnly)
        $ps = [powershell]::Create(); $ps.Runspace = $rs
        [void]$ps.AddScript('param($s) Invoke-PssScan -Status $s').AddArgument($sync)
        $state.Job = @{ PS = $ps; RS = $rs; Sync = $sync; Handle = $ps.BeginInvoke() }
        $timer.Start()
    }
    $ui.BtnRescan.Add_Click({ & $startRescan })

    & $load
    & $loadUndo
    & $loadBootTests
    # Size to the screen (90% of the work area, within sensible limits)
    try {
        $wa = [Windows.SystemParameters]::WorkArea
        $win.Width = [Math]::Max(1000, [Math]::Min(1500, $wa.Width * 0.92)); $win.Height = [Math]::Max(600, [Math]::Min(940, $wa.Height * 0.92))
    } catch {}
    if ($Snapshot) {
        # Lay the window content out without ever showing a window, then save it as a PNG
        $root = $win.Content; $win.Content = $null
        foreach ($key in @($win.Resources.Keys)) { $root.Resources[$key] = $win.Resources[$key] }
        $wrap = New-Object Windows.Controls.Border
        $wrap.Background = $win.Background
        [Windows.Documents.TextElement]::SetForeground($wrap, $win.Foreground)
        [Windows.Documents.TextElement]::SetFontFamily($wrap, $win.FontFamily)
        [Windows.Documents.TextElement]::SetFontSize($wrap, $win.FontSize)
        $wrap.Child = $root
        $size = New-Object Windows.Size 1440, 860
        $wrap.Measure($size); $wrap.Arrange((New-Object Windows.Rect $size)); $wrap.UpdateLayout()
        if ($ui.Grid.Items.Count) { $ui.Grid.SelectedIndex = 0; $wrap.UpdateLayout() }
        if ($SnapshotTab) {
            $ui.Tabs.SelectedIndex = $SnapshotTab
            if ($ui.UndoGrid.Items.Count) { $ui.UndoGrid.SelectedIndex = 0 }
            if ($ui.BtGrid.Items.Count -ge 2) { $ui.BtnBtCompare.RaiseEvent((New-Object Windows.RoutedEventArgs ([Windows.Controls.Button]::ClickEvent))) }
            $wrap.Measure($size); $wrap.Arrange((New-Object Windows.Rect $size)); $wrap.UpdateLayout()
        }
        $bmp = New-Object Windows.Media.Imaging.RenderTargetBitmap 1440, 860, 96, 96, ([Windows.Media.PixelFormats]::Pbgra32)
        $bmp.Render($wrap)
        $enc = New-Object Windows.Media.Imaging.PngBitmapEncoder
        $enc.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bmp))
        $fs = [IO.File]::Create($Snapshot); $enc.Save($fs); $fs.Close()
        return $state.Scan
    }
    [void]$win.ShowDialog()
    return $state.Scan
}

# ======================================================================================
#  Entry point
# ======================================================================================

function Start-PaxStartupScanner {
    param([switch]$Gui, [switch]$Report, [string]$Export, [switch]$ReadOnly)
    # Run the same way whatever the technician's profile sets (these only apply inside this call)
    Set-StrictMode -Off
    $ErrorActionPreference = 'Continue'
    $ProgressPreference = 'SilentlyContinue'
    $script:PssReadOnly = [bool]$ReadOnly -or $env:PSS_READONLY -in '1', 'true', 'yes'
    $script:PssEof = $false
    $script:PssShowMicrosoft = $false
    $script:PssOnlyEnabled = $false
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        Write-Host '  This is 32-bit PowerShell; results would be incomplete. Use the normal 64-bit PowerShell.' -ForegroundColor Red
        return
    }
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-PssHeader $null
    if (-not $isAdmin) { Write-Host '   Not running elevated - some areas (services, tasks, WMI, boot history) will be incomplete.' -ForegroundColor Yellow }
    $scan = Invoke-PssConsoleScan
    if ($Export) {
        Export-PssReport $scan $Export
        Write-Host "   Report saved: $Export" -ForegroundColor Green
    }
    if ($Gui) { [void](Show-PssGui $scan); return }
    if ($Report) {
        Write-PssHeader $scan
        Write-PssDashboard $scan
        [void](Write-PssTable ($scan.Items | Where-Object { $_.Risk -in 'High', 'Medium' }) 'Flagged items' -NoPaging)
        Write-Host ''
        return
    }
    Start-PssConsole $scan
}

Start-PaxStartupScanner -Gui:$Gui -Report:$Report -Export $Export -ReadOnly:$ReadOnly
