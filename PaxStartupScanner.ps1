#Requires -Version 5.1
<#
.SYNOPSIS
    PAX Startup Scanner - finds everything that starts with Windows, shows what it is and where
    it lives, flags suspicious entries and shows what is slowing boot down.

.DESCRIPTION
    Read-only IT diagnostic tool. Nothing is installed and nothing on the system is changed.
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
#>
[CmdletBinding()]
param(
    [switch]$Gui,
    [switch]$Report,
    [string]$Export
)

$script:PssVersion = '1.0.0'
$script:PssUrl     = 'https://raw.githubusercontent.com/joshpack/PaxStartupScanner/main/PaxStartupScanner.ps1'
$script:PssSelfPath = $PSCommandPath   # empty when run through irm | iex

# ======================================================================================
#  Scanner engine
# ======================================================================================

function Initialize-Pss {
    $script:PssHKLM = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    $script:PssHKU  = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Registry64)
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
        [string]$Publisher = '', [string]$Kind = '', [bool]$NoImage = $false
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
    $it = [pscustomobject][ordered]@{
        Id = 0; Risk = 'OK'; RiskScore = 0; Category = $Category; Name = $Name; Enabled = $Enabled
        EnabledText = $(if ($Enabled) { 'Yes' } else { 'No' }); User = $User; Trigger = $Trigger
        Command = $Command; ImagePath = $(if ($res) { $res.Image } else { '' }); Via = $(if ($res) { $res.Host } else { '' })
        Location = $Location; RegKey = $RegKey; ValueName = $ValueName; ServiceName = $ServiceName; Extra = $Extra; Kind = $Kind
        NoImage = $NoImage
        FileExists = $false; Size = $null; Created = $null; Modified = $null; Hidden = $false
        Publisher = $Publisher; Company = ''; Description = ''; Product = ''; Version = ''
        SignStatus = ''; Signer = ''; SignText = ''; IsMicrosoft = $false
        Running = $false; ProcCount = 0; MemoryMB = 0; CpuSec = 0; RunText = ''
        BootDelayMs = 0; BootDelayCount = 0; BootDelayText = ''; Impact = ''
        Flags = ''; FlagList = @(); Sha256 = ''
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
                Add-PssItem -Category $d.Cat -Name $nm -Location $path -Command $v -Enabled $en -User $r.User -Trigger 'Logon' -RegKey $path -ValueName $n
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
                    if ($v) { Add-PssItem -Category 'Run Key' -Name "Windows\$n" -Location $path -Command $v -User $r.User -Trigger 'Logon' -RegKey $path -ValueName $n -Extra 'Legacy load point (rarely used legitimately)' }
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
            $cmd = $file.FullName; $img = $file.FullName
            if ($file.Extension -eq '.lnk' -and $shell) {
                try {
                    $s = $shell.CreateShortcut($file.FullName)
                    if ($s.TargetPath) { $img = $s.TargetPath; $cmd = ('"{0}" {1}' -f $s.TargetPath, $s.Arguments).Trim() }
                } catch {}
            }
            $en = $true; if ($fd.Root) { $en = Get-PssApproved $fd.Root 'StartupFolder' $file.Name }
            $res = Resolve-PssImage $cmd
            Add-PssItem -Category 'Startup Folder' -Name $file.BaseName -Location $file.FullName -Command $cmd -Image $res.Image -Enabled $en -User $fd.User -Trigger 'Logon' -Kind 'File'
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
                        Add-PssItem -Category 'Scheduled Task' -Name $t.Path -Location "Task Scheduler $($t.Path)" -Command ("$cmd $($a.A)").Trim() -Image $res.Image -Enabled ([bool]$t.Enabled) -User $runAs -Trigger $trigText -Extra ($extra -join '; ') -Kind 'Task'
                    } else {
                        $c = Get-PssClsid $a.C
                        Add-PssItem -Category 'Scheduled Task' -Name $t.Path -Location "Task Scheduler $($t.Path)" -Command "COM handler $($a.C) $($c.Name)" -Image $c.Dll -NoImage (-not $c.Dll) -Enabled ([bool]$t.Enabled) -User $runAs -Trigger $trigText -Extra ($extra -join '; ') -Kind 'Task'
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
        if ($isDriver -and -not $img) { $img = "System32\drivers\$($s.ServiceName).sys" }
        $trig = if ($isDriver) { "$st start" } elseif ($delayed) { 'Automatic (delayed)' } else { 'Automatic' }
        if ($hasTrig -and -not $isDriver) { $trig += ' + trigger' }
        $status = [string]$s.Status
        $extra = "Status: $status"; if ($acct) { $extra += "; Account: $acct" }
        $res = Resolve-PssImage $img
        $image = $res.Image
        if ($dll) { $image = $dll; $extra += "; Host: $img" }
        Add-PssItem -Category $(if ($isDriver) { 'Driver' } else { 'Service' }) -Name ("{0} ({1})" -f $s.DisplayName, $s.ServiceName) -Location $path -Command $img -Image $image -User $acct -Trigger $trig -RegKey $path -Extra $extra -ServiceName $s.ServiceName -Kind 'Service'
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
                Add-PssItem -Category 'Winlogon' -Name "Winlogon\$n" -Location $path -Command $part -User $r.User -Trigger 'Logon' -RegKey $path -ValueName $n -Extra $(if ($default) { 'Windows default value' } else { 'NON-DEFAULT value' }) -Kind $(if ($default) { 'Default' } else { 'Modified' })
            }
        }
        $nk = (Open-PssSub $k 'Notify')
        if ($nk) {
            foreach ($sn in $nk.GetSubKeyNames()) {
                $sk = (Open-PssSub $nk $sn); $dll = [string](Get-PssRegValue $sk 'DllName'); $sk.Close()
                if ($dll) { Add-PssItem -Category 'Winlogon' -Name "Notify\$sn" -Location "$path\Notify\$sn" -Command $dll -Image $dll -User $r.User -Trigger 'Logon' -RegKey "$path\Notify\$sn" -Kind 'Modified' }
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
                Add-PssItem -Category 'AppInit' -Name ([IO.Path]::GetFileName($d)) -Location $p -Command $d -Image $d -Enabled ($load -eq 1) -Trigger 'Every GUI process' -RegKey $p -ValueName 'AppInit_DLLs' -Kind 'Modified'
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
            if ($dbg) { Add-PssItem -Category 'IFEO' -Name "$sn -> Debugger" -Location "$base\$sn" -Command $dbg -Trigger "When $sn starts" -RegKey "$base\$sn" -ValueName 'Debugger' -Extra 'Runs instead of the target program' -Kind 'Modified' }
            $sk.Close()
        }
        $k.Close()
    }
    $spe = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
    $k = Open-PssKey $spe
    if ($k) {
        foreach ($sn in $k.GetSubKeyNames()) {
            $sk = (Open-PssSub $k $sn); $m = [string](Get-PssRegValue $sk 'MonitorProcess'); $sk.Close()
            if ($m) { Add-PssItem -Category 'IFEO' -Name "$sn -> MonitorProcess" -Location "$spe\$sn" -Command $m -Trigger "When $sn exits" -RegKey "$spe\$sn" -ValueName 'MonitorProcess' -Kind 'Modified' }
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
                Add-PssItem -Category 'Boot Execute' -Name "$n" -Location $sm -Command $v -Image "$env:SystemRoot\System32\$img.exe" -Trigger 'Before Windows starts' -RegKey $sm -ValueName $n -Extra $(if ($def) { 'Windows default value' } else { 'NON-DEFAULT value' }) -Kind $(if ($def) { 'Default' } else { 'Modified' })
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
                    Add-PssItem -Category 'LSA' -Name "$n\$pkg" -Location $p -Command $pkg -Image "$env:SystemRoot\System32\$dll" -Trigger 'Loaded by LSASS at boot' -RegKey $p -ValueName $n
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
            if ($d) { Add-PssItem -Category 'Print Monitor' -Name $sn -Location "$pm\$sn" -Command $d -Image "$env:SystemRoot\System32\$d" -Trigger 'Loaded by spooler' -RegKey "$pm\$sn" -ValueName 'Driver' }
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
            if ($stub) { Add-PssItem -Category 'Active Setup' -Name $(if ($nm) { $nm } else { $sn }) -Location "$p\$sn" -Command $stub -Enabled ($isOn -ne 0) -Trigger 'First logon per user' -RegKey "$p\$sn" -ValueName 'StubPath' }
        }
        $k.Close()
    }
    # Explorer hooks: ShellServiceObjects, DelayLoad, BHOs, SharedTaskScheduler
    foreach ($p in 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects', 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects') {
        $k = Open-PssKey $p; if (-not $k) { continue }
        foreach ($sn in $k.GetSubKeyNames()) {
            $c = Get-PssClsid $sn
            Add-PssItem -Category 'Explorer' -Name $(if ($c.Name) { $c.Name } else { $sn }) -Location "$p\$sn" -Command "$sn" -Image $c.Dll -Trigger $(if ($p -match 'Browser') { 'Internet Explorer / Edge IE mode' } else { 'Explorer start' }) -RegKey "$p\$sn"
        }
        $k.Close()
    }
    foreach ($p in 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler') {
        $k = Open-PssKey $p; if (-not $k) { continue }
        foreach ($n in $k.GetValueNames()) {
            $v = [string]$k.GetValue($n); $clsid = if ($p -match 'Shared') { $n } else { $v }
            $c = Get-PssClsid $clsid
            Add-PssItem -Category 'Explorer' -Name $(if ($c.Name) { $c.Name } elseif ($n) { $n } else { $clsid }) -Location $p -Command $clsid -Image $c.Dll -Trigger 'Explorer start' -RegKey $p -ValueName $n
        }
        $k.Close()
    }
    # cmd.exe AutoRun, logon scripts, screensaver, Store startup tasks (per user)
    $roots = @([pscustomobject]@{ Root = 'HKLM'; User = 'All users' }) + @($script:PssUsers | ForEach-Object { [pscustomobject]@{ Root = $_.Root; User = $_.User; Sid = $_.Sid } })
    foreach ($r in $roots) {
        $p = "$($r.Root)\Software\Microsoft\Command Processor"
        $k = Open-PssKey $p
        if ($k) { $v = [string](Get-PssRegValue $k 'AutoRun'); $k.Close(); if ($v) { Add-PssItem -Category 'Cmd AutoRun' -Name 'Command Processor AutoRun' -Location $p -Command $v -User $r.User -Trigger 'Every cmd.exe start' -RegKey $p -ValueName 'AutoRun' -Kind 'Modified' } }
        if ($r.Root -ne 'HKLM') {
            $p = "$($r.Root)\Environment"
            $k = Open-PssKey $p
            if ($k) { $v = [string](Get-PssRegValue $k 'UserInitMprLogonScript'); $k.Close(); if ($v) { Add-PssItem -Category 'Logon Script' -Name 'UserInitMprLogonScript' -Location $p -Command $v -User $r.User -Trigger 'Logon' -RegKey $p -ValueName 'UserInitMprLogonScript' -Kind 'Modified' } }
            $p = "$($r.Root)\Control Panel\Desktop"
            $k = Open-PssKey $p
            if ($k) {
                $v = [string](Get-PssRegValue $k 'SCRNSAVE.EXE'); $act = [string]$k.GetValue('ScreenSaveActive'); $k.Close()
                if ($v) { Add-PssItem -Category 'Screensaver' -Name ([IO.Path]::GetFileName($v)) -Location $p -Command $v -Image $v -Enabled ($act -eq '1') -User $r.User -Trigger 'Idle' -RegKey $p -ValueName 'SCRNSAVE.EXE' }
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
                        Add-PssItem -Category 'Store App' -Name "$fam ($tid)" -Location "$p\$pkg\$tid" -Command $pkg -Enabled ($state -in 2, 4, 5) -User $r.User -Trigger 'Logon' -RegKey "$p\$pkg\$tid" -ValueName 'State' -Publisher $(if ($fam -match '^Microsoft') { 'Microsoft (Store package)' } else { 'Store package' }) -NoImage $true -Extra "Package: $pkg; State: $state"
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
                    if ($scr) { Add-PssItem -Category 'Logon Script' -Name "GPO $kind script" -Location "$p\$g\$s" -Command "$scr $par".Trim() -Image $scr -User $r.User -Trigger $kind -RegKey "$p\$g\$s" -ValueName 'Script' }
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
        foreach ($n in $k.GetValueNames()) { $v = [string]$k.GetValue($n); if ($v) { Add-PssItem -Category 'Netsh' -Name $n -Location $p -Command $v -Image "$env:SystemRoot\System32\$v" -Trigger 'When netsh runs' -RegKey $p -ValueName $n } }
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
        $wa = @{ Category = 'WMI'; Name = $c.Name; Location = "root\subscription $cls"; Command = $cmd; Trigger = $(if ($q) { $q } else { 'Not bound to a filter' }); Kind = 'Modified'; Extra = "Consumer type: $cls" }
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
    $res = [pscustomobject]@{ Available = $false; Error = ''; Boots = @(); Delays = @(); LastBootMs = 0; LastMainMs = 0; LastPostMs = 0 }
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
    if ($res.Boots) { $b = @($res.Boots)[0]; $res.LastBootMs = $b.BootSec * 1000; $res.LastMainMs = $b.MainPathSec * 1000; $res.LastPostMs = $b.PostBootSec * 1000 }
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
        if ($it.Created -and -not $it.IsMicrosoft -and ((Get-Date) - $it.Created).TotalDays -lt 7 -and $it.FileExists) { $flags.Add('File created in the last 7 days'); $score += 1 }
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
    $procMap = @{}
    try {
        foreach ($p in (Get-CimInstance Win32_Process -Property ProcessId, ExecutablePath, WorkingSetSize, KernelModeTime, UserModeTime -ErrorAction Stop)) {
            if (-not $p.ExecutablePath) { continue }
            $key = $p.ExecutablePath.ToLowerInvariant()
            if (-not $procMap.ContainsKey($key)) { $procMap[$key] = @{ Count = 0; WS = 0; Cpu = 0 } }
            $procMap[$key].Count++; $procMap[$key].WS += [double]$p.WorkingSetSize; $procMap[$key].Cpu += ([double]$p.KernelModeTime + [double]$p.UserModeTime) / 1e7
        }
    } catch {}

    Set-PssStatus 'Reading boot performance history...' 90 $Status
    $boot = Get-PssBootPerf
    $delayMap = @{}
    foreach ($d in $boot.Delays) {
        foreach ($nm in @($d.Name, $d.FriendlyName)) {
            if (-not $nm) { continue }
            $key = ([IO.Path]::GetFileName($nm)).ToLowerInvariant()
            if (-not $delayMap.ContainsKey($key)) { $delayMap[$key] = @{ Max = 0; Count = 0 } }
            $delayMap[$key].Count++; if ($d.DegradationMs -gt $delayMap[$key].Max) { $delayMap[$key].Max = $d.DegradationMs }
        }
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
        if ($it.ImagePath) {
            $pm = $procMap[[string]$it.ImagePath.ToLowerInvariant()]
            if ($pm -and $it.ImagePath -notmatch '(?i)\\(svchost|rundll32|dllhost|explorer)\.exe$') {
                $it.Running = $true; $it.ProcCount = $pm.Count; $it.MemoryMB = [int][math]::Round($pm.WS / 1MB, 0); $it.CpuSec = [int][math]::Round($pm.Cpu, 0)
            }
        }
        $it.RunText = if ($it.ProcCount) { '{0} MB' -f $it.MemoryMB } elseif ($it.Running) { 'Running' } else { '' }
        $keys = @()
        if ($it.ImagePath) { try { $keys += [IO.Path]::GetFileName($it.ImagePath).ToLowerInvariant() } catch {} }
        if ($it.ServiceName) { $keys += $it.ServiceName.ToLowerInvariant() }
        foreach ($key in $keys) { if ($delayMap.ContainsKey($key)) { $it.BootDelayMs = $delayMap[$key].Max; $it.BootDelayCount = $delayMap[$key].Count; break } }
        if ($it.BootDelayMs) { $it.BootDelayText = '{0:N1}s' -f ($it.BootDelayMs / 1000) }
        $it.Impact = if ($it.BootDelayMs -ge 3000 -or $it.MemoryMB -ge 400) { 'High' } elseif ($it.BootDelayMs -ge 1000 -or $it.MemoryMB -ge 150 -or $it.CpuSec -ge 600) { 'Medium' } elseif ($it.Running -or $it.BootDelayMs) { 'Low' } else { '' }
        Measure-PssRisk $it
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
    if ($it.BootDelayMs) { $f['Boot delay'] = '{0:N1}s worst case, flagged by Windows {1} time(s)' -f ($it.BootDelayMs / 1000), $it.BootDelayCount }
    if ($it.Sha256) { $f['SHA-256'] = $it.Sha256 }
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

function Export-PssReport($Scan, [string]$Path) {
    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()
    $cols = 'Id', 'Risk', 'RiskScore', 'Category', 'Name', 'EnabledText', 'User', 'Trigger', 'Command', 'ImagePath', 'Publisher', 'SignStatus', 'Description', 'Version', 'FileExists', 'Created', 'Modified', 'Location', 'ValueName', 'Running', 'MemoryMB', 'BootDelayMs', 'Impact', 'IsMicrosoft', 'Flags', 'Extra'
    if ($ext -eq '.csv') { $Scan.Items | Select-Object $cols | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8; return }
    if ($ext -eq '.json') {
        [pscustomobject]@{ Computer = $Scan.Computer; OS = $Scan.OS; ScannedAt = $Scan.ScannedAt; Admin = $Scan.IsAdmin; Items = @($Scan.Items | Select-Object $cols); Boots = $Scan.Boot.Boots; BootDelays = $Scan.Boot.Delays } |
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
<div class="tiles">
<div class="t"><b>$($items.Count)</b>startup items</div>
<div class="t"><b>$(@($items | Where-Object { -not $_.IsMicrosoft }).Count)</b>third-party</div>
<div class="t"><b class="High">$(@($items | Where-Object Risk -eq 'High').Count)</b>high risk</div>
<div class="t"><b class="Medium">$(@($items | Where-Object Risk -eq 'Medium').Count)</b>medium risk</div>
<div class="t"><b>$(if ($Scan.Boot.LastBootMs) { '{0:N1}s' -f ($Scan.Boot.LastBootMs / 1000) } else { 'n/a' })</b>last boot</div>
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
    $t2 = 'IT diagnostics  '
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
    Write-Host ('   {0,-18}{1,7}{2,13}{3,10}' -f 'Category', 'Total', 'Third-party', 'Flagged') -ForegroundColor DarkGray
    foreach ($g in $groups) {
        $tp = @($g.Group | Where-Object { -not $_.IsMicrosoft }).Count
        $fl = @($g.Group | Where-Object { $_.Risk -in 'High', 'Medium' }).Count
        Write-Host ('   {0,-18}{1,7}' -f $g.Name, $g.Count) -NoNewline -ForegroundColor Gray
        Write-Host ('{0,13}' -f $tp) -NoNewline -ForegroundColor $(if ($tp) { 'White' } else { 'DarkGray' })
        Write-Host ('{0,10}' -f $fl) -ForegroundColor $(if ($fl) { 'Yellow' } else { 'DarkGray' })
    }

    Write-PssRule 'Boot and performance'
    $b = $Scan.Boot
    if ($b.LastBootMs) {
        $col = if ($b.LastBootMs -gt 90000) { 'Red' } elseif ($b.LastBootMs -gt 45000) { 'Yellow' } else { 'Green' }
        Write-Host '   Last boot      ' -NoNewline -ForegroundColor DarkGray
        Write-Host ('{0:N1}s' -f ($b.LastBootMs / 1000)) -NoNewline -ForegroundColor $col
        Write-Host ('   (to desktop {0:N1}s, settling {1:N1}s)' -f ($b.LastMainMs / 1000), ($b.LastPostMs / 1000)) -ForegroundColor Gray
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
        $nm = $it.Name; if (-not $it.Enabled) { $nm = "$nm [off]" }
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
        Write-Host '   > ' -NoNewline -ForegroundColor Cyan
        $k = Read-PssKey
        switch -Regex ($k) {
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

function Get-PssVisible($Scan) {
    if ($script:PssShowMicrosoft) { return $Scan.Items }
    return @($Scan.Items | Where-Object { -not $_.IsMicrosoft -or $_.Risk -ne 'OK' })
}

function Show-PssBoot($Scan) {
    Write-PssHeader $Scan
    $b = $Scan.Boot
    if (-not $b.Available) { Write-Host ''; Write-Host "   $($b.Error)" -ForegroundColor Yellow }
    else {
        Write-PssRule 'Recent boots'
        Write-Host ('   {0,-18}{1,10}{2,12}{3,12}' -f 'When', 'Total', 'To desktop', 'Settling') -ForegroundColor DarkGray
        foreach ($x in @($b.Boots | Select-Object -First 10)) {
            $c = if ($x.BootSec -gt 90) { 'Red' } elseif ($x.BootSec -gt 45) { 'Yellow' } else { 'Green' }
            Write-Host ('   {0,-18}' -f ('{0:yyyy-MM-dd HH:mm}' -f $x.Time)) -NoNewline -ForegroundColor Gray
            Write-Host ('{0,10}' -f ('{0:N1}s' -f $x.BootSec)) -NoNewline -ForegroundColor $c
            Write-Host ('{0,12}{1,12}' -f ('{0:N1}s' -f $x.MainPathSec), ('{0:N1}s' -f $x.PostBootSec)) -ForegroundColor Gray
        }
        Write-PssRule 'What Windows says slowed boot (worst delay per item)'
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
    $heavy = @($Scan.Items | Where-Object { $_.Running -and $_.ProcCount } | Sort-Object MemoryMB -Descending | Select-Object -First 12)
    Write-PssRule 'Startup items using the most memory right now'
    foreach ($it in $heavy) {
        $c = if ($it.MemoryMB -ge 400) { 'Red' } elseif ($it.MemoryMB -ge 150) { 'Yellow' } else { 'Gray' }
        Write-Host ('   #{0,-5}' -f $it.Id) -NoNewline -ForegroundColor DarkGray
        Write-Host (Format-PssCell $it.Name 44) -NoNewline -ForegroundColor $(if ($it.IsMicrosoft) { 'DarkGray' } else { 'White' })
        Write-Host ('{0,8} MB' -f $it.MemoryMB) -NoNewline -ForegroundColor $c
        Write-Host ('{0,9}s CPU  {1} proc' -f $it.CpuSec, $it.ProcCount) -ForegroundColor DarkGray
    }
    Read-PssPick $Scan $null
}

function Show-PssCategories($Scan) {
    Write-PssHeader $Scan
    $groups = @((Get-PssVisible $Scan) | Group-Object Category | Sort-Object Name)
    Write-PssRule 'Categories'
    for ($i = 0; $i -lt $groups.Count; $i++) {
        Write-Host ('   [{0,2}] ' -f ($i + 1)) -NoNewline -ForegroundColor Cyan
        Write-Host ('{0,-18}{1,5} items' -f $groups[$i].Name, $groups[$i].Count) -ForegroundColor Gray
    }
    Write-Host ''
    Write-Host '   Category number > ' -NoNewline -ForegroundColor Cyan
    $k = Read-PssKey
    if ($k -match '^\d+$' -and [int]$k -ge 1 -and [int]$k -le $groups.Count) {
        $g = $groups[[int]$k - 1]
        Write-PssHeader $Scan
        $r = Write-PssTable $g.Group $g.Name
        Read-PssPick $Scan $r
    }
}

function Invoke-PssExportPrompt($Scan) {
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

function Start-PssConsole($Scan) {
    while ($true) {
        Write-PssHeader $Scan
        Write-PssDashboard $Scan
        $fl = @($Scan.Items | Where-Object { $_.Risk -in 'High', 'Medium' }).Count
        $tp = @($Scan.Items | Where-Object { -not $_.IsMicrosoft }).Count
        Write-PssRule 'Menu'
        $menu = @(
            @('1', "Review flagged items ($fl)"), @('5', 'Search'),
            @('2', "Third-party startup items ($tp)"), @('6', 'Boot performance / slowdowns'),
            @('3', 'Browse by category'), @('E', 'Export report (HTML/CSV/JSON)'),
            @('4', "All items incl. Microsoft ($($Scan.Items.Count))"), @('G', 'Open GUI view'),
            @('M', $(if ($script:PssShowMicrosoft) { 'Browse/search: hide Microsoft' } else { 'Browse/search: show Microsoft' })), @('R', 'Rescan')
        )
        for ($i = 0; $i -lt $menu.Count; $i += 2) {
            foreach ($m in $menu[$i], $menu[$i + 1]) {
                Write-Host ('   [' ) -NoNewline -ForegroundColor DarkGray
                Write-Host $m[0] -NoNewline -ForegroundColor Cyan
                Write-Host ('] ' + $m[1].PadRight(36)) -NoNewline -ForegroundColor Gray
            }
            Write-Host ''
        }
        Write-Host '   [' -NoNewline -ForegroundColor DarkGray; Write-Host 'Q' -NoNewline -ForegroundColor Cyan; Write-Host '] Quit' -NoNewline -ForegroundColor Gray
        Write-Host '          Type an item number at any prompt to see its details' -ForegroundColor DarkGray
        Write-Host ''
        Write-Host '   > ' -NoNewline -ForegroundColor Cyan
        $k = Read-PssKey
        if ($script:PssEof) { Write-Host ''; return }
        switch -Regex ($k) {
            '^1$' { Write-PssHeader $Scan; $r = Write-PssTable ($Scan.Items | Where-Object { $_.Risk -in 'High', 'Medium' }) 'Flagged items (high and medium risk)'; Read-PssPick $Scan $r ; break }
            '^2$' { Write-PssHeader $Scan; $r = Write-PssTable ($Scan.Items | Where-Object { -not $_.IsMicrosoft }) 'Third-party startup items'; Read-PssPick $Scan $r ; break }
            '^3$' { Show-PssCategories $Scan ; break }
            '^4$' { Write-PssHeader $Scan; $r = Write-PssTable $Scan.Items 'All startup items'; Read-PssPick $Scan $r ; break }
            '^5$' {
                Write-Host '   Search name, file, publisher or command > ' -NoNewline -ForegroundColor Cyan
                $q = Read-PssKey
                if ($q) {
                    $hits = @((Get-PssVisible $Scan) | Where-Object { "$($_.Name) $($_.ImagePath) $($_.Publisher) $($_.Command) $($_.Location) $($_.Description)" -like "*$q*" })
                    Write-PssHeader $Scan; $r = Write-PssTable $hits "Search: $q"; Read-PssPick $Scan $r
                }
            ; break }
            '^6$' { Show-PssBoot $Scan ; break }
            '^(?i)e$' { Invoke-PssExportPrompt $Scan ; break }
            '^(?i)g$' { $Scan = Show-PssGui $Scan ; break }
            '^(?i)m$' { $script:PssShowMicrosoft = -not $script:PssShowMicrosoft ; break }
            '^(?i)r$' { Write-PssHeader $null; $Scan = Invoke-PssConsoleScan ; break }
            '^(?i)(q|quit|exit)$' { Write-Host ''; return }
            '^\d+$' { Show-PssDetails $Scan ([int]$k) }
        }
    }
}

# ======================================================================================
#  GUI (WPF)
# ======================================================================================

function Show-PssGui($Scan, [string]$Snapshot) {
    # -Snapshot <png>: render the window off-screen to an image instead of showing it (self-test)
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
    <Style TargetType="CheckBox"><Setter Property="Foreground" Value="#C9CEDA"/><Setter Property="VerticalAlignment" Value="Center"/><Setter Property="Margin" Value="0,0,14,0"/></Style>
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
      <ComboBox x:Name="Cat" Width="160" DockPanel.Dock="Left" Margin="0,0,14,0"/>
      <CheckBox x:Name="HideMs" IsChecked="True" DockPanel.Dock="Left">Hide clean Microsoft items</CheckBox>
      <CheckBox x:Name="FlagOnly" DockPanel.Dock="Left">Flagged only</CheckBox>
      <Button x:Name="BtnExport" DockPanel.Dock="Right" Margin="0">Export report</Button>
      <Button x:Name="BtnRescan" DockPanel.Dock="Right">Rescan</Button>
    </DockPanel>
    <TextBlock x:Name="Banner" Grid.Row="2" Foreground="#FBBF24" Margin="0,0,0,6" TextWrapping="Wrap" Visibility="Collapsed"/>
    <TabControl Grid.Row="3" Background="Transparent" BorderThickness="0" Padding="0">
      <TabItem Header="Startup items">
        <Grid>
          <Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="5"/><RowDefinition Height="230"/></Grid.RowDefinitions>
          <DataGrid x:Name="Grid">
            <DataGrid.Columns>
              <DataGridTextColumn Header="#" Binding="{Binding Id}" Width="44"/>
              <DataGridTextColumn Header="Risk" Binding="{Binding Risk}" Width="64" SortMemberPath="RiskScore"/>
              <DataGridTextColumn Header="Category" Binding="{Binding Category}" Width="110"/>
              <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="230"/>
              <DataGridTextColumn Header="On" Binding="{Binding EnabledText}" Width="42"/>
              <DataGridTextColumn Header="Publisher" Binding="{Binding Publisher}" Width="170"/>
              <DataGridTextColumn Header="Signed" Binding="{Binding SignText}" Width="74"/>
              <DataGridTextColumn Header="File" Binding="{Binding ImagePath}" Width="*" MinWidth="260"/>
              <DataGridTextColumn Header="Boot delay" Binding="{Binding BootDelayText}" Width="76" SortMemberPath="BootDelayMs"/>
              <DataGridTextColumn Header="Memory" Binding="{Binding RunText}" Width="70" SortMemberPath="MemoryMB"/>
            </DataGrid.Columns>
          </DataGrid>
          <GridSplitter Grid.Row="1" HorizontalAlignment="Stretch" Background="Transparent"/>
          <Border Grid.Row="2" Background="{StaticResource Card}" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="6" Padding="10">
            <DockPanel>
              <StackPanel DockPanel.Dock="Bottom" Orientation="Horizontal" Margin="0,8,0,0">
                <Button x:Name="BtnLoc">Open location</Button><Button x:Name="BtnFile">Show file</Button>
                <Button x:Name="BtnVt">VirusTotal</Button><Button x:Name="BtnWeb">Search web</Button><Button x:Name="BtnCopy">Copy details</Button>
              </StackPanel>
              <TextBox x:Name="Detail" IsReadOnly="True" BorderThickness="0" Background="Transparent" FontFamily="Consolas" FontSize="12" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"/>
            </DockPanel>
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
    </TabControl>
    <TextBlock x:Name="Status" Grid.Row="4" Foreground="{StaticResource Mut}" Margin="2,6,0,0"/>
  </Grid>
</Window>
'@
    $win = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xaml))
    $ui = @{}
    foreach ($n in 'SubTitle', 'Tiles', 'Search', 'SearchHint', 'Cat', 'HideMs', 'FlagOnly', 'BtnExport', 'BtnRescan', 'Banner', 'Grid', 'Detail', 'BtnLoc', 'BtnFile', 'BtnVt', 'BtnWeb', 'BtnCopy', 'BootGrid', 'DelayGrid', 'Status') { $ui[$n] = $win.FindName($n) }
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

    $applyFilter = {
        $s = $state.Scan; if (-not $s) { return }
        $q = $ui.Search.Text; $cat = [string]$ui.Cat.SelectedItem
        $list = New-Object System.Collections.ArrayList
        foreach ($it in $s.Items) {
            if ($ui.HideMs.IsChecked -and $it.IsMicrosoft -and $it.Risk -eq 'OK') { continue }
            if ($ui.FlagOnly.IsChecked -and $it.Risk -notin 'High', 'Medium') { continue }
            if ($cat -and $cat -ne 'All categories' -and $it.Category -ne $cat) { continue }
            if ($q -and "$($it.Name) $($it.ImagePath) $($it.Publisher) $($it.Command) $($it.Location)" -notlike "*$q*") { continue }
            [void]$list.Add($it)
        }
        $ui.Grid.ItemsSource = $list
        $ui.Status.Text = "Showing $($list.Count) of $($s.Items.Count) items  -  scanned in {0:N1}s at {1:HH:mm:ss}" -f $s.Duration, $s.ScannedAt
    }

    $load = {
        $s = $state.Scan
        $ui.SubTitle.Text = "$($s.Computer)  -  $($s.OS)  -  " + $(if ($s.IsAdmin) { 'elevated' } else { 'not elevated' })
        $ui.Tiles.Children.Clear()
        [void]$ui.Tiles.Children.Add((& $makeTile $s.Items.Count 'startup items' '#E6E8EE'))
        [void]$ui.Tiles.Children.Add((& $makeTile @($s.Items | Where-Object { -not $_.IsMicrosoft }).Count 'third-party' '#E6E8EE'))
        [void]$ui.Tiles.Children.Add((& $makeTile @($s.Items | Where-Object Risk -eq 'High').Count 'high risk' '#FF7B7B'))
        [void]$ui.Tiles.Children.Add((& $makeTile @($s.Items | Where-Object Risk -eq 'Medium').Count 'medium risk' '#FBBF24'))
        [void]$ui.Tiles.Children.Add((& $makeTile $(if ($s.Boot.LastBootMs) { '{0:N1}s' -f ($s.Boot.LastBootMs / 1000) } else { 'n/a' }) 'last boot' '#38BDF8'))
        $cats = @('All categories') + @($s.Items | ForEach-Object Category | Sort-Object -Unique)
        $prev = $ui.Cat.SelectedItem
        $ui.Cat.ItemsSource = $cats
        $ui.Cat.SelectedItem = $(if ($prev -and $cats -contains $prev) { $prev } else { 'All categories' })
        $notes = @()
        if (-not $s.IsAdmin) { $notes += 'Not elevated: services, tasks, WMI and boot history may be incomplete. Run from an elevated PowerShell for full results.' }
        if ($s.NotLoadedProfiles) { $notes += 'Users not logged on (Run keys not read): ' + ($s.NotLoadedProfiles -join ', ') }
        $notes += $s.Errors
        $ui.Banner.Text = ($notes -join "`n"); $ui.Banner.Visibility = $(if ($notes) { 'Visible' } else { 'Collapsed' })
        $ui.BootGrid.ItemsSource = @($s.Boot.Boots)
        $ui.DelayGrid.ItemsSource = @($s.Boot.Delays)
        & $applyFilter
    }

    $sel = { $ui.Grid.SelectedItem }
    $ui.Grid.Add_SelectionChanged({ $it = & $sel; $ui.Detail.Text = $(if ($it) { Get-PssDetailText $it } else { '' }) })
    $ui.Search.Add_TextChanged({
            $ui.SearchHint.Visibility = $(if ($ui.Search.Text) { 'Collapsed' } else { 'Visible' })
            & $applyFilter
        })
    $ui.Cat.Add_SelectionChanged({ & $applyFilter })
    $ui.HideMs.Add_Click({ & $applyFilter })
    $ui.FlagOnly.Add_Click({ & $applyFilter })
    $ui.BtnLoc.Add_Click({ $it = & $sel; if ($it) { Open-PssLocation $it } })
    $ui.BtnFile.Add_Click({ $it = & $sel; if ($it) { Open-PssFolder $it } })
    $ui.BtnWeb.Add_Click({ $it = & $sel; if ($it) { Open-PssWebSearch $it } })
    $ui.BtnVt.Add_Click({ $it = & $sel; if ($it) { if (Open-PssVirusTotal $it) { $ui.Detail.Text = Get-PssDetailText $it } else { $ui.Status.Text = $script:PssHashError } } })
    $ui.BtnCopy.Add_Click({ $it = & $sel; if ($it) { [Windows.Clipboard]::SetText((Get-PssDetailText $it)); $ui.Status.Text = 'Details copied to clipboard.' } })
    $ui.Grid.Add_MouseDoubleClick({ $it = & $sel; if ($it) { Open-PssLocation $it } })
    $ui.BtnExport.Add_Click({
            $d = New-Object Microsoft.Win32.SaveFileDialog
            $d.Filter = 'HTML report|*.html|CSV|*.csv|JSON|*.json'
            $d.FileName = 'PAX-Startup-{0}-{1:yyyyMMdd-HHmm}' -f $state.Scan.Computer, $state.Scan.ScannedAt
            if ($d.ShowDialog($win)) {
                try { Export-PssReport $state.Scan $d.FileName; $ui.Status.Text = "Saved $($d.FileName)"; if ($d.FileName -match '\.html$') { Start-Process $d.FileName } }
                catch { [Windows.MessageBox]::Show("Could not save: $($_.Exception.Message)") | Out-Null }
            }
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
    $ui.BtnRescan.Add_Click({
            $ui.BtnRescan.IsEnabled = $false; $win.Cursor = [Windows.Input.Cursors]::AppStarting
            $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            foreach ($f in (Get-ChildItem function: | Where-Object { $_.Name -like '*-Pss*' })) {
                $iss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry $f.Name, $f.Definition))
            }
            $sync = [hashtable]::Synchronized(@{ Stage = 'Starting...'; Pct = 0 })
            $rs = [runspacefactory]::CreateRunspace($iss); $rs.Open()
            $rs.SessionStateProxy.SetVariable('PssVersion', $script:PssVersion)
            $ps = [powershell]::Create(); $ps.Runspace = $rs
            [void]$ps.AddScript('param($s) Invoke-PssScan -Status $s').AddArgument($sync)
            $state.Job = @{ PS = $ps; RS = $rs; Sync = $sync; Handle = $ps.BeginInvoke() }
            $timer.Start()
        })

    & $load
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
        $size = New-Object Windows.Size 1280, 800
        $wrap.Measure($size); $wrap.Arrange((New-Object Windows.Rect $size)); $wrap.UpdateLayout()
        if ($ui.Grid.Items.Count) { $ui.Grid.SelectedIndex = 0; $wrap.UpdateLayout() }
        $bmp = New-Object Windows.Media.Imaging.RenderTargetBitmap 1280, 800, 96, 96, ([Windows.Media.PixelFormats]::Pbgra32)
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
    param([switch]$Gui, [switch]$Report, [string]$Export)
    # Run the same way whatever the technician's profile sets (these only apply inside this call)
    Set-StrictMode -Off
    $ErrorActionPreference = 'Continue'
    $ProgressPreference = 'SilentlyContinue'
    $script:PssEof = $false
    $script:PssShowMicrosoft = $false
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

Start-PaxStartupScanner -Gui:$Gui -Report:$Report -Export $Export
