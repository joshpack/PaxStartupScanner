<#
    Renders the README screenshots from synthetic sample data (no real machine data), off-screen.
    Run from Windows PowerShell:  powershell -STA -ExecutionPolicy Bypass -File tools\Render-Screenshots.ps1
#>
param([string]$OutDir = (Join-Path $PSScriptRoot '..\docs\screenshots'))

$main = Join-Path $PSScriptRoot '..\PaxStartupScanner.ps1'
$text = [IO.File]::ReadAllText($main)
$text = $text.Substring(0, $text.LastIndexOf('Start-PaxStartupScanner -Gui'))
. ([scriptblock]::Create($text))
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

# ---------------------------------------------------------------- sample data
Initialize-Pss
$now = Get-Date
function New-Sample {
    param($Category, $Name, $Command, $Image, [string]$Pub = '', [string]$Sign = 'Valid', [bool]$Ms = $false,
        [bool]$Exists = $true, $User = 'CONTOSO\alex', $Trigger = 'Logon', $Location = '', [int]$Mem = 0, [int]$Cpu = 0,
        [int]$Delay = 0, [bool]$Enabled = $true, $Kind = '', $Desc = '', [bool]$NoImage = $false, $Extra = '', [int]$AgeDays = 400, $ValueName = '')
    $p = @{ Category = $Category; Name = $Name; Location = $Location; Command = $Command; Enabled = $Enabled; User = $User; Trigger = $Trigger; Kind = $Kind; Extra = $Extra; ValueName = $ValueName }
    if ($NoImage) { $p.NoImage = $true } else { $p.Image = $Image }
    # How the sample could be changed (drives the Disable/Delete buttons; nothing is ever changed here)
    $p.Op = switch ($Category) {
        'Run Key' { @{ Type = 'RegValue'; Key = $Location; Name = $Name; ApprovedRoot = 'HKU\S-1-5-21-0'; ApprovedKind = 'Run' } }
        'Startup Folder' { @{ Type = 'File'; Path = $Location; ApprovedRoot = 'HKU\S-1-5-21-0'; ApprovedName = 'sample.lnk' } }
        'Scheduled Task' { @{ Type = 'Task'; Path = $Name } }
        'Service' { @{ Type = 'Service'; Name = 'sample'; Start = 'auto' } }
        'Driver' { @{ Type = 'Service'; Name = 'sample'; Start = $(if ($Trigger -like 'Boot*') { 'boot' } else { 'system' }) } }
        'WMI' { @{ Type = 'Wmi'; Class = 'CommandLineEventConsumer'; Name = $Name } }
        'Winlogon' { @{ Type = 'ListPart'; Key = $Location; Name = 'Shell'; Part = $Command; Sep = ','; Default = '' } }
        'Store App' { @{ Type = 'StoreApp'; Key = $Location; ByPolicy = $false } }
        default { @{ Type = 'RegValue'; Key = $Location; Name = $Name } }
    }
    Add-PssItem @p
    $it = $script:PssItems[$script:PssItems.Count - 1]
    if ($Image) { $it.ImagePath = $Image }
    if (-not $NoImage) {
        $it.FileExists = $Exists
        if ($Exists) {
            $it.Size = 1MB + ($Name.Length * 377111); $it.Created = $now.AddDays(-$AgeDays); $it.Modified = $now.AddDays(-[Math]::Min($AgeDays, 30))
            $it.SignStatus = $Sign; $it.Company = $Pub; $it.Description = $Desc; $it.Version = '4.2.1.0'
            if ($Sign -eq 'Valid') { $it.Signer = "CN=$Pub, O=$Pub"; $it.Publisher = $Pub }
            elseif ($Pub) { $it.Publisher = "$Pub (not verified)" } else { $it.Publisher = '(unknown publisher)' }
        } else { $it.Publisher = '(file missing)' }
        $it.IsMicrosoft = $Ms
        $it.SignText = switch ($it.SignStatus) { 'Valid' { 'Signed' } 'NotSigned' { 'Unsigned' } '' { '-' } default { $it.SignStatus } }
    } else { $it.Publisher = $Pub; $it.SignText = 'n/a'; $it.IsMicrosoft = $Ms }
    if ($Mem) { $it.Running = $true; $it.ProcCount = 1; $it.MemoryMB = $Mem; $it.CpuSec = $Cpu; $it.RunText = "$Mem MB" }
    if ($Delay) { $it.BootDelayMs = $Delay; $it.BootDelayCount = 3; $it.BootDelayText = '{0:N1}s' -f ($Delay / 1000) }
    $it.Impact = if ($Delay -ge 3000 -or $Mem -ge 400) { 'High' } elseif ($Delay -ge 1000 -or $Mem -ge 150) { 'Medium' } elseif ($Mem -or $Delay) { 'Low' } else { '' }
    Measure-PssRisk $it
    Set-PssPermissions $it
    Set-PssFacets $it
}
# Sample timed restarts for the Boot tests tab
function Get-PssBootTests {
    $mk = { param($when, $label, $b, $s, $procs, $top) [pscustomobject]@{ Id = $when; Boot = [datetime]$when; When = ([datetime]$when).ToString('yyyy-MM-dd HH:mm'); Label = $label; BootToIdleSec = $b; SignInToIdleSec = $s; TotalSec = $b + $s; BootText = (Format-PssSec $b); SignInText = (Format-PssSec $s); TotalText = (Format-PssSec ($b + $s)); SignedInFirst = $false; ProcessesStarted = $procs; TopProcesses = $top; Notes = '' } }
    @(
        (& $mk $now.AddHours(-1).ToString('yyyy-MM-dd HH:mm') 'After changes' 38.4 27.9 41 @([pscustomobject]@{ Name = 'OneDrive.exe'; CpuSec = 6.0 }, [pscustomobject]@{ Name = 'Steam.exe'; CpuSec = 4.1 }))
        (& $mk $now.AddHours(-3).ToString('yyyy-MM-dd HH:mm') 'Before changes' 41.2 70.3 64 @([pscustomobject]@{ Name = 'Discord.exe'; CpuSec = 22.1 }, [pscustomobject]@{ Name = 'svchost.exe'; CpuSec = 14.0 }, [pscustomobject]@{ Name = 'Steam.exe'; CpuSec = 12.4 }))
    )
}
function Get-PssChangeHistory { @([pscustomobject]@{ Time = $now.AddHours(-2); Action = 'Disable'; Category = 'Run Key'; Name = 'Discord'; Undone = $false }, [pscustomobject]@{ Time = $now.AddHours(-2).AddMinutes(1); Action = 'Delete'; Category = 'Scheduled Task'; Name = '\OneDrive Sync Task'; Undone = $false }) }
function Get-PssBootTestState { $null }
# Sample undo history for the Undo tab screenshot (the real list reads %ProgramData%\PaxStartupScanner\Backups)
function Get-PssUndoRecords {
    @(
        [pscustomobject]@{ When = $now.AddMinutes(-2).ToString('yyyy-MM-dd HH:mm'); Action = 'Delete'; Category = 'Scheduled Task'; Name = '\OneDrive Sync Task'; Location = 'Task Scheduler \OneDrive Sync Task'; RunBy = 'CONTOSO\it-admin'; Steps = @() }
        [pscustomobject]@{ When = $now.AddMinutes(-4).ToString('yyyy-MM-dd HH:mm'); Action = 'Delete'; Category = 'WMI'; Name = 'PerfCounterUpdate'; Location = 'root\subscription CommandLineEventConsumer'; RunBy = 'CONTOSO\it-admin'; Steps = @() }
        [pscustomobject]@{ When = $now.AddMinutes(-6).ToString('yyyy-MM-dd HH:mm'); Action = 'Disable'; Category = 'Run Key'; Name = 'Spotify'; Location = 'HKU\...\Run'; RunBy = 'CONTOSO\it-admin'; Steps = @() }
        [pscustomobject]@{ When = $now.AddMinutes(-7).ToString('yyyy-MM-dd HH:mm'); Action = 'Disable'; Category = 'Service'; Name = 'Printer Helper Service (PrnHelper)'; Location = 'HKLM\SYSTEM\CurrentControlSet\Services\PrnHelper'; RunBy = 'CONTOSO\it-admin'; Steps = @() }
    )
}
$hku = 'HKU\S-1-5-21-1004336348-1177238915-682003330-1104\Software\Microsoft\Windows\CurrentVersion\Run'
$hklm = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

New-Sample 'Run Key' 'WindowsUpdateHelper' 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA' $ps -Pub 'Microsoft Windows' -Ms $true -Location $hku -ValueName 'WindowsUpdateHelper' -Desc 'Windows PowerShell'
New-Sample 'Scheduled Task' '\OneDrive Sync Task' 'C:\Users\alex\AppData\Local\Temp\svchost.exe -k netsvcs' 'C:\Users\alex\AppData\Local\Temp\svchost.exe' -Sign 'NotSigned' -Trigger 'Logon, Time' -Location 'Task Scheduler \OneDrive Sync Task' -Kind 'Task' -AgeDays 2 -Mem 42 -Extra 'Author: alex; Hidden task'
New-Sample 'WMI' 'PerfCounterUpdate' 'wscript.exe //B C:\ProgramData\perf\update.vbs' 'C:\ProgramData\perf\update.vbs' -Sign 'NotSigned' -Trigger "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'" -Location 'root\subscription CommandLineEventConsumer' -Kind 'Modified' -User '' -AgeDays 2
New-Sample 'Startup Folder' 'Weather Widget' '"C:\Users\alex\AppData\Roaming\WeatherNow\weathernow.exe" /tray' 'C:\Users\alex\AppData\Roaming\WeatherNow\weathernow.exe' -Pub 'WeatherNow Ltd' -Sign 'NotSigned' -Location 'C:\Users\alex\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Weather Widget.lnk' -Kind 'File' -Mem 88 -Desc 'WeatherNow tray widget'
New-Sample 'Service' 'Printer Helper Service (PrnHelper)' 'C:\Program Files\Printer Tools\prnhelper.exe' 'C:\Program Files\Printer Tools\prnhelper.exe' -Pub 'Printer Tools' -Sign 'NotSigned' -User 'LocalSystem' -Trigger 'Automatic' -Location 'HKLM\SYSTEM\CurrentControlSet\Services\PrnHelper' -Delay 2800 -Mem 35 -Extra 'Status: Running; Account: LocalSystem'
New-Sample 'Run Key' 'Adobe Acrobat Synchronizer' '"C:\Program Files\Adobe\Acrobat DC\Acrobat\AdobeCollabSync.exe"' 'C:\Program Files\Adobe\Acrobat DC\Acrobat\AdobeCollabSync.exe' -Exists $false -Location $hklm -User 'All users'
New-Sample 'Run Key' 'Discord' '"C:\Users\alex\AppData\Local\Discord\Update.exe" --processStart Discord.exe' 'C:\Users\alex\AppData\Local\Discord\Update.exe' -Pub 'Discord Inc.' -Location $hku -Mem 412 -Delay 4200 -Desc 'Discord'
New-Sample 'Run Key' 'Steam' '"C:\Program Files (x86)\Steam\steam.exe" -silent' 'C:\Program Files (x86)\Steam\steam.exe' -Pub 'Valve Corp.' -Location $hku -Mem 236 -Delay 1600 -Desc 'Steam'
New-Sample 'Run Key' 'Spotify' '"C:\Users\alex\AppData\Roaming\Spotify\Spotify.exe" --autostart --minimized' 'C:\Users\alex\AppData\Roaming\Spotify\Spotify.exe' -Pub 'Spotify AB' -Location $hku -Mem 188 -Enabled $false -Desc 'Spotify'
New-Sample 'Run Key' 'LogiOptions' '"C:\Program Files\Logitech\LogiOptionsPlus\logioptionsplus_agent.exe" /launchGui' 'C:\Program Files\Logitech\LogiOptionsPlus\logioptionsplus_agent.exe' -Pub 'Logitech Inc' -Location $hklm -User 'All users' -Mem 64
New-Sample 'Run Key' 'Zoom' '"C:\Users\alex\AppData\Roaming\Zoom\bin\Zoom.exe" --autostart' 'C:\Users\alex\AppData\Roaming\Zoom\bin\Zoom.exe' -Pub 'Zoom Communications, Inc.' -Location $hku
New-Sample 'Run Key' 'OneDrive' '"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background' 'C:\Program Files\Microsoft OneDrive\OneDrive.exe' -Pub 'Microsoft Corporation' -Ms $true -Location $hku -Mem 96
New-Sample 'Run Key' 'SecurityHealth' '%windir%\system32\SecurityHealthSystray.exe' 'C:\Windows\System32\SecurityHealthSystray.exe' -Pub 'Microsoft Windows' -Ms $true -Location $hklm -User 'All users' -Mem 9
New-Sample 'Startup Folder' 'Dropbox' '"C:\Program Files (x86)\Dropbox\Client\Dropbox.exe" /systemstartup' 'C:\Program Files (x86)\Dropbox\Client\Dropbox.exe' -Pub 'Dropbox, Inc' -Location 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\Dropbox.lnk' -Kind 'File' -User 'All users' -Mem 172
New-Sample 'Scheduled Task' '\GoogleUpdateTaskMachineCore' '"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /c' 'C:\Program Files (x86)\Google\Update\GoogleUpdate.exe' -Pub 'Google LLC' -Trigger 'Logon, Schedule' -User 'SYSTEM' -Location 'Task Scheduler \GoogleUpdateTaskMachineCore' -Kind 'Task'
New-Sample 'Scheduled Task' '\Adobe Acrobat Update Task' '"C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\AdobeARM.exe"' 'C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\AdobeARM.exe' -Pub 'Adobe Inc.' -Trigger 'Logon, Schedule' -Location 'Task Scheduler \Adobe Acrobat Update Task' -Kind 'Task'
New-Sample 'Service' 'NVIDIA Display Container LS (NVDisplay.ContainerLocalSystem)' 'C:\Windows\System32\DriverStore\FileRepository\nv_dispi.inf_amd64\Display.NvContainer\NVDisplay.Container.exe -s NVDisplay.ContainerLocalSystem' 'C:\Windows\System32\DriverStore\FileRepository\nv_dispi.inf_amd64\Display.NvContainer\NVDisplay.Container.exe' -Pub 'NVIDIA Corporation' -User 'LocalSystem' -Trigger 'Automatic' -Location 'HKLM\SYSTEM\CurrentControlSet\Services\NVDisplay.ContainerLocalSystem' -Mem 38 -Delay 1100
New-Sample 'Service' 'Dropbox Update Service (dbupdate)' '"C:\Program Files (x86)\Dropbox\Update\DropboxUpdate.exe" /svc' 'C:\Program Files (x86)\Dropbox\Update\DropboxUpdate.exe' -Pub 'Dropbox, Inc' -User 'LocalSystem' -Trigger 'Automatic (delayed)' -Location 'HKLM\SYSTEM\CurrentControlSet\Services\dbupdate'
New-Sample 'Driver' 'Logitech LampArray Service (logi_lamparray_service)' 'System32\drivers\logi_lamparray.sys' 'C:\Windows\System32\drivers\logi_lamparray.sys' -Pub 'Logitech Inc' -User '' -Trigger 'System start' -Location 'HKLM\SYSTEM\CurrentControlSet\Services\logi_lamparray_service'
New-Sample 'Store App' 'SpotifyAB.SpotifyMusic (SpotifyStartupTask)' 'SpotifyAB.SpotifyMusic_zpdnekdrzrea0' $null -Pub 'Store package' -NoImage $true -Enabled $false -Location 'HKU\...\AppModel\SystemAppData\SpotifyAB.SpotifyMusic_zpdnekdrzrea0\SpotifyStartupTask'
foreach ($n in 'Windows Defender Scheduled Scan', 'UpdateOrchestrator\Schedule Scan', 'WindowsUpdate\Scheduled Start', 'Time Synchronization\SynchronizeTime', 'Defrag\ScheduledDefrag', 'Diagnosis\Scheduled', 'DiskCleanup\SilentCleanup', 'Maintenance\WinSAT') {
    New-Sample 'Scheduled Task' "\Microsoft\Windows\$n" 'C:\Windows\System32\svchost.exe' 'C:\Windows\System32\svchost.exe' -Pub 'Microsoft Windows' -Ms $true -Trigger 'Schedule' -User 'SYSTEM' -Location "Task Scheduler \Microsoft\Windows\$n" -Kind 'Task'
}
foreach ($n in 'Windows Update (wuauserv)', 'Windows Defender Firewall (mpssvc)', 'Print Spooler (Spooler)', 'Windows Audio (Audiosrv)', 'DHCP Client (Dhcp)', 'DNS Client (Dnscache)', 'Windows Event Log (EventLog)', 'Task Scheduler (Schedule)') {
    New-Sample 'Service' $n 'C:\Windows\system32\svchost.exe -k netsvcs -p' 'C:\Windows\System32\svchost.exe' -Pub 'Microsoft Windows' -Ms $true -Trigger 'Automatic' -User 'LocalSystem' -Location 'HKLM\SYSTEM\CurrentControlSet\Services'
}
foreach ($n in 'disk', 'volmgr', 'tcpip', 'ndis', 'acpi', 'pci', 'storahci', 'mountmgr') {
    New-Sample 'Driver' "$n ($n)" "System32\drivers\$n.sys" "C:\Windows\System32\drivers\$n.sys" -Pub 'Microsoft Windows' -Ms $true -Trigger 'Boot start' -User '' -Location "HKLM\SYSTEM\CurrentControlSet\Services\$n"
}
New-Sample 'Winlogon' 'Winlogon\Userinit' 'C:\Windows\system32\userinit.exe' 'C:\Windows\System32\userinit.exe' -Pub 'Microsoft Windows' -Ms $true -User 'All users' -Location 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Kind 'Default'
New-Sample 'Winlogon' 'Winlogon\Shell' 'explorer.exe' 'C:\Windows\explorer.exe' -Pub 'Microsoft Windows' -Ms $true -User 'All users' -Location 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Kind 'Default'

$rank = @{ High = 0; Medium = 1; Low = 2; OK = 3 }
$items = @($script:PssItems | Sort-Object @{ E = { $rank[$_.Risk] } }, @{ E = { $_.IsMicrosoft } }, Category, Name)
$i = 1; foreach ($it in $items) { $it.Id = $i++ }
$boots = @(); $r = New-Object Random 7
for ($d = 0; $d -lt 10; $d++) { $tot = [math]::Round(38 + $r.NextDouble() * 30, 1); $main = [math]::Round($tot * 0.45, 1); $boots += [pscustomobject]@{ Time = $now.AddDays(-$d * 1.7).Date.AddHours(8).AddMinutes($d * 7); BootSec = $tot; MainPathSec = $main; PostBootSec = [math]::Round($tot - $main, 1); Degraded = $true } }
$delays = @(
    [pscustomobject]@{ Time = $now.AddDays(-1); Type = 'App'; Name = 'Update.exe'; FriendlyName = 'Discord'; TotalMs = 6100; DegradationMs = 4200 }
    [pscustomobject]@{ Time = $now.AddDays(-1); Type = 'Service'; Name = 'PrnHelper'; FriendlyName = 'Printer Helper Service'; TotalMs = 3900; DegradationMs = 2800 }
    [pscustomobject]@{ Time = $now.AddDays(-3); Type = 'App'; Name = 'steam.exe'; FriendlyName = 'Steam'; TotalMs = 2400; DegradationMs = 1600 }
    [pscustomobject]@{ Time = $now.AddDays(-3); Type = 'Driver'; Name = 'nvlddmkm.sys'; FriendlyName = 'NVIDIA Windows Kernel Mode Driver'; TotalMs = 1500; DegradationMs = 1100 }
)
$scan = [pscustomobject]@{
    Items = $items; Errors = @(); Computer = 'WORKSTATION-07'; OS = 'Windows 11 Pro 24H2 (build 26100)'; IsAdmin = $true; Users = @('CONTOSO\alex')
    NotLoadedProfiles = @(); Uptime = New-TimeSpan -Days 2 -Hours 5 -Minutes 41; Duration = 3.8; ScannedAt = $now; Version = $script:PssVersion
    Boot = [pscustomobject]@{ Available = $true; Error = ''; Boots = $boots; Delays = $delays; LastBootMs = $boots[0].BootSec * 1000; LastMainMs = $boots[0].MainPathSec * 1000; LastPostMs = $boots[0].PostBootSec * 1000; LastBootTime = $boots[0].Time }
}

# ---------------------------------------------------------------- console capture
$script:Segs = New-Object System.Collections.Generic.List[object]
function Write-Host { param([Parameter(Position = 0)]$Object = '', [switch]$NoNewline, $ForegroundColor = 'Gray', $BackgroundColor)
    $script:Segs.Add([pscustomobject]@{ T = [string]$Object; C = [string]$ForegroundColor; NL = -not $NoNewline }) }
function Clear-Host { }
function Get-PssWidth { 117 }
$script:NextKey = ''
function Read-PssKey { $script:Segs.Add([pscustomobject]@{ T = $script:NextKey; C = 'White'; NL = $true }); return $script:NextKey }

$pal = @{ Black = '#0C0C0C'; DarkBlue = '#0037DA'; DarkGreen = '#13A10E'; DarkCyan = '#3A96DD'; DarkRed = '#C50F1F'; DarkMagenta = '#881798'; DarkYellow = '#C19C00'; Gray = '#CCCCCC'
    DarkGray = '#767676'; Blue = '#3B78FF'; Green = '#16C60C'; Cyan = '#61D6D6'; Red = '#E74856'; Magenta = '#B4009E'; Yellow = '#F9F1A5'; White = '#F2F2F2' }
$bc = New-Object Windows.Media.BrushConverter
function Save-Console([string]$Path, [string]$Title) {
    $tb = New-Object Windows.Controls.TextBlock
    $tb.FontFamily = 'Cascadia Mono, Consolas'; $tb.FontSize = 14; $tb.Background = $bc.ConvertFrom('#0C0C0C')
    foreach ($s in $script:Segs) {
        $run = New-Object Windows.Documents.Run ($s.T -replace "`r", '')
        $c = if ($pal.ContainsKey($s.C)) { $pal[$s.C] } else { '#CCCCCC' }
        $run.Foreground = $bc.ConvertFrom($c)
        $tb.Inlines.Add($run)
        if ($s.NL) { $tb.Inlines.Add((New-Object Windows.Documents.LineBreak)) }
    }
    $bar = New-Object Windows.Controls.TextBlock
    $bar.Text = $Title; $bar.Foreground = $bc.ConvertFrom('#CCCCCC'); $bar.FontFamily = 'Segoe UI'; $bar.FontSize = 12; $bar.Padding = '14,8,0,8'; $bar.Background = $bc.ConvertFrom('#202020')
    $sp = New-Object Windows.Controls.StackPanel; $sp.Background = $bc.ConvertFrom('#0C0C0C')
    $tb.Margin = '10,6,10,14'
    [void]$sp.Children.Add($bar); [void]$sp.Children.Add($tb)
    $sp.Measure((New-Object Windows.Size ([double]::PositiveInfinity), ([double]::PositiveInfinity)))
    $w = [Math]::Ceiling($sp.DesiredSize.Width); $h = [Math]::Ceiling($sp.DesiredSize.Height)
    $sp.Arrange((New-Object Windows.Rect 0, 0, $w, $h)); $sp.UpdateLayout()
    $bmp = New-Object Windows.Media.Imaging.RenderTargetBitmap $w, $h, 96, 96, ([Windows.Media.PixelFormats]::Pbgra32)
    $bmp.Render($sp)
    $enc = New-Object Windows.Media.Imaging.PngBitmapEncoder; $enc.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bmp))
    $fs = [IO.File]::Create($Path); $enc.Save($fs); $fs.Close()
    $script:Segs.Clear()
}

$title = 'Administrator: Windows PowerShell'
# 1) dashboard + menu
$script:NextKey = 'q'
Start-PssConsole $scan
Save-Console (Join-Path $OutDir 'console-dashboard.png') $title
# 2) flagged list
Write-PssHeader $scan
[void](Write-PssTable ($scan.Items | Where-Object { $_.Risk -in 'High', 'Medium' }) 'Flagged items (high and medium risk)' -NoPaging)
Write-Host ''
Write-Host '   Item # for details, or Enter to go back > ' -NoNewline -ForegroundColor Cyan
Write-Host '1' -ForegroundColor White
Save-Console (Join-Path $OutDir 'console-flagged.png') $title
# 3) details
$script:NextKey = ''
Show-PssDetails $scan 1
Save-Console (Join-Path $OutDir 'console-details.png') $title
# 4) boot performance
Show-PssBoot $scan
Save-Console (Join-Path $OutDir 'console-boot.png') $title
# 5) GUI, startup items tab and Undo tab
[void](Show-PssGui $scan -Snapshot (Join-Path $OutDir 'gui.png'))
[void](Show-PssGui $scan -Snapshot (Join-Path $OutDir 'gui-boot-tests.png') -SnapshotTab 1)
[void](Show-PssGui $scan -Snapshot (Join-Path $OutDir 'gui-undo.png') -SnapshotTab 3)
Get-ChildItem $OutDir -Filter *.png | ForEach-Object { '{0}  {1:N0} KB' -f $_.Name, ($_.Length / 1KB) }
