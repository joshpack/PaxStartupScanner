<#
    Off-screen checks for the GUI window chrome and remembered placement. Nothing is ever shown on screen,
    and the real settings folder is never touched (PSS_CONFIG_DIR points at a temp folder).
    Run from Windows PowerShell:  powershell -STA -ExecutionPolicy Bypass -File tools\Test-Window.ps1 [-OutDir <folder>]
#>
param([string]$OutDir = (Join-Path ([IO.Path]::GetTempPath()) 'pss-window-test'))

$main = Join-Path $PSScriptRoot '..\PaxStartupScanner.ps1'
$text = [IO.File]::ReadAllText($main)
$text = $text.Substring(0, $text.LastIndexOf('Start-PaxStartupScanner -Gui'))
. ([scriptblock]::Create($text))
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$cfg = Join-Path $OutDir 'config'
if (Test-Path -LiteralPath $cfg) { Remove-Item -LiteralPath $cfg -Recurse -Force }
$env:PSS_CONFIG_DIR = $cfg
$script:PssReadOnly = $false
$fails = 0
function Check([string]$Name, [bool]$Ok) { if ($Ok) { Write-Host "PASS  $Name" -ForegroundColor Green } else { Write-Host "FAIL  $Name" -ForegroundColor Red; $script:fails++ } }

# ---- the message dialog renders with its own title bar
$png = Join-Path $OutDir 'dialog.png'
[void](Show-PssMessage $null "Delete this startup entry?`n`nRun Key: Weather Widget`nIt is backed up first, so Undo changes can put it back." 'YesNo' 'Warning' -Snapshot $png)
Check 'dialog snapshot written' (Test-Path -LiteralPath $png)
$png2 = Join-Path $OutDir 'dialog-error.png'
[void](Show-PssMessage $null 'Could not save: access denied.' 'OK' 'Error' -Snapshot $png2)
Check 'error dialog snapshot written' (Test-Path -LiteralPath $png2)

# ---- the title bar XAML parses for both kinds of window and has the right buttons
foreach ($k in @(@{ R = $true; N = 'resizable' }, @{ R = $false; N = 'dialog' })) {
    $x = '<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"><Window.Resources>' + (Get-PssChromeXaml -Styles) + '</Window.Resources><Border x:Name="RootBorder"><DockPanel>' + $(if ($k.R) { Get-PssChromeXaml -Resizable } else { Get-PssChromeXaml -NoMinimize }) + '</DockPanel></Border></Window>'
    $w = [Windows.Markup.XamlReader]::Parse($x)
    Initialize-PssChrome $w
    Check "$($k.N): close button" ([bool]$w.FindName('CapClose'))
    Check "$($k.N): maximize only when resizable" ([bool]$w.FindName('CapMax') -eq $k.R)
    Check "$($k.N): caption buttons clickable in chrome" ([Windows.Shell.WindowChrome]::GetIsHitTestVisibleInChrome($w.FindName('CapClose')))
    if ($k.R) {
        $w.WindowState = 'Maximized'; & $w.Tag $w
        Check 'maximized: content padded inside the screen' ($w.FindName('RootBorder').Margin.Top -gt 0)
        Check 'maximized: restore glyph' ($w.FindName('CapMax').ToolTip -eq 'Restore down')
        $w.WindowState = 'Normal'; & $w.Tag $w
        Check 'normal: no padding' ($w.FindName('RootBorder').Margin.Top -eq 0)
    }
}

# ---- placement save / load round trip (windows are created but never shown)
$screens = @((New-Object Windows.Rect 0, 0, 1920, 1040), (New-Object Windows.Rect 1920, 0, 2560, 1400))
$new = { $w = New-Object Windows.Window; $w.MinWidth = 900; $w.MinHeight = 560; $w.Width = 1000; $w.Height = 700; $w }
Check 'nothing saved yet: nothing restored' (-not (Restore-PssPlacement (& $new) $screens))
$a = & $new; $a.Left = 2100; $a.Top = 120; $a.Width = 1300; $a.Height = 820
Check 'saved' (Save-PssPlacement $a)
Check 'file in the config folder' (Test-Path -LiteralPath (Join-Path $cfg 'window.json'))
$b = & $new
Check 'restored' (Restore-PssPlacement $b $screens)
Check 'same position and size' ($b.Left -eq 2100 -and $b.Top -eq 120 -and $b.Width -eq 1300 -and $b.Height -eq 820 -and $b.WindowStartupLocation -eq 'Manual')
Check 'not maximized' ($b.WindowState -eq 'Normal')
# maximized flag
[IO.File]::WriteAllText((Join-Path $cfg 'window.json'), '{"Left":100,"Top":80,"Width":1200,"Height":760,"Maximized":true}')
$c = & $new
Check 'maximized restored' ((Restore-PssPlacement $c $screens) -and $c.WindowState -eq 'Maximized' -and $c.Left -eq 100)
# smaller than the minimum size is clamped
[IO.File]::WriteAllText((Join-Path $cfg 'window.json'), '{"Left":100,"Top":80,"Width":400,"Height":300,"Maximized":false}')
$c = & $new
Check 'clamped to minimum size' ((Restore-PssPlacement $c $screens) -and $c.Width -eq 900 -and $c.Height -eq 560)
# off every screen: ignored
foreach ($p in @('{"Left":-30000,"Top":-30000,"Width":1200,"Height":760,"Maximized":false}', '{"Left":5000,"Top":100,"Width":1200,"Height":760,"Maximized":false}', '{"Left":100,"Top":1500,"Width":1200,"Height":760,"Maximized":false}')) {
    [IO.File]::WriteAllText((Join-Path $cfg 'window.json'), $p)
    $c = & $new
    Check "off-screen ignored: $p" (-not (Restore-PssPlacement $c $screens) -and [double]::IsNaN($c.Left) -and $c.Width -eq 1000)
}
# damaged file: ignored
[IO.File]::WriteAllText((Join-Path $cfg 'window.json'), '{ not json')
Check 'damaged file ignored' (-not (Restore-PssPlacement (& $new) $screens))
# read-only mode writes nothing
Remove-Item -LiteralPath (Join-Path $cfg 'window.json')
$script:PssReadOnly = $true
Check 'read-only: not saved' (-not (Save-PssPlacement $a) -and -not (Test-Path -LiteralPath (Join-Path $cfg 'window.json')))
$script:PssReadOnly = $false
# the real screens are readable
$real = @(Get-PssScreens)
Check "screens found ($($real.Count))" ($real.Count -ge 1)

Remove-Item -LiteralPath $cfg -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
if ($fails) { Write-Host "$fails check(s) failed" -ForegroundColor Red; exit 1 } else { Write-Host 'All checks passed' -ForegroundColor Green; exit 0 }
