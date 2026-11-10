<#
    Checks "update before start": a copy run from a file replaces itself with a newer release and runs that instead.
    Everything happens in a temp folder against a fake GitHub API on a local HttpListener (127.0.0.1); the real
    release, the installed copy and this repo's file are never touched, and nothing is shown on screen.
    Run from Windows PowerShell or pwsh:  powershell -ExecutionPolicy Bypass -File tools\Test-Update.ps1
#>
$main = Join-Path $PSScriptRoot '..\pxdStartupScanner.ps1'
$fails = 0
function Check([string]$Name, [bool]$Ok) { if ($Ok) { Write-Host "PASS  $Name" -ForegroundColor Green } else { Write-Host "FAIL  $Name" -ForegroundColor Red; $script:fails++ } }

$t = Join-Path ([IO.Path]::GetTempPath()) ('pss-update-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $t | Out-Null
$saved = @{}
foreach ($n in 'PXD_UPDATE_API', 'PXD_NO_UPDATE', 'PXD_INMEMORY', 'PXD_UPDATED_FROM', 'PSS_READONLY', 'PSS_CONFIG_DIR') { $saved[$n] = [Environment]::GetEnvironmentVariable($n); [Environment]::SetEnvironmentVariable($n, $null) }
$server = $null; $listener = $null
try {
    $src = [IO.File]::ReadAllText($main)
    $cur = [regex]::Match($src, "PssVersion = '([^']+)'").Groups[1].Value
    $copy = Join-Path $t 'pxdStartupScanner.ps1'
    [IO.File]::WriteAllText($copy, $src)

    # ---- the fake GitHub: answers from a shared table the checks change as they go
    $port = Get-Random -Minimum 41000 -Maximum 49000
    $prefix = "http://127.0.0.1:$port/"
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($prefix); $listener.Start()
    $fake = [hashtable]::Synchronized(@{ Tag = "v$cur"; File = [byte[]]@(); Sum = $null; Requests = 0 })
    $ps = [powershell]::Create()
    [void]$ps.AddScript({
            param($listener, $fake, $prefix)
            while ($listener.IsListening) {
                try { $ctx = $listener.GetContext() } catch { return }
                $fake.Requests++
                $path = $ctx.Request.Url.AbsolutePath
                $body = [byte[]]@()
                if ($path -eq '/repos/joshpack/pxdStartupScanner/releases/latest') {
                    $assets = @(@{ name = 'pxdStartupScanner.ps1'; browser_download_url = "${prefix}file" })
                    if ($fake.Sum) { $assets += @{ name = 'pxdStartupScanner.ps1.sha256'; browser_download_url = "${prefix}sum" } }
                    $body = [Text.Encoding]::UTF8.GetBytes((@{ tag_name = $fake.Tag; assets = $assets } | ConvertTo-Json -Depth 4))
                } elseif ($path -eq '/file') { $body = $fake.File }
                elseif ($path -eq '/sum') { $body = [Text.Encoding]::ASCII.GetBytes([string]$fake.Sum) }
                else { $ctx.Response.StatusCode = 404 }
                $ctx.Response.OutputStream.Write($body, 0, $body.Length); $ctx.Response.Close()
            }
        }).AddArgument($listener).AddArgument($fake).AddArgument($prefix)
    $server = $ps.BeginInvoke()
    $env:PXD_UPDATE_API = $prefix.TrimEnd('/')

    # ---- the functions, from the temp copy, with the re-run recorded instead of started
    $text = [IO.File]::ReadAllText($copy)
    . ([scriptblock]::Create($text.Substring(0, $text.LastIndexOf('Start-pxdStartupScanner -Gui'))))
    $script:PssReadOnly = $false; $script:PssInMemory = $false
    $script:Reran = $null
    function Invoke-PssRerun([string]$Path, [hashtable]$Params) { $script:Reran = @{ Path = $Path; Params = $Params; From = $env:PXD_UPDATED_FROM } }
    $params = @{ Gui = $false; Report = $true; Export = 'C:\x\report.html'; ReadOnly = $false }
    function Get-Sha([byte[]]$b) { $s = [Security.Cryptography.SHA256]::Create(); try { ([BitConverter]::ToString($s.ComputeHash($b))).Replace('-', '').ToLowerInvariant() } finally { $s.Dispose() } }
    $newVer = '9.8.7'
    $newText = $text.Replace("`$script:PssVersion = '$cur'", "`$script:PssVersion = '$newVer'")
    $newBytes = [Text.Encoding]::ASCII.GetBytes($newText)
    function Unchanged { ([IO.File]::ReadAllText($copy) -eq $text) -and -not (Test-Path -LiteralPath "$copy.pxdnew") -and -not (Test-Path -LiteralPath "$copy.pxdold") }

    # ---- no update
    $r = Update-PssBeforeStart $params $copy
    Check 'same version on GitHub: nothing changes' (-not $r -and (Unchanged) -and -not $script:Reran -and $fake.Requests -eq 1)
    $fake.Tag = "v$newVer"; $fake.File = $newBytes; $fake.Sum = (Get-Sha $newBytes) + '  pxdStartupScanner.ps1'
    $n = $fake.Requests
    Check 'irm | iex (no file): no check at all' (-not (Update-PssBeforeStart $params '') -and $fake.Requests -eq $n)
    $script:PssInMemory = $true; $r = Update-PssBeforeStart $params $copy; $script:PssInMemory = $false
    Check 'in-memory: no check' (-not $r -and $fake.Requests -eq $n -and (Unchanged))
    $script:PssReadOnly = $true; $r = Update-PssBeforeStart $params $copy; $script:PssReadOnly = $false
    Check 'read-only: no check' (-not $r -and $fake.Requests -eq $n -and (Unchanged))
    $env:PXD_NO_UPDATE = '1'; $r = Update-PssBeforeStart $params $copy; $env:PXD_NO_UPDATE = $null
    Check 'PXD_NO_UPDATE=1: no check' (-not $r -and $fake.Requests -eq $n -and (Unchanged))
    $other = Join-Path $t 'other.ps1'; Set-Content -LiteralPath $other -Value 'Write-Output 1'
    Check 'a file that is not this scanner: no check' (-not (Update-PssBeforeStart $params $other) -and $fake.Requests -eq $n)

    # ---- bad downloads are refused and leave the file as it was
    $fake.Sum = ('0' * 64) + '  pxdStartupScanner.ps1'
    Check 'checksum mismatch: refused, file unchanged' (-not (Update-PssBeforeStart $params $copy) -and (Unchanged) -and -not $script:Reran)
    $broken = [Text.Encoding]::ASCII.GetBytes($newText.Substring(0, [int]($newText.Length / 2)))
    $fake.File = $broken; $fake.Sum = $null
    Check 'cut-off download: refused, file unchanged' (-not (Update-PssBeforeStart $params $copy) -and (Unchanged))
    $wrong = [Text.Encoding]::ASCII.GetBytes($text)   # says it's the old version
    $fake.File = $wrong
    Check 'download with the wrong version inside: refused' (-not (Update-PssBeforeStart $params $copy) -and (Unchanged))

    # ---- offline / GitHub slow: gives up quickly
    $env:PXD_UPDATE_API = 'http://127.0.0.1:1'
    $clock = [Diagnostics.Stopwatch]::StartNew(); $r = Update-PssBeforeStart $params $copy; $clock.Stop()
    Check "offline: runs this copy ($([int]$clock.Elapsed.TotalSeconds) s)" (-not $r -and $clock.Elapsed.TotalSeconds -lt 6 -and (Unchanged))
    $env:PXD_UPDATE_API = $prefix.TrimEnd('/')

    # ---- a good update: file replaced, the new copy runs once with the same parameters
    $fake.File = $newBytes; $fake.Sum = (Get-Sha $newBytes) + '  pxdStartupScanner.ps1'
    $r = Update-PssBeforeStart $params $copy
    Check 'newer release: file replaced with it' ($r -and [IO.File]::ReadAllText($copy) -eq $newText -and -not (Test-Path -LiteralPath "$copy.pxdnew") -and -not (Test-Path -LiteralPath "$copy.pxdold"))
    Check 'newer release: re-run with the same parameters' ($script:Reran -and $script:Reran.Path -eq $copy -and $script:Reran.Params.Report -eq $true -and $script:Reran.Params.Export -eq 'C:\x\report.html' -and $script:Reran.Params.Gui -eq $false)
    Check 'the re-run is told not to check again' ($script:Reran.From -eq $cur -and -not $env:PXD_UPDATED_FROM)
    $env:PXD_UPDATED_FROM = $cur; $n = $fake.Requests
    Check 'inside the re-run: no second check' (-not (Update-PssBeforeStart $params $copy) -and $fake.Requests -eq $n)
    $env:PXD_UPDATED_FROM = $null

    # ---- end to end: run the old file; it updates to a stub release, which runs instead of the scan
    [IO.File]::WriteAllText($copy, $text)
    $env:PSS_CONFIG_DIR = Join-Path $t 'config'   # (if the update failed, the old copy's scan would keep settings out of APPDATA)
    $stub = "param([switch]`$Gui, [switch]`$Report, [string]`$Export, [switch]`$ReadOnly)`r`n`$script:PssVersion = '$newVer'`r`nfunction Start-pxdStartupScanner { }`r`n[IO.File]::WriteAllText((Join-Path `$PSScriptRoot 'stub-ran.txt'), `"Report=`$Report Export=`$Export from=`$env:PXD_UPDATED_FROM`")`r`n"
    $stubBytes = [Text.Encoding]::ASCII.GetBytes($stub)
    $fake.File = $stubBytes; $fake.Sum = (Get-Sha $stubBytes) + '  pxdStartupScanner.ps1'
    $out = & $copy -Report -Export 'C:\x\e2e.html' 6>&1 | Out-String
    $ran = Join-Path $t 'stub-ran.txt'
    Check 'end to end: the old file updated itself and ran the new one' ((Test-Path -LiteralPath $ran) -and (Get-Content -LiteralPath $ran -Raw) -eq "Report=True Export=C:\x\e2e.html from=$cur" -and [IO.File]::ReadAllText($copy) -eq $stub)
    Check 'end to end: the old copy did not scan as well' ($out -notmatch 'Scanning')
} catch {
    Check "no unexpected error ($($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber))" $false
} finally {
    if ($listener) { try { $listener.Stop(); $listener.Close() } catch {} }
    foreach ($n in $saved.Keys) { [Environment]::SetEnvironmentVariable($n, $saved[$n]) }
    if ($t -and (Split-Path $t -Leaf) -like 'pss-update-test-*' -and (Test-Path -LiteralPath $t)) { Remove-Item -LiteralPath $t -Recurse -Force }
}
if ($fails) { Write-Host "$fails check(s) failed" -ForegroundColor Red; exit 1 } else { Write-Host 'All update checks passed' -ForegroundColor Green }
