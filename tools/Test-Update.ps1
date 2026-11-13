<#
    Checks "update before start": a copy run from a file replaces itself with a newer release and runs that instead.
    Release info and downloads come from pxdtek.com first and GitHub only as the fallback; a block page (HTML) is never
    taken for the release, the script or its checksum.
    Everything happens in a temp folder against two fake sources on a local HttpListener (127.0.0.1): /m stands for
    pxdtek.com and /g for GitHub. The real pxdtek.com, GitHub, the installed copy and this repo's file are never touched,
    and nothing is shown on screen.
    Run from Windows PowerShell or pwsh:  powershell -ExecutionPolicy Bypass -File tools\Test-Update.ps1
#>
$main = Join-Path $PSScriptRoot '..\pxdStartupScanner.ps1'
$fails = 0
function Check([string]$Name, [bool]$Ok) { if ($Ok) { Write-Host "PASS  $Name" -ForegroundColor Green } else { Write-Host "FAIL  $Name" -ForegroundColor Red; $script:fails++ } }

$t = Join-Path ([IO.Path]::GetTempPath()) ('pss-update-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $t | Out-Null
$saved = @{}
foreach ($n in 'PXD_UPDATE_API', 'PXD_NO_UPDATE', 'PXD_INMEMORY', 'PXD_UPDATED_FROM', 'PSS_READONLY', 'PSS_CONFIG_DIR') { $saved[$n] = [Environment]::GetEnvironmentVariable($n); [Environment]::SetEnvironmentVariable($n, $null) }
$listener = $null
try {
    $src = [IO.File]::ReadAllText($main)
    $cur = [regex]::Match($src, "PssVersion = '([^']+)'").Groups[1].Value
    $copy = Join-Path $t 'pxdStartupScanner.ps1'
    [IO.File]::WriteAllText($copy, $src)

    # ---- the fake sources: each answers 'ok', 'html' (a filter's block page, status 200) or 'down' (503), per kind
    $port = Get-Random -Minimum 41000 -Maximum 49000
    $prefix = "http://127.0.0.1:$port/"
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($prefix); $listener.Start()
    $fake = [hashtable]::Synchronized(@{ Tag = "v$cur"; File = [byte[]]@(); Sum = $null; Requests = 0
            m = @{ api = 'ok'; file = 'ok'; sum = 'ok' }; g = @{ api = 'ok'; file = 'ok'; sum = 'ok' }; Hits = [hashtable]::Synchronized(@{})
        })
    $ps = [powershell]::Create()
    [void]$ps.AddScript({
            param($listener, $fake, $prefix)
            $block = [Text.Encoding]::UTF8.GetBytes('<!DOCTYPE html><html><head><title>Blocked</title></head><body>This site is blocked by your organization.</body></html>')
            while ($listener.IsListening) {
                try { $ctx = $listener.GetContext() } catch { return }
                $fake.Requests++
                $parts = $ctx.Request.Url.AbsolutePath.Trim('/') -split '/'
                $who = $parts[0]; $kind = $null; $body = [byte[]]@()
                if ($parts.Count -eq 6 -and $parts[1] -eq 'repos' -and $parts[2] -eq 'pxdtek' -and $parts[3] -eq 'pxdStartupScanner') { $kind = 'api' }
                elseif ($parts.Count -eq 3 -and $parts[1] -eq 'dl') { $kind = $parts[2] }
                $fake.Hits["$who/$kind"] = 1 + [int]$fake.Hits["$who/$kind"]
                $mode = if ($who -in 'm', 'g' -and $kind) { $fake[$who][$kind] } else { 'none' }
                if ($mode -eq 'html') { $body = $block; $ctx.Response.ContentType = 'text/html' }
                elseif ($mode -eq 'down') { $ctx.Response.StatusCode = 503 }
                elseif ($mode -eq 'none') { $ctx.Response.StatusCode = 404 }
                elseif ($kind -eq 'api') {
                    $assets = @(@{ name = 'pxdStartupScanner.ps1'; browser_download_url = "$prefix$who/dl/file" })
                    if ($fake.Sum) { $assets += @{ name = 'pxdStartupScanner.ps1.sha256'; browser_download_url = "$prefix$who/dl/sum" } }
                    $body = [Text.Encoding]::UTF8.GetBytes((@{ tag_name = $fake.Tag; assets = $assets } | ConvertTo-Json -Depth 4))
                } elseif ($kind -eq 'file') { $body = $fake.File }
                elseif ($kind -eq 'sum') { $body = [Text.Encoding]::ASCII.GetBytes([string]$fake.Sum) }
                $ctx.Response.OutputStream.Write($body, 0, $body.Length); $ctx.Response.Close()
            }
        }).AddArgument($listener).AddArgument($fake).AddArgument($prefix)
    [void]$ps.BeginInvoke()
    $mirror = $prefix + 'm'; $github = $prefix + 'g'
    $env:PXD_UPDATE_API = "$mirror;$github"   # pxdtek.com first, then GitHub

    # ---- the functions, from the temp copy, with the re-run recorded instead of started
    $text = [IO.File]::ReadAllText($copy)
    . ([scriptblock]::Create($text.Substring(0, $text.LastIndexOf('Start-pxdStartupScanner -Gui'))))

    # the real address rules first
    Check 'default sources: pxdtek.com first, GitHub second' ($(Remove-Item Env:\PXD_UPDATE_API; $b = @(Get-PssApiBases); $env:PXD_UPDATE_API = "$mirror;$github"; ($b -join ' ') -eq 'https://pxdtek.com/gh https://api.github.com'))
    Check 'a pxdtek.com download maps to its GitHub copy' ((Get-PssGitHubCopy 'https://pxdtek.com/dl/pxdStartupScanner/v1.6.2/pxdStartupScanner.ps1') -eq 'https://github.com/pxdtek/pxdStartupScanner/releases/download/v1.6.2/pxdStartupScanner.ps1' -and $null -eq (Get-PssGitHubCopy 'https://example.com/x'))
    Check 'block pages are recognised; a script starting with <# is not one' ((Test-PssHtml ([Text.Encoding]::UTF8.GetBytes("`r`n <!doctype html><p>blocked"))) -and (Test-PssHtml ([Text.Encoding]::UTF8.GetBytes('<html>'))) -and -not (Test-PssHtml ([Text.Encoding]::ASCII.GetBytes("#Requires -Version 5.1`r`n<#`r`n.SYNOPSIS"))) -and -not (Test-PssHtml ([Text.Encoding]::ASCII.GetBytes("<#`r`n.SYNOPSIS`r`n    A script that starts with its help comment`r`n#>"))))
    # in this test the "pxdtek.com" downloads map to the fake GitHub
    function Get-PssGitHubCopy([string]$Url) { if ($Url.StartsWith("$mirror/dl/")) { return $github + $Url.Substring($mirror.Length) } return $null }

    $script:PssReadOnly = $false; $script:PssInMemory = $false
    $script:Reran = $null
    function Invoke-PssRerun([string]$Path, [hashtable]$Params) { $script:Reran = @{ Path = $Path; Params = $Params; From = $env:PXD_UPDATED_FROM } }
    $params = @{ Gui = $false; Report = $true; Export = 'C:\x\report.html'; ReadOnly = $false }
    function Get-Sha([byte[]]$b) { $s = [Security.Cryptography.SHA256]::Create(); try { ([BitConverter]::ToString($s.ComputeHash($b))).Replace('-', '').ToLowerInvariant() } finally { $s.Dispose() } }
    $newVer = '9.8.7'
    $newText = $text.Replace("`$script:PssVersion = '$cur'", "`$script:PssVersion = '$newVer'")
    $newBytes = [Text.Encoding]::ASCII.GetBytes($newText)
    function Unchanged { ([IO.File]::ReadAllText($copy) -eq $text) -and -not (Test-Path -LiteralPath "$copy.pxdnew") -and -not (Test-Path -LiteralPath "$copy.pxdold") }
    function Set-Mode([string]$Who, [string]$Api = 'ok', [string]$File = 'ok', [string]$Sum = 'ok') { $fake[$Who] = @{ api = $Api; file = $File; sum = $Sum } }
    function Reset-Case { [IO.File]::WriteAllText($copy, $text); $script:Reran = $null; $fake.Hits.Clear(); Set-Mode m; Set-Mode g }
    function Hits([string]$k) { [int]$fake.Hits[$k] }

    # ---- no update
    $r = Update-PssBeforeStart $params $copy
    Check 'same version: nothing changes, GitHub not asked' (-not $r -and (Unchanged) -and -not $script:Reran -and (Hits 'm/api') -eq 1 -and (Hits 'g/api') -eq 0)
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

    # ---- a good update straight from pxdtek.com
    Reset-Case
    $r = Update-PssBeforeStart $params $copy
    Check 'newer release from pxdtek.com: file replaced, GitHub not asked' ($r -and [IO.File]::ReadAllText($copy) -eq $newText -and (Hits 'g/api') + (Hits 'g/file') + (Hits 'g/sum') -eq 0 -and -not (Test-Path -LiteralPath "$copy.pxdnew") -and -not (Test-Path -LiteralPath "$copy.pxdold"))
    Check 'newer release: re-run with the same parameters' ($script:Reran -and $script:Reran.Path -eq $copy -and $script:Reran.Params.Report -eq $true -and $script:Reran.Params.Export -eq 'C:\x\report.html' -and $script:Reran.Params.Gui -eq $false)
    Check 'the re-run is told not to check again' ($script:Reran.From -eq $cur -and -not $env:PXD_UPDATED_FROM)
    $env:PXD_UPDATED_FROM = $cur; $n = $fake.Requests
    Check 'inside the re-run: no second check' (-not (Update-PssBeforeStart $params $copy) -and $fake.Requests -eq $n)
    $env:PXD_UPDATED_FROM = $null

    # ---- pxdtek.com blocked or down: the GitHub copy is used; a block page is never taken for anything
    Reset-Case; Set-Mode m -Api html
    Check 'pxdtek.com release info is a block page: GitHub used' ((Update-PssBeforeStart $params $copy) -and [IO.File]::ReadAllText($copy) -eq $newText -and (Hits 'g/api') -eq 1)
    Reset-Case; Set-Mode m -Api down
    Check 'pxdtek.com down: GitHub used' ((Update-PssBeforeStart $params $copy) -and [IO.File]::ReadAllText($copy) -eq $newText -and (Hits 'g/api') -eq 1)
    Reset-Case; Set-Mode m -File html
    Check 'download is a block page: the GitHub copy is used' ((Update-PssBeforeStart $params $copy) -and [IO.File]::ReadAllText($copy) -eq $newText -and (Hits 'm/file') -eq 1 -and (Hits 'g/file') -eq 1)
    Reset-Case; Set-Mode m -Sum html
    Check 'checksum is a block page: the GitHub checksum is used' ((Update-PssBeforeStart $params $copy) -and [IO.File]::ReadAllText($copy) -eq $newText -and (Hits 'g/sum') -eq 1)
    Reset-Case; Set-Mode m -File down
    Check 'download fails: the GitHub copy is used' ((Update-PssBeforeStart $params $copy) -and [IO.File]::ReadAllText($copy) -eq $newText -and (Hits 'g/file') -eq 1)
    Reset-Case; Set-Mode m -Api html; Set-Mode g -Api html
    Check 'both block the release info: no update' (-not (Update-PssBeforeStart $params $copy) -and (Unchanged) -and -not $script:Reran)
    Reset-Case; Set-Mode m -File html; Set-Mode g -File html
    Check 'both downloads are block pages: refused, file unchanged' (-not (Update-PssBeforeStart $params $copy) -and (Unchanged) -and -not $script:Reran)
    Reset-Case; Set-Mode m -Sum html; Set-Mode g -Sum html
    Check 'no readable checksum: refused (the file is not trusted)' (-not (Update-PssBeforeStart $params $copy) -and (Unchanged))
    Reset-Case

    # ---- bad downloads are refused and leave the file as it was
    $fake.Sum = ('0' * 64) + '  pxdStartupScanner.ps1'
    Check 'checksum mismatch on both sources: refused, file unchanged' (-not (Update-PssBeforeStart $params $copy) -and (Unchanged) -and -not $script:Reran)
    $fake.File = [Text.Encoding]::ASCII.GetBytes($newText.Substring(0, [int]($newText.Length / 2))); $fake.Sum = $null
    Check 'cut-off download: refused, file unchanged' (-not (Update-PssBeforeStart $params $copy) -and (Unchanged))
    $fake.File = [Text.Encoding]::ASCII.GetBytes($text)   # says it's the old version
    Check 'download with the wrong version inside: refused' (-not (Update-PssBeforeStart $params $copy) -and (Unchanged))

    # ---- offline: gives up quickly
    $env:PXD_UPDATE_API = 'http://127.0.0.1:1;http://127.0.0.1:2'
    $clock = [Diagnostics.Stopwatch]::StartNew(); $r = Update-PssBeforeStart $params $copy; $clock.Stop()
    Check "offline: runs this copy ($([int]$clock.Elapsed.TotalSeconds) s)" (-not $r -and $clock.Elapsed.TotalSeconds -lt 10 -and (Unchanged))
    $env:PXD_UPDATE_API = "$mirror;$github"

    # ---- end to end: run the old file; pxdtek.com is blocked, it updates from "GitHub" to a stub release, which runs
    [IO.File]::WriteAllText($copy, $text); Set-Mode m -Api html
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
