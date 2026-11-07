# PAX Startup Scanner

Finds everything that starts with Windows: what each item is, where it lives, who signed it, whether it looks suspicious, and what is slowing the machine down. It is one PowerShell script with nothing to install. You can run it straight from GitHub on any machine you are fixing.

![Console dashboard](docs/screenshots/console-dashboard.png)

## Run it

Open **PowerShell as Administrator** and paste:

```powershell
irm https://raw.githubusercontent.com/joshpack/PaxStartupScanner/main/PaxStartupScanner.ps1 | iex
```

That's it. The script runs in memory and leaves nothing behind on the machine.

On older systems where PowerShell doesn't use TLS 1.2 by default (Server 2012 R2/2016, early Windows 10), use:

```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; irm https://raw.githubusercontent.com/joshpack/PaxStartupScanner/main/PaxStartupScanner.ps1 | iex
```

### Options

`irm | iex` can't take parameters. To pass options, run the script as a script block:

```powershell
# Open the graphical view
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/joshpack/PaxStartupScanner/main/PaxStartupScanner.ps1))) -Gui

# Non-interactive: print the summary + flagged items, save a report, and return
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/joshpack/PaxStartupScanner/main/PaxStartupScanner.ps1))) -Report -Export C:\Temp\startup.html
```

| Parameter | What it does |
|---|---|
| `-Gui` | Opens the graphical view instead of the console menu |
| `-Report` | Scans, prints the summary and flagged items, then returns (good for remote shells and scripts) |
| `-Export <path>` | Saves a report after scanning. Use `.html` (self-contained, filterable), `.csv` or `.json` |

A downloaded copy runs the same way: `powershell -ExecutionPolicy Bypass -File .\PaxStartupScanner.ps1`

## Using the console

The dashboard shows the risk summary, where things start from, boot times and the heaviest third-party items. From the menu:

| Key | |
|---|---|
| `1` | Review flagged items (high and medium risk) |
| `2` | All third-party startup items |
| `3` | Browse by category |
| `4` | Everything, including Microsoft items |
| `5` | Search by name, file, publisher, command or location |
| `6` | Boot performance: recent boot times, what Windows says slowed boot, memory use right now |
| `E` | Export an HTML / CSV / JSON report |
| `G` | Open the GUI with the same results |
| `M` | Include clean Microsoft items when browsing and searching |
| `R` | Rescan |
| any number | Show that item's details |

![Flagged items](docs/screenshots/console-flagged.png)

The details view shows the item's command, the resolved file, its signature, publisher, version and dates, and its registry or task location. It also shows whether the item is running and how much memory it uses, any boot delay Windows recorded for it, and every flag. From there you can:

- **O**: open the location. This jumps Regedit to the key, or opens Task Scheduler or the startup folder.
- **F**: show the file in Explorer.
- **H**: calculate the SHA-256 hash.
- **V**: look the hash up on VirusTotal.
- **S**: search the web for the file name.
- **C**: copy the details to the clipboard.

![Item details](docs/screenshots/console-details.png)

![Boot performance](docs/screenshots/console-boot.png)

## The GUI

Press `G` from the menu or run with `-Gui`. The GUI is a single lightweight window with search, a category filter, a "hide clean Microsoft items" switch, a details pane and a boot-performance tab. Rescans run in the background, so the window stays responsive.

![GUI](docs/screenshots/gui.png)

## What it scans

| Area | Where |
|---|---|
| Run keys | `Run`, `RunOnce`, `RunServices`, `Policies\Explorer\Run` and their 32-bit `WOW6432Node` versions, for the machine **and every logged-on user**. Items disabled in Task Manager show as `[off]` |
| Legacy load points | `Windows NT\CurrentVersion\Windows` `Load` / `Run` |
| Startup folders | The all-users folder and every profile's folder, with shortcuts resolved to their target |
| Scheduled tasks | All tasks, including hidden ones, with triggers (boot, logon, schedule, event...), run-as account, author and last run |
| Services | Automatic and delayed-start services. For `svchost` services the real service DLL is checked |
| Drivers | Boot, system and automatic-start drivers |
| Winlogon | `Shell`, `Userinit`, `Taskman`, `AppSetup` and `Notify`, with changes from the Windows defaults flagged |
| Explorer hooks | Shell service objects, delay-load objects, browser helper objects, `SharedTaskScheduler` |
| Injection points | `AppInit_DLLs`, Image File Execution Options debuggers, `SilentProcessExit` monitors |
| Boot | `BootExecute`, `SetupExecute`, `Execute`, `S0InitialCommand` |
| LSA | Authentication, notification and security packages |
| Other | Print monitors, Active Setup, `netsh` helpers, `cmd.exe` AutoRun, logon scripts (`UserInitMprLogonScript` and Group Policy startup/logon scripts), screensaver, Microsoft Store app startup tasks |
| WMI | Permanent event subscriptions (command-line and script consumers) and the filter that triggers them |

For every file it finds it reports whether the file exists, its size and dates, its version info, and its Authenticode signature (catalog-signed Windows files included). Signature checks run in parallel, so a full scan usually finishes in under 10 seconds.

## How risk is scored

Each item collects points from flags. **6+ = High**, **3-5 = Medium**, **1-2 = Low**.

| Flag | Points |
|---|---|
| Encoded PowerShell, inline `javascript:`/`vbscript:`, `regsvr32 /i:` script loading, `certutil` download/decode | 6 |
| Windows process name (`svchost.exe`, `lsass.exe`...) running from outside the Windows folder | 6 |
| Signature doesn't match the file (tampered) | 6 |
| Winlogon value changed from the Windows default | 6 |
| Downloads or evaluates code (`DownloadString`, `IEX`, `Invoke-WebRequest`...), `bitsadmin` download | 5 |
| Double extension (`invoice.pdf.exe`) | 5 |
| WMI persistence, IFEO debugger hijack | 5 |
| Runs from Temp, Public, Downloads or the Recycle Bin | 4 |
| AppInit DLL, non-default boot execute, `mshta`, untrusted certificate | 4 |
| Unsigned executable or DLL | 3 |
| URL in the command line, long encoded string, `cmd.exe` AutoRun, legacy load point | 3 |
| Unsigned file in AppData or a top-level ProgramData folder, script file, Windows Script Host, hidden window | 2 |
| IFEO entry that points to a Microsoft-signed tool | 2 |
| Unquoted service path with spaces, file not found (orphaned entry) | 2 |
| Hidden file, created in the last 7 days (non-Microsoft), signature couldn't be checked | 1 |

Scoring is a triage aid, not a verdict. Plenty of legitimate software is unsigned, and malware can be signed. Use the details view, the hash and VirusTotal to decide.

## Boot and slowdowns

With admin rights the scanner reads Windows' own boot diagnostics log (`Diagnostics-Performance`):

- **Boot times:** total, time to desktop and settling time for recent boots.
- **Slow items:** every app, service and driver Windows recorded as slowing boot, with its worst delay.

Those delays are matched back to startup items, and each item also shows its live memory and CPU use. Together this shows what is actually costing time instead of just guessing.

## Requirements

| | |
|---|---|
| Windows | Windows 10, Windows 11, Windows Server 2016 and later |
| PowerShell | Windows PowerShell 5.1 (built in) or PowerShell 7+. 64-bit only |
| Rights | Run elevated for full results. Without admin, services, tasks, WMI and boot history are partly hidden and the scanner says so |

## Safety and privacy

- **Read-only.** It never disables, deletes or changes startup items. The one write is the same one Autoruns makes: **O** on a registry item sets Regedit's "last key" so Regedit opens at that key.
- **Nothing leaves the machine.** No telemetry and no uploads. **V** opens a VirusTotal page for the file's SHA-256 hash in the browser. The file itself is never uploaded. **S** opens a web search for the file name. Both happen only when you press the key.
- **Exports are saved only where you choose.**

## Limitations

- Registry Run keys are read only for users who are logged on, because other users' registry hives aren't loaded. Those users' startup folders are still scanned, and the dashboard lists the users it couldn't read.
- Run it from 64-bit PowerShell. 32-bit PowerShell sees a redirected registry and file system, so the script refuses to run there.
- It finds the places software uses to start automatically. It is not an antivirus and doesn't scan file contents.

## Rebuilding the screenshots

`tools/Render-Screenshots.ps1` renders the README images off-screen from built-in sample data, so no real machine data is used:

```powershell
powershell -STA -ExecutionPolicy Bypass -File tools\Render-Screenshots.ps1
```
