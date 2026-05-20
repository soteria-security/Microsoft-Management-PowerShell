# Microsoft Windows

## Purpose
Scripts in this folder assist administrators with auditing and managing Windows endpoints (workstations and servers). No cloud module is required — these scripts use Windows-native PowerShell providers, WMI/CIM, and the registry.

---

## Scripts

### EnableCommandLineAuditing.ps1
Enables PowerShell transcription, PowerShell module logging, and command-line process auditing on the local machine by writing the relevant Group Policy registry keys under `HKLM`. The script self-elevates: if launched without administrator privileges it relaunches itself with `RunAs`.

**Registry values written:**
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription` → `EnableTranscripting = 1`, `OutputDirectory = $env:USERPROFILE\Documents\PowerShell\Transcripts`, `EnableInvocationHeader = 1`
- `HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging` → `EnableModuleLogging = 1` with `ModuleNames\* = *` (log every module)
- `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit` → `ProcessCreationIncludeCmdLine_Enabled = 1`

**Requirements:**
- Local Administrator on the device (self-elevated by the script).
- Must run from an interactive desktop session — the elevation prompt is UAC.

> Note: `ProcessCreationIncludeCmdLine_Enabled` only takes effect once Windows is also configured to log process-creation events (Security log event ID **4688**). Enable **Audit Process Creation** under *Local Security Policy → Advanced Audit Policy Configuration → Detailed Tracking* (or push it via Group Policy / Intune). Without that, the cmdline-inclusion registry flag is set but no events are written.

**Run:**
```powershell
.\EnableCommandLineAuditing.ps1
```

---

### PC-Info.ps1
Menu-driven interactive script that performs a battery of read-only checks against a target Windows host (local or remote). On launch it prompts for a `ComputerName` or IP, validates reachability and WSMan, then presents a numbered menu.

**Available checks:**
| # | Action |
|---|--------|
| 1 | Device info — OS version, NIC details, disk space, currently logged-on user (resolves to AD DisplayName when possible) |
| 2 | AutoLogin configuration (`Winlogon` registry values) |
| 3 | Mapped drives for the currently logged-on user |
| 4 | Active remote sessions via `quser /server:` |
| 5 | Installed printers — local and network |
| 6 | Members of the local Administrators group |
| 7 | Hosts file contents (parsed for IP + hostname pairs) |
| 8 | PowerShell `ExecutionPolicy` on the target |
| 9 | Hotfixes — query a single KB or list all installed |
| 10 | Resultant Set of Policy (RSOP) HTML report — written to `<script-dir>\RSOP\<host>-rsop.html` |
| 11 | User profile directories under `C:\Users\` |
| 12 | Installed software (via `wmic product`) |
| 13 | Services list (note: menu labels say "processes" — actually returns services) |
| 14 | Firefox and Chrome browser extensions for the logged-on user |
| 15 | Run every check in sequence |
| 16 | Look up another computer (restart at the prompt) |
| H | Show in-script help |
| Q | Quit |

**Requirements on the operator's machine:**
- `ActiveDirectory` PowerShell module (RSAT) for the `Get-ADUser` call inside the device-info check.
- Network reachability to the target (`Test-Connection`, SMB admin shares `\\<host>\c$`, WMI/CIM, optional WSMan).

**Requirements on the target machine:**
- **WMI / RPC** (DCOM port 135 + dynamic high ports) for `Get-WmiObject` calls.
- **SMB admin shares** (`Admin$`, `C$`) for hosts file, user-profile, and browser-extension lookups — caller must be a member of the target's local **Administrators** group.
- **WinRM / WSMan** for the `Invoke-Command`-based execution policy check (option 8).

**Run:**
```powershell
.\PC-Info.ps1
```

> Limitations: several functions assume the operator is running as a domain user with administrative rights on the target. Pure local-account access will fail on the SMB-share-based checks. The `ExecutionPolicy` check works against hostnames but not bare IP addresses (Kerberos / WinRM constraint).
