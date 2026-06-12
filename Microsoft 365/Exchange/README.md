# Microsoft Exchange Online

## Purpose
Scripts in this folder assist administrators with auditing and managing a Microsoft Exchange Online environment. Most scripts require the `ExchangeOnlineManagement` PowerShell module and an authenticated session via `Connect-ExchangeOnline`. A few also require `Connect-IPPSSession` (Security & Compliance) or `Connect-MgGraph` (Microsoft Graph) — those requirements are called out per script below.

> Install the modules once:
> ```powershell
> Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
> Install-Module Microsoft.Graph             -Scope CurrentUser -Force   # only for cross-module scripts
> ```

---

## Scripts

### Block Auto-Forwarding.ps1
Creates an Exchange transport rule named **"Block Auto-Forwarding"** that rejects any internally-originated message identified as an AutoForward and bound for an external recipient.

**Required role:** Exchange Online **Organization Management** (or any role group that grants the `Transport Rules` management role).

**Connect:**
```powershell
Connect-ExchangeOnline -ShowBanner:$false
```

**Run:**
```powershell
& ".\Block Auto-Forwarding.ps1"
```

---

### Exchange-SeekandDestroy.ps1
Connects to Exchange Online **and** Security & Compliance PowerShell, blocks a sender (or matches by subject), runs a compliance content search across all mailboxes, and iteratively purges matching messages until none remain. The script manages its own connections — do **not** call `Connect-ExchangeOnline` or `Connect-IPPSSession` first.

**Module requirement:** `ExchangeOnlineManagement` **v3.9.0 or later** (required for `Connect-IPPSSession -EnableSearchOnlySession`, which Microsoft began enforcing in August 2025). The script checks the installed version and exits if it is too old.

**Required roles:**
- `eDiscovery Manager` or `eDiscovery Administrator`
- `Search and Purge` (granted by `Organization Management` or `Data Investigator` role groups)
- Valid Microsoft 365 license on the admin account

**Limitations (per Microsoft):**
- Up to 100 items per mailbox per purge action (script handles this by iterating).
- Unindexed items and Microsoft Teams messages are not purged.

**Parameters:**
- `-AdminAccount` — UPN of the admin account used for both Exchange Online and IPPS connections.
- `-BySender` / `-BySubject` — pick one search mode. Defaults to `-BySender` when neither is specified.
- `-DeleteType` — `Hard` (permanent) or `Soft` (recoverable).

**Run:**
```powershell
.\Exchange-SeekandDestroy.ps1 -AdminAccount myadmin@contoso.com -BySender  -DeleteType Hard
.\Exchange-SeekandDestroy.ps1 -AdminAccount myadmin@contoso.com -BySubject -DeleteType Soft
```

---

### Get-ActiveSyncMailboxes.ps1
Audits Exchange Online mailboxes with ActiveSync enabled and identifies which of those are actively partnered with a mobile device. Output is appended to `ActiveSyncMailboxes.txt` in the current directory.

**Required role:** any Exchange Online role that can read mailbox CAS configuration (e.g., `View-Only Recipients`, `Recipient Management`, `Organization Management`).

**Connect:**
```powershell
Connect-ExchangeOnline -ShowBanner:$false
```

**Run:**
```powershell
.\Get-ActiveSyncMailboxes.ps1
```

---

### Get-MailDomainsStatus.ps1
Gathers Exchange-accepted domains and queries public DNS (Google's `8.8.8.8`) to validate the DMARC, SPF, and DKIM selector 1 / selector 2 records for each domain. Output is written to the console — pipe to a file if you need a report.

**Parameters:**
- `-Domains` — *(optional)* comma-separated list of domains to evaluate. When omitted, the script enumerates accepted domains via `Get-AcceptedDomain` and requires an active Exchange Online connection.

**Connect (only required when `-Domains` is not supplied):**
```powershell
Connect-ExchangeOnline -ShowBanner:$false
```

**Run:**
```powershell
# Use accepted domains from the tenant
.\Get-MailDomainsStatus.ps1

# Or evaluate a specific list (no Exchange connection needed)
.\Get-MailDomainsStatus.ps1 -Domains domain1.com, domain2.com, domain3.com
```

---

### Invoke-BlockSharedMailboxSignIn.ps1
Discovers every shared mailbox in the tenant and disables interactive sign-in (`accountEnabled = false`) on the underlying user object via Microsoft Graph. Implements CIS Microsoft 365 Foundations Benchmark control **1.2.2 (L1)**.

**Module requirements:** `ExchangeOnlineManagement` **and** `Microsoft.Graph` (specifically `Microsoft.Graph.Users` for `Update-MgUser`).

**Connect (both sessions required):**
```powershell
Connect-ExchangeOnline -ShowBanner:$false
Connect-MgGraph -ContextScope Process -Scopes "User.ReadWrite.All"
```

**Run:**
```powershell
.\Invoke-BlockSharedMailboxSignIn.ps1
```

---

### Remove-CalendarAutoMappingSharedMailbox.ps1
Starting in January 2025, Outlook began auto-mapping calendars from shared mailboxes the user has FullAccess to. For users with FullAccess to many shared mailboxes, this clutters the calendar pane and can cause performance issues. This script enumerates every shared mailbox, finds all delegates with FullAccess (excluding `NT AUTHORITY\SELF`), removes the existing permission, and re-adds it with `-AutoMapping:$false`.

**Required role:** Exchange Online **Organization Management** (or any role with `Recipient Management` rights to modify mailbox permissions).

**Connect:**
```powershell
Connect-ExchangeOnline -ShowBanner:$false
```

**Run:**
```powershell
.\Remove-CalendarAutoMappingSharedMailbox.ps1
```

---

## See also

- [`Exchange Audit Events/`](./Exchange%20Audit%20Events/README.md) — Azure Automation runbook + on-demand script that configure per-mailbox audit logging and verify the audit configuration for newly provisioned mailboxes.
