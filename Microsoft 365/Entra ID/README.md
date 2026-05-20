# Microsoft Entra

## Purpose
Scripts in this folder assist administrators with auditing, hardening, and managing a Microsoft Entra ID tenant. Most scripts require an authenticated Microsoft Graph session via the `Microsoft.Graph` PowerShell module; the connect command for each script is listed below.

> Connect-MgGraph requests interactive consent the first time each scope set is used. Run from a session whose signed-in account holds the appropriate directory roles (e.g., **Application Administrator**, **Privileged Role Administrator**, or **Global Administrator** for the more privileged scripts).

---

## Scripts

### Enumerate-PrivilegedGroups
Queries the tenant for every group flagged `isAssignableToRole = true` and returns Group Type, Membership Type, Assigned Licenses, Disabled Features, Role-Assignable status, Assigned Roles, Members, On-Premise sync state, and License Errors.

**Connect:**
```powershell
Connect-MgGraph -ContextScope Process -Scopes `
    "Directory.Read.All", "GroupMember.Read.All", "RoleManagement.Read.Directory"
```

**Run:**
```powershell
.\Enumerate-PrivilegedGroups.ps1
```

---

### Find-AppLicensedUsers
Identifies every user with a given application enabled through licensing (e.g., Yammer, Bookings, Kaizala). Outputs `UserLicenseReport.csv` in the current directory.

**Parameters:**
- `-psModule` — `MSOL` or `Graph`. *(MSOL is the retired MSOnline module; new tenants must use `Graph`.)*
- `-Applications` — comma-separated list of application keywords to match (e.g., `Yammer, Kaizala`).

**Connect (Graph mode):**
```powershell
Connect-MgGraph -ContextScope Process -Scopes "User.Read.All"
```

**Run:**
```powershell
.\Find-AppLicensedUsers.ps1 -psModule Graph -Applications Yammer, Kaizala
```

---

### Invoke-KillAllSessions
Revokes all active sign-in sessions for every user in the tenant. The script calls `Connect-MgGraph` itself with the scopes below — no pre-authentication needed.

**Scopes requested by the script:**
`User.ReadWrite.All`, `Directory.ReadWrite.All`

**Run:**
```powershell
.\Invoke-KillAllSessions.ps1
```

---

### Invoke-KillSession
Revokes all active sign-in sessions for a single targeted user. The script calls `Connect-MgGraph` itself with the scopes below.

**Parameters:**
- `-targetUser` — value to look the user up by (Mail, UPN, or DisplayName).
- `-lookupType` — `Mail`, `UPN`, or `DisplayName`. Defaults to `UPN`.

**Scopes requested by the script:**
`User.ReadWrite.All`, `Directory.ReadWrite.All`

**Run:**
```powershell
.\Invoke-KillSession.ps1 -lookupType UPN -targetUser user@contoso.com
.\Invoke-KillSession.ps1 -lookupType Mail -targetUser user@contoso.com
.\Invoke-KillSession.ps1 -lookupType DisplayName -targetUser "First Last"
```

---

### Invoke-OwnedObjectsReport
Enumerates every Entra object (group, application, service principal) owned by each user and exports the result to an Excel workbook (`MS_User_Owned_Objects.xlsx`) with one worksheet per user. For application owners, the report also resolves the corresponding service principal and notes the inherited ownership.

**Module requirement:** `ImportExcel` (PowerShell Gallery).

**Parameters:**
- `-outputPath` — directory where the workbook is written.
- `-targetUsers` — `All` (default) or a comma-separated list of user `id` values.

**Connect:**
```powershell
Connect-MgGraph -ContextScope Process -Scopes `
    "User.Read.All", "Application.Read.All", "Group.Read.All"
```

**Run:**
```powershell
.\Invoke-OwnedObjectsReport.ps1 -outputPath C:\Reports
```

---

### Invoke-PowerShellRestrictions
Restricts first-party Microsoft administrative PowerShell / CLI applications to explicitly assigned users by creating (if missing) and hardening their service principals so that `appRoleAssignmentRequired = true` and only assigned users hold the default app role. Target users can be supplied via a directory role, a security group, a CSV of UserPrincipalNames, or a single UPN.

**Target applications hardened by default:**
- Microsoft Intune PowerShell
- Microsoft Azure PowerShell (Az)
- Microsoft Azure CLI
- Graph Explorer
- Microsoft Graph Command Line Tools
- Microsoft Exchange REST API Based PowerShell
- Power BI PowerShell

*(The Azure Active Directory PowerShell SP entry is commented out — that module was retired in October 2025 and Microsoft no longer allows new SP provisioning for that AppId.)*

**Connect:**
```powershell
Connect-MgGraph -ContextScope Process -Scopes `
    "Application.ReadWrite.All", "Directory.ReadWrite.All", `
    "AppRoleAssignment.ReadWrite.All", "User.Read.All", `
    "Group.Read.All", "RoleManagement.Read.Directory"
```

**Required directory role:** the signed-in account must hold **Application Administrator**, **Cloud Application Administrator**, or **Global Administrator**. The script performs a pre-flight scope check and prints the exact reconnect command if any required scope is missing.

**Run:**
```powershell
.\Invoke-PowerShellRestrictions.ps1
# Then choose 1 (Directory Role), 2 (Security Group), 3 (CSV), or 4 (single UPN).
```

---

### Remediate-DangerousDefaults
Tightens the tenant-wide `authorizationPolicy` (blocks self-service account creation, restricts guest invites, disables app creation by default users, removes risky consent flows, etc.) and creates a Conditional Access policy targeting `MicrosoftAdminPortals` for non-admin users. The CA policy is created in **report-only** mode — review and enable it explicitly after validation.

Review the script body before running; the `defaultUserRolePermissions` and `blockMsolPowerShell` blocks include settings that may be too aggressive for some tenants.

**Connect:**
```powershell
Connect-MgGraph -ContextScope Process -Scopes `
    "Directory.ReadWrite.All", "Policy.ReadWrite.Authorization", `
    "Policy.ReadWrite.ConditionalAccess"
```

**Run:**
```powershell
.\Remediate-DangerousDefaults.ps1
```

---

### Invoke-StaleAccountDetection
Identifies stale user accounts across hybrid on-prem AD, Entra ID, and Exchange Online by correlating identities via the immutable ID (Base64-encoded `objectGUID`). Aggregates the most recent activity timestamp from `lastLogonTimestamp` (AD), `signInActivity.lastSignInDateTime` (Entra), and `LastLogonTime` (mailbox statistics), then flags accounts whose latest activity is older than the cutoff. Shared, room, and equipment mailboxes are excluded automatically. Output is written to `StaleAccounts.csv`.

**Parameters:**
- `-StaleDays` — integer threshold; default `60`.
- `-OutputPath` — destination CSV path; default `.\StaleAccounts.csv`.

**Module requirements:**
- `ActiveDirectory` (RSAT) for `Get-ADUser` — must run from a domain-joined host or one with RSAT installed.
- `Microsoft.Graph.Authentication` for `Invoke-MgGraphRequest`.
- `ExchangeOnlineManagement` for `Get-Mailbox` / `Get-MailboxStatistics`.

**Connect:**
```powershell
Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All"
Connect-ExchangeOnline -ShowBanner:$false
```

**Run:**
```powershell
.\Invoke-StaleAccountDetection.ps1
.\Invoke-StaleAccountDetection.ps1 -StaleDays 90 -OutputPath C:\Reports\stale.csv
```

---

## Conditional Access

### Conditional Access\Create-OWACAPolicy.ps1
Creates a Conditional Access policy that blocks **browser** access to **Outlook Web App** (AppId `00000002-0000-0ff1-ce00-000000000000`) for members of one or more named groups, unless the device is corporate-owned or compliant. The policy is created in **report-only** mode (`enabledForReportingButNotEnforced`) — review and enable it after validating the impact.

**Parameters:**
- `-GroupNames` — array of group display name *prefixes* used in a `startswith()` lookup. All matching groups are excluded from access by the resulting policy.

**Connect:**
```powershell
Connect-MgGraph -ContextScope Process -Scopes `
    "Group.Read.All", "Policy.ReadWrite.ConditionalAccess"
```

**Run:**
```powershell
.\Conditional Access\Create-OWACAPolicy.ps1 -GroupNames "Contractors", "Interns"
```
