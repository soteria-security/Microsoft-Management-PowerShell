# Exchange Audit Events

## Purpose
Two complementary scripts that ensure newly-provisioned mailboxes capture the expanded set of standard audit events Microsoft made available in Purview Audit. Both scripts apply identical `AuditAdmin` / `AuditDelegate` / `AuditOwner` lists on the affected mailboxes.

Supplements the blog post: [Better Visibility — New Standard Logs in Microsoft Purview Audit](https://blog.soteria.io/better-visibility-new-standard-logs-in-microsoft-purview-audit-16ec7d000bab).

---

## Scripts

### Account_Provisioning.ps1
On-demand script that creates a new Entra ID user via Microsoft Graph and then applies the expanded mailbox audit configuration via Exchange Online. Use this when provisioning individual accounts so the mailbox starts capturing the full event set immediately.

The script calls `Connect-MgGraph` and `Connect-ExchangeOnline` itself — no pre-authentication required.

**Parameters:**
- `-firstName` *(required)* — user's first name.
- `-lastName` *(required)* — user's last name.
- `-domain` *(required)* — mail domain for the UPN (e.g., `contoso.com`).
- `-startDate` *(required)* — datetime; collected for record keeping.
- `-department` *(optional)* — sets the user's department attribute.
- `-userManager` *(optional)* — UPN of the user's manager; if supplied, a manager link is created via Graph.

**Scopes requested by the script:**
`User.ReadWrite.All`, `Directory.ReadWrite.All`, `GroupMember.ReadWrite.All`, `Group.ReadWrite.All`, `Directory.AccessAsUser.All`

**Required Exchange role:** `Recipient Management` or `Organization Management` (for `Set-Mailbox`).

> ⚠ Note: `Set-Mailbox` will fail if the mailbox has not yet been provisioned by Exchange Online. If the audit-enable step errors immediately after user creation, re-run only the audit-enable portion a few minutes later, or call `Set-Mailbox` separately after the mailbox appears in `Get-Mailbox`.

**Run:**
```powershell
.\Account_Provisioning.ps1 -firstName John -lastName Doe -domain contoso.com -startDate 01/01/1970

# With optional department and manager
.\Account_Provisioning.ps1 -firstName John -lastName Doe -domain contoso.com `
    -startDate 01/01/1970 -department Sales -userManager jsmith@contoso.com
```

---

### ConfigureExchangeMailboxAudit_Runbook.ps1
**Deployment** script — creates and publishes an Azure Automation PowerShell runbook named `ConfigureExchangeMailboxAudit` in an existing Automation account. The runbook is designed to be attached to a schedule (daily/weekly) so the audit configuration sweeps every mailbox and applies the expanded audit set to any new ones, recording handled mailbox identities in an Automation variable so it does not re-process them.

This script **does not create the schedule or the runbook's required Automation assets** — see the prerequisites below.

**Parameters:**
- `-resourceGroupName` *(required)* — resource group containing the Automation account.
- `-automationAccountName` *(required)* — Automation account to deploy the runbook into.

**Prerequisites:**
1. **Az PowerShell session** — the deployment script uses `New-AzAutomationRunbook` and `Publish-AzAutomationRunbook` from `Az.Automation`. Connect first:
   ```powershell
   Connect-AzAccount
   Set-AzContext -SubscriptionId <subscription-id>
   ```
2. **Az role assignment** — the signed-in account needs `Automation Contributor` (or higher) on the target Automation account.
3. **Automation assets the runbook expects at runtime:**
   - **PowerShell credential** named `ExchangeAuditlogConf` — UPN/password of an account with Exchange `Recipient Management` (or higher) used by the runbook to call `Connect-ExchangeOnline`.
   - **Automation variable** named `ConfiguredMailboxes` — encrypted string variable; can start empty. The runbook appends each processed mailbox identity so subsequent runs skip them.
4. **Modules imported into the Automation account:**
   - `ExchangeOnlineManagement`
   - `Az.Accounts` (transitively required by the modern Automation runtime)

**Run (deployment):**
```powershell
.\ConfigureExchangeMailboxAudit_Runbook.ps1 `
    -resourceGroupName MyAutomationRG `
    -automationAccountName MyAutomationAccount
```

After the runbook publishes, attach it to a schedule via the portal (Automation Account → Runbooks → ConfigureExchangeMailboxAudit → Schedules) or via `Register-AzAutomationScheduledRunbook`.

---

## Audit event sets applied

Both scripts add the following event types to each affected mailbox with `AuditEnabled = $true` and `AuditLogAgeLimit = 365`:

| Audit type | Events |
|------------|--------|
| `AuditAdmin` | `AddFolderPermissions`, `ApplyPriorityCleanup`, `ApplyRecord`, `AttachmentAccess`, `Copy`, `Create`, `FolderBind`, `HardDelete`, `MailItemsAccessed`, `ModifyFolderPermissions`, `Move`, `MoveToDeletedItems`, `PriorityCleanupDelete`, `RecordDelete`, `RemoveFolderPermissions`, `Send`, `SendAs`, `SendOnBehalf`, `SoftDelete`, `Update`, `UpdateCalendarDelegation`, `UpdateComplianceTag`, `UpdateFolderPermissions`, `UpdateInboxRules` |
| `AuditDelegate` | same as `AuditAdmin` minus `Copy`, `MailboxLogin`, `SearchQueryInitiated`, `Send`, `UpdateCalendarDelegation` |
| `AuditOwner` | `AddFolderPermissions`, `ApplyPriorityCleanup`, `ApplyRecord`, `AttachmentAccess`, `Create`, `HardDelete`, `MailboxLogin`, `MailItemsAccessed`, `ModifyFolderPermissions`, `Move`, `MoveToDeletedItems`, `PriorityCleanupDelete`, `RecordDelete`, `RemoveFolderPermissions`, `SearchQueryInitiated`, `Send`, `SoftDelete`, `Update`, `UpdateCalendarDelegation`, `UpdateComplianceTag`, `UpdateFolderPermissions`, `UpdateInboxRules` |
