# Microsoft-Management-PowerShell

A collection of PowerShell scripts to aid in auditing, managing, and maintaining Microsoft environments — Microsoft 365 (Entra ID + Exchange Online), on-premises Active Directory, Microsoft Azure, and Windows endpoints.

## Repository layout

| Folder | Contents |
|--------|----------|
| [`Microsoft 365/Entra ID/`](./Microsoft%20365/Entra%20ID/README.md) | Entra ID auditing & hardening — privileged group enumeration, owned-object reports, session revocation, PowerShell module restriction, dangerous-default remediation, stale-account detection, OWA Conditional Access policy creation. |
| [`Microsoft 365/Exchange/`](./Microsoft%20365/Exchange/README.md) | Exchange Online operations — block external auto-forwarding, seek-and-destroy mail purge, ActiveSync audit, mail-domain DMARC/SPF/DKIM validation, shared-mailbox sign-in lockdown, calendar auto-mapping cleanup. |
| [`Microsoft 365/Exchange/Exchange Audit Events/`](./Microsoft%20365/Exchange/Exchange%20Audit%20Events/README.md) | Per-mailbox audit configuration — on-demand provisioning script and Azure Automation runbook deployment. |
| [`Microsoft Active Directory/`](./Microsoft%20Active%20Directory/README.md) | On-prem AD operations — emergency tenant-wide password reset, stale user cleanup. |
| [`Microsoft Azure/`](./Microsoft%20Azure/README.md) | Azure subscription operations — bulk storage account key rotation. |
| [`Microsoft Windows/`](./Microsoft%20Windows/README.md) | Windows endpoint tooling — enable command-line / PowerShell auditing, interactive PC info collector. |

## Prerequisites by area

| Area | Module(s) | Authentication |
|------|-----------|----------------|
| Entra ID | `Microsoft.Graph` (+ `ImportExcel` for the owned-objects report) | `Connect-MgGraph -Scopes <scope list>` |
| Exchange Online | `ExchangeOnlineManagement` (**v3.9.0+** for Seek-and-Destroy) | `Connect-ExchangeOnline`; some scripts also need `Connect-IPPSSession` |
| Active Directory | `ActiveDirectory` (RSAT) | Domain Kerberos session |
| Azure | `Az` | `Connect-AzAccount` + `Set-AzContext` |
| Windows | (built-in providers) | Local Administrator on target hosts; WinRM/WMI where indicated |

Each folder's `README.md` lists the exact scopes/roles, parameters, and runnable examples per script.

---

### All scripts are provided "AS-IS" and without warranty or guarantee.
