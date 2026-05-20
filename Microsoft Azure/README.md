# Microsoft Azure

## Purpose
Scripts in this folder assist administrators with auditing and managing a Microsoft Azure subscription. All scripts require the `Az` PowerShell module and an authenticated session via `Connect-AzAccount`.

> Install the Az module once:
> ```powershell
> Install-Module Az -Scope CurrentUser -Force
> ```

---

## Scripts

### Rotate-AllKeys.ps1
> ⚠ **WARNING** — regenerates **every access key** on **every storage account** in the currently selected subscription. Any application, function app, or service still using the previous keys will lose access until updated. Prefer scheduled rotation via [Azure Key Vault managed key rotation](https://learn.microsoft.com/en-us/azure/key-vault/keys/how-to-configure-key-rotation) where possible; use this script for one-shot emergency rotation only.

The script enumerates storage accounts via `Get-AzStorageAccount`, then calls `New-AzStorageAccountKey` against each key name returned by `Get-AzStorageAccountKey` (e.g., `key1`, `key2`, plus `kerb1` / `kerb2` if Azure AD Kerberos is enabled).

**Scope:** the current `Get-AzContext` subscription. To rotate keys across multiple subscriptions, run the script once per subscription after switching context with `Set-AzContext -SubscriptionId <id>`.

**Required role on each storage account:**
- `Storage Account Contributor`, **or**
- `Storage Account Key Operator Service Role`

**Connect:**
```powershell
Connect-AzAccount
Set-AzContext -SubscriptionId <subscription-id>
```

**Run:**
```powershell
.\Rotate-AllKeys.ps1
```

**After rotation:** update any consuming services (App Service connection strings, Function App application settings, AzCopy scripts, Logic Apps, Storage Explorer profiles, etc.) with the new key values before the cached old key expires.
