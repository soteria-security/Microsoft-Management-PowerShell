# Microsoft Active Directory

## Purpose
Scripts in this folder assist administrators with auditing and managing an on-premises Active Directory environment.

## Prerequisites
All scripts here use the `ActiveDirectory` PowerShell module and must run from a host that can resolve and reach a Domain Controller:

- A domain-joined workstation or member server with **Remote Server Administration Tools (RSAT) — Active Directory** installed, **or**
- A Domain Controller (`Active Directory Domain Services` role installed).

The signed-in user must have **Domain Admin** (or equivalent) rights to make the changes these scripts perform. No `Connect-*` cmdlet is required — the `ActiveDirectory` module uses the current Kerberos session.

> Install RSAT (Windows 10/11):
> ```powershell
> Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
> ```

---

## Scripts

### Emergency-AD-Password-Reset.ps1
> ⚠ **WARNING** — last-resort recovery script. Forces a password reset on **every** Active Directory account: standard users, the built-in Administrator (`-500`), Guest (`-501`), and the `krbtgt` Kerberos account (`-502`), unless explicitly excluded. The Guest account is disabled if found enabled.
>
> Before running this, attempt the documented [AD Forest Recovery](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-perform-initial-recovery) procedure. The script requires the operator to type `I AGREE` (case-sensitive) at the confirmation prompt before any change is made.

**Behavior summary:**
- Standard users: generates a new password (length range prompted at runtime), clears `PasswordNeverExpires`, and sets `ChangePasswordAtLogon = $true`.
- Built-in `-500`, `-501`, `-502` accounts: generates a 120–128 character password and resets without forcing change-at-logon (the krbtgt account in particular must not be reset twice in rapid succession — wait at least 10 hours between resets per Microsoft guidance).

**Parameters:**
- `-ExcludedUsers` — array of SamAccountNames to leave untouched. Useful for at least one break-glass admin account.

**Run:**
```powershell
.\Emergency-AD-Password-Reset.ps1 -ExcludedUsers userAdmin1, userAdmin2
```

---

### Invoke-StaleUserCleanup.ps1
Finds every enabled user whose `LastLogonDate` is older than `-range` days and either disables them (default) or reports on them (`-reportOnly`). Accounts that look like service accounts (any `servicePrincipalName` set, excluding `krbtgt`) are written to `Potential_Service_Accounts.csv` and **never disabled** — they require manual review. Disabled accounts have their `Description` field stamped with `Disabled by <admin> on <date>`. A full transcript is written to `Disabled_Users_<date>.log` in the script directory.

**Parameters:**
- `-range` *(required)* — integer; accounts with no logon for more than this many days are considered stale.
- `-reportOnly` *(optional switch)* — when present, displays the disable candidates in `Out-GridView` instead of disabling them.

**Run:**
```powershell
# Disable every enabled non-service account with no logon in 90 days
.\Invoke-StaleUserCleanup.ps1 -range 90

# Report-only mode — opens an Out-GridView of accounts that would be disabled
.\Invoke-StaleUserCleanup.ps1 -range 90 -reportOnly
```

> Note: `Out-GridView` requires the `Microsoft.PowerShell.GraphicalTools` module on PowerShell 7+ (it ships built-in only with Windows PowerShell 5.1).
