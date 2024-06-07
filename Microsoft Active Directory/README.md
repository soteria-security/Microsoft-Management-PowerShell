# Microsoft Active Directory

# Purpose
Scripts provided are intended to assist administrators in auditing and managing their Microsoft Active Directory environment.


# Scripts
- Emergency-AD-Password-Reset: __WARNING!__ This script forces password resets on ALL Active Directory accounts - All users, Built-In Admin, Guest and Kerberos accounts included, unless explicitly excluded, and is intended only as a last resort for an emergency recovery of an Active Directory environment. When possible, booting the environment into Safe Mode to [Recover Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-perform-initial-recovery) should be attempted instead.

```
# Execution Example:
.\Emergency-AD-Password-Reset.ps1 -ExcludedUsers userAdmin@contoso.local, userAdmin2@contoso.local
```
- Invoke-StaleUserCleanup: Identifies and disables all user accounts that are enabled and have not logged in in $N days (Stale accounts). Alternatively, identify and generate a report of all accounts that are enabled and have not logged in in $N days (Stale accounts).

```
# Execution Example
./Invoke-StaleUserCleanup.ps1 -range 90

# Report Only Mode
./Invoke-StaleUserCleanup.ps1 -range 90 -reportOnly
```