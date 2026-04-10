# Microsoft Entra

# Purpose
Scripts provided are intended to assist administrators in auditing and managing their Microsoft Entra environment.


# Scripts
- Enumerate-PrivilegedGroups: Queries the Entra ID environment and returns details about all groups including Group Type, Assigned Licenses, Assigned Azure or Entra Roles, Group Members, and more. Requires an already authenticated Microsoft Graph session with "Directory.Read.All", "GroupMember.Read.All", and "RoleManagement.Read.Directory" Microsoft Graph Scopes.

   ```
  Connect-MgGraph -ContextScope Process -Scopes "Directory.Read.All", "GroupMember.Read.All", "RoleManagement.Read.Directory"
   ```
- Find-AppLicensedUsers: Queries the Entra ID environment using either the MSOL or Microsoft Graph PowerShell module to find all users with defined applications licensed/enabled. Example: Find all users with Yammer enabled. Requires an already authenticated MSOL or Microsoft Graph session with "Directory.Read.All", "GroupMember.Read.All", and "RoleManagement.Read.Directory" Microsoft Graph Scopes.

  ```
  Connect-MgGraph -ContextScope Process -Scopes "Directory.Read.All", "GroupMember.Read.All", "RoleManagement.Read.Directory"
  ```
- Invoke-KillAllSessions: Forces all current Microsoft Entra signed-in users to disconnect. Creates an authenticated Microsoft Graph session with the necessary scopes.
- Invoke-KillSession: Forces specified Microsoft Entra signed-in user to disconnect. Creates an authenticated Microsoft Graph session with the necessary scopes.
- Invoke-PowerShellRestrictions: Restricts Azure AD, PnP SharePoint, Microsoft Intune, Microsoft Azure, Azure CLI, and Microsoft Graph PowerShell Modules to Explicitly Assigned Users. If Application Service Principals (Enterprise Applications) do not exist, this script will create them. Requires an authenticated Microsoft Graph session with "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "Directory.ReadWrite.All", "GroupMember.Read.All", and "RoleManagement.Read.Directory" Microsoft Graph Scopes.

  ```
  Connect-MgGraph -ContextScope Process -Scopes "Directory.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "Application.ReadWrite.All", "GroupMember.Read.All", "RoleManagement.Read.Directory"
  ```
- Remediate-DangerousDefaults: Restrict default guest and user permissions that allow self-service account creation, guest invitations, application consents, application creation, and more. Create Conditional Access Policy to restrict Microsoft Admin Portals. It is recommended to review and modify the options of the script to meet organizational needs. Requires an already authenticated Microsoft Graph session with "Directory.Read.All", "Policy.ReadWrite.Authorization", and "Policy.ReadWrite.ConditionalAccess" Microsoft Graph Scopes.

  ```
  Connect-MgGraph -ContextScope Process -Scopes "Directory.ReadWrite.All", "Policy.ReadWrite.Authorization", "Policy.ReadWrite.ConditionalAccess"
  ```

- Invoke-StaleAccountDetection: Identifies stale user accounts (no activity for 60+ days) across hybrid on-prem Active Directory, Entra ID, and Exchange Online by correlating identities using the immutable ID (Base64-encoded `objectGUID`). Aggregates last activity from AD (`lastLogonTimestamp`), Entra (`signInActivity` via Microsoft Graph), and Exchange mailbox usage (`LastLogonTime` via Exchange Online PowerShell). Automatically excludes shared, room, and equipment mailboxes. Outputs a consolidated report of stale accounts with unified identity attributes and activity timestamps. Requires connectivity to on-prem AD, an authenticated Graph session with `User.Read.All` and `AuditLog.Read.All`, and an active Exchange Online session.

```
Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All"

Connect-ExchangeOnline -ShowBanner:$false
```