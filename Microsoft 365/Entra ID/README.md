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
- Invoke-PowerShellRestrictions: Restricts Azure AD, PnP SharePoint, Microsoft Intune, Microsoft Azure, and Microsoft Graph PowerShell Modules to Explicitly Assigned Users. If Application Service Principals (Enterprise Applications) do not exist, this script will create them. Requires an authenticated Microsoft Graph session with "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "Directory.ReadWrite.All", "GroupMember.Read.All", and "RoleManagement.Read.Directory" Microsoft Graph Scopes.

  ```
  Connect-MgGraph -ContextScope Process -Scopes "Directory.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "Application.ReadWrite.All", "GroupMember.Read.All", "RoleManagement.Read.Directory"
  ```
