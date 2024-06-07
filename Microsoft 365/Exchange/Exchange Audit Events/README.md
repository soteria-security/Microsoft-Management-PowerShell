# Microsoft Exchange Online and Microsoft Entra

# Purpose
Scripts provided are intended to assist administrators in auditing and managing their Microsoft Exchange Online environment.


# Scripts
- Enumerate-PrivilegedGroups: Creates a new user account in the Entra ID environment and sets the Exchange Audit Log Event Types to capture for the account. Supplements the blog [Better Visibility — New Standard Logs in Microsoft Purview Audit](https://blog.soteria.io/better-visibility-new-standard-logs-in-microsoft-purview-audit-16ec7d000bab). Creates an authenticated Microsoft Exchange Online and Microsoft Graph session with "User.ReadWrite.All", "Directory.ReadWrite.All", "GroupMember.ReadWrite.All", "Group.ReadWrite.All", and "Directory.AccessAsUser.All" Microsoft Graph Scopes.

   ```
  # Example Execution:
    .\Account_Provisioning.ps1 -firstName John -lastName Doe -domain contoso.com -startDate 01/01/1970

  # Alternative Parameters -Department and -userManager
    .\Account_Provisioning.ps1 -firstName John -lastName Doe -domain contoso.com -startDate 01/01/1970 -Department Sales -userManager jsmith@contoso.com
   ```
- ConfigureExchangeMailboxAudit_Runbook: Creates an Azure Runbook that sets the Exchange Audit Log Event Types to capture for all accounts. Designed to be incorporated into automation and run on a scheduled basis. __Does not create a schedule or automation.__ Supplements the blog [Better Visibility — New Standard Logs in Microsoft Purview Audit](https://blog.soteria.io/better-visibility-new-standard-logs-in-microsoft-purview-audit-16ec7d000bab).
