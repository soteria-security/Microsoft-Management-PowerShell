# Microsoft Entra

# Purpose
Scripts provided are intended to assist administrators in auditing and managing their Microsoft Exchange Online environment.


# Scripts
- Block Auto-Forwarding: Creates an Exchange Transport Rule to block all AutoForward messages to external recipients. Requires an already authenticated Microsoft Exchange Online PowerShell session with sufficient permissions.

```
# Execution Example:
& ".\Block Auto-Forwarding.ps1"
```
- Exchange-SeekandDestroy:  Connect to Exchange Online, enter email address or domain, automate block and Content Search to remove emails from the specified sender. Requires an authenticated Microsoft Exchange Online PowerShell session with sufficient permissions.

```
./Exchange-SeekandDestroy.ps1 -AdminAccount myadmin@mydomain.com -Sender badguy@maliciousdomain.com -DeleteType Hard
```
- Get-ActiveSyncMailboxes: Audit Exchange mailboxes with ActiveSync enabled. Requires an already authenticated Microsoft Exchange Online PowerShell session with sufficient permissions.

```
./Get-ActiveSyncMailboxes.ps1
```
- Get-MailDomainStatus: Gather Exchange Mail Domains, Check and Validate DMARC, SPF, and DKIM Records for Domains in use. Requires an already authenticated Microsoft Exchange Online PowerShell session with sufficient permissions.

```
./Get-MailDomainsStatus.ps1 -Domains domain1,domain2,domain3
```