<#
  .SYNOPSIS 
    Starting January 2025, Microsoft added a feature to Outlook that enables auto-mapping of a user's calendars. In shared mailboxes, this can result in multiple calendars being auto-mapped. It is recommended to disable this ability.
  .DESCRIPTION
    Starting January 2025, Microsoft added a feature to Outlook that enables auto-mapping of a user's calendars. In shared mailboxes, this can result in multiple calendars being auto-mapped. It is recommended to disable this ability.
    This script discovers all shared mailboxes, and all users whose calendars would be auto-mapped, and disables this setting.
  .INPUTS
    None.
  .OUTPUTS
    None
  .EXAMPLE
    ./Remove-CalendarAutoMappingSharedMailbox.ps1
#>

$sharedMailboxes = Get-EXOMailbox -Filter { recipienttypedetails -eq "SharedMailbox" }

Function Remove-CalendarAutoMappingSharedMailbox {
    ForEach ($mailbox in $sharedMailboxes) {
        $fullAccess = Get-Mailbox -Identity $mailbox.PrimarySmtpAddress | Foreach-Object { Get-MailboxPermission $_ | Where-Object { ($_.User -ne 'NT AUTHORITY\SELF') -and ($_.AccessRights -eq 'FullAccess') } }
        
        ForEach ($user in $fullAccess) {
            Write-Host "Removing Auto-mapping from $($mailbox.Alias)"
            Remove-MailboxPermission -Identity $mailbox.PrimarySmtpAddress -User $user.user -AccessRights FullAccess -Confirm:$false

            Add-MailboxPermission -Identity $mailbox.PrimarySmtpAddress -User $user.user -AccessRights FullAccess -AutoMapping:$false
        }
    }
}

Remove-CalendarAutoMappingSharedMailbox