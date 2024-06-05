[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]
    $resourceGroupName,
    [Parameter(Mandatory = $true)]
    [string]
    $automationAccountName
)

$runbookName = "ConfigureExchangeMailboxAudit"

$runbookContent = @"
`$AuditAdmin = @('AddFolderPermissions','ApplyPriorityCleanup','ApplyRecord','AttachmentAccess','Copy','Create','FolderBind','HardDelete','MailItemsAccessed','ModifyFolderPermissions','Move','MoveToDeletedItems','PriorityCleanupDelete','RecordDelete','RemoveFolderPermissions','Send','SendAs','SendOnBehalf','SoftDelete','Update','UpdateCalendarDelegation','UpdateComplianceTag','UpdateFolderPermissions','UpdateInboxRules')

`$AuditDelegate = @('AddFolderPermissions','ApplyPriorityCleanup','ApplyRecord','AttachmentAccess','Create','FolderBind','HardDelete','MailItemsAccessed','ModifyFolderPermissions','Move','MoveToDeletedItems','PriorityCleanupDelete','RecordDelete','RemoveFolderPermissions','SendAs','SendOnBehalf','SoftDelete','Update','UpdateComplianceTag','UpdateFolderPermissions','UpdateInboxRules')

`$AuditOwner = @('AddFolderPermissions','ApplyPriorityCleanup','ApplyRecord','AttachmentAccess','Create','HardDelete','MailboxLogin','MailItemsAccessed','ModifyFolderPermissions','Move','MoveToDeletedItems','PriorityCleanupDelete','RecordDelete','RemoveFolderPermissions','SearchQueryInitiated','Send','SoftDelete','Update','UpdateCalendarDelegation','UpdateComplianceTag','UpdateFolderPermissions','UpdateInboxRules')

`$UserCredential = Get-AutomationPSCredential -Name 'ExchangeAuditlogConf'

Connect-ExchangeOnline -Credential `$UserCredential -ShowProgress `$true

`$ConfiguredMailboxes = Get-AutomationVariable -Name 'ConfiguredMailboxes'

`$allMailboxes = Get-Mailbox -ResultSize Unlimited

foreach (`$mailbox in `$allMailboxes) {
    if (`$ConfiguredMailboxes -notcontains `$mailbox.Identity) {
        Set-Mailbox -Identity `$mailbox.Identity -AuditEnabled `$true -AuditLogAgeLimit 365 -AuditAdmin @{add=`$AuditAdmin} -AuditDelegate @{add=`$AuditDelegate} -AuditOwner @{add=`$AuditOwner}

        `$ConfiguredMailboxes += `$mailbox.Identity
    }
}

Set-AutomationVariable -Name 'ConfiguredMailboxes' -Value `$ConfiguredMailboxes

Disconnect-ExchangeOnline -Confirm:`$false
"@

$null = New-AzAutomationRunbook -ResourceGroupName $resourceGroupName -AutomationAccountName $automationAccountName -Name $runbookName -Type PowerShell -Content $runbookContent

Publish-AzAutomationRunbook -ResourceGroupName $resourceGroupName -AutomationAccountName $automationAccountName -Name $runbookName