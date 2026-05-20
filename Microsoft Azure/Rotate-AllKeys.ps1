<#
.SYNOPSIS
    Rotate every access key on every storage account in the current Az subscription.
.DESCRIPTION
    Enumerates all storage accounts in the subscription returned by Get-AzContext, then
    regenerates each access key (key1, key2, kerb1, kerb2 — whatever the account has)
    via New-AzStorageAccountKey. Any application or service still using the old keys
    will lose access until updated.
.NOTES
    Requires Az.Storage and an authenticated Az session (Connect-AzAccount).
    Caller must hold Storage Account Contributor or Storage Account Key Operator
    Service Role on each storage account.
.EXAMPLE
    Connect-AzAccount
    Set-AzContext -SubscriptionId <subscription-id>
    .\Rotate-AllKeys.ps1
#>

Function Rotate-AllKeys {
    $storageAccounts = Get-AzStorageAccount

    foreach ($sa in $storageAccounts) {
        $keys = Get-AzStorageAccountKey -Name $sa.StorageAccountName -ResourceGroupName $sa.ResourceGroupName
        foreach ($key in $keys) {
            New-AzStorageAccountKey -ResourceGroupName $sa.ResourceGroupName -Name $sa.StorageAccountName -KeyName $key.KeyName
        }
    }
}

Rotate-AllKeys
