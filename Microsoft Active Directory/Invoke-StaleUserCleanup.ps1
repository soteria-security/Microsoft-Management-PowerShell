[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [Int32]
    $range,
    [Parameter(Mandatory = $true)]
    [switch]
    $reportOnly
)
# Import the Active Directory Module
Import-module activedirectory

$admin = $env:USERNAME

$day = Get-Date -Format g

$date = get-date

Start-Transcript -IncludeInvocationHeader -Path "$psscriptroot\Disabled_Users_$date.log"

$stale_accounts = Get-ADUser -filter { Enabled -eq $true } -properties LastLogonDate | Where-Object { ($_.samaccountname -notlike "krbtgt*") -and ($_.lastlogondate -lt (Get-Date).adddays(-$range)) }

$serviceAccts = $stale_accounts | Where-Object { ($_.ServicePrincipalNames -like "*") -and ($_.samaccountname -notlike "krbtgt") }

$serviceAccts | Export-Csv "$psscriptroot\Potential_Service_Accounts.csv" -NoTypeInformation

$toDisable = $stale_accounts | Where-Object { $_ -notin $serviceAccts }

Write-Host "$($stale_accounts.count) stale accounts were found. $($serviceAccts.Count) possible Service Accounts were found.`nPotential Service Accounts will not be modified and can be reviewed in the output file $psscriptroot\Potential_Service_Accounts.csv. $($toDisable.count) accounts will be disabled.`nA log of all activity will be recorded in $psscriptroot\Disabled_Users_$date.log"

If (! $reportOnly.IsPresent) {
    Foreach ($account in $toDisable) {
        Write-Host "Disabling $account with description Disabled by $admin on $day."
        Disable-ADAccount -identity $account
        Set-ADUser $account -Description "Disabled by $admin on $day"
    }
}
Else {
    $toDisable | Out-GridView
}

Stop-Transcript