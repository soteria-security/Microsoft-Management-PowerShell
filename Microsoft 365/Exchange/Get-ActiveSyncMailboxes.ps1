<#
  .SYNOPSIS 
    Audit Exchange mailboxes with ActiveSync enabled
  .DESCRIPTION
    Audit Exchange mailboxes for ActiveSync enabled clients and identify those in use.
  .INPUTS
    None.
  .OUTPUTS
    Text file containing the list of mailboxes with enabled and active ActiveSync statuses
  .EXAMPLE
    ./Get-ActiveSyncMailboxes.ps1
#>




$global:enabled = Get-ExoCASMailbox -ResultSize Unlimited -Filter "Name -notlike '*Discovery*' -and ActiveSyncEnabled -eq $true" | Select-Object DisplayName,ActiveSyncEnabled
    
$global:inUse = Get-ExoCASMailbox -ResultSize Unlimited -PropertySets ActiveSync -Filter "HasActiveSyncDevicePartnership -eq $true" | Select-Object DisplayName,ActiveSyncEnabled,HasActiveSyncDevicePartnership


Function Get-Data {

  foreach ($account in $enabled){
    Write-output $account.DisplayName "has ActiveSync enabled."
  }

  foreach ($mailbox in $inUse.DisplayName){
    if ($enabled -contains $mailbox){
      Write-output $mailbox "is actively using ActiveSync."
    }
  }
}


Function Colorize($ForeGroundColor){
  $color = $Host.UI.RawUI.ForegroundColor
  $Host.UI.RawUI.ForegroundColor = $ForeGroundColor

  if ($args){
    Write-Output $args
  }

  $Host.UI.RawUI.ForegroundColor = $color
}

$message1 = Write-Output "Exchange ActiveSync is an Exchange synchronization protocol that's optimized to work together with high-latency and low-bandwidth networks. `nThe protocol, based on HTTP and XML, lets mobile phones access an organization's information on a server that's running Microsoft Exchange.`n"
$message2 = Write-output "It is recommended to disable ActiveSync on all accounts and instead rely on good Mobile Device Management (MDM), or Mobile Application Management (MAM) practices. `nThese options, coupled with the Modern Authentication technologies now incorporated into Microsoft applications, allow for a more secure connection to tenant resources.`n"

Colorize Red ($message1)
Colorize Yellow ($message2)

Get-Data | Out-File "ActiveSyncMailboxes.txt" -Append