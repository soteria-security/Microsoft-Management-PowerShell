<#
.Synopsis
    Connect to Exchange Online, enter email address or domain, automate block and Content Search to remove emails from the specified sender
.DESCRIPTION
    Connect to Exchange Online, enter email address or domain, automate block and Content Search to remove emails from the specified sender
.COMPONENT
    Exchange Online PowerShell Module, and sufficient rights to change admin accounts
.INPUTS
    Admin Credentials (UserPrincipalName), Sender's email address, Delete Type (Hard or Soft)
.ROLE
    Exchange Admin or Global Admin and eDiscovery Manager or eDiscovery Admin roles
.FUNCTIONALITY
    Connect to Exchange Online, enter email address or domain, automate block and Content Search to remove emails from the specified sender
.Example
    ./Exchange-SeekandDestroy.ps1 -AdminAccount myadmin@mydomain.com -BySender -DeleteType Hard

.Example
    ./Exchange-SeekandDestroy.ps1 -AdminAccount myadmin@mydomain.com -BySubject -DeleteType Hard
#>

param (
    [Parameter(Mandatory = $true,
        HelpMessage = 'Admin or Auditor Username')]
    [string] $AdminAccount,
    [Parameter(Mandatory = $false,
        HelpMessage = 'Search by Sender')]
    [switch] $BySender,
    [Parameter(Mandatory = $false,
        HelpMessage = 'Search by Subject')]
    [switch] $BySubject,
    [Parameter(Mandatory = $true,
        HelpMessage = 'Delete Type for Discovered Messages')]
    [ValidateSet('Hard', 'Soft',
        IgnoreCase = $true)]
    [string] $DeleteType
)

#Get the date in desired format
$global:date = Get-Date -f dd-MM-yyyy

#Define the content search name
$global:searchName = ""

Function Confirm-Close {
    Read-Host "Press Enter to Exit"
    Exit
}

Function Colorize($ForeGroundColor) {
    $color = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = $ForeGroundColor
  
    if ($args) {
        Write-Output $args
    }
  
    $Host.UI.RawUI.ForegroundColor = $color
}

Function Connect-Service {
    Connect-ExchangeOnline -UserPrincipalName $AdminAccount
    Connect-IPPSSession -UserPrincipalName $AdminAccount
}

Function Confirm-InstalledModules {
    #Check for required Modules and prompt for install if missing
    $modules = @("ExchangeOnlineManagement")
    $count = 0
    $installed = Get-InstalledModule | Select-Object Name

    foreach ($module in $modules) {
        if ($installed.Name -notcontains $module) {
            $message = Write-Output "`n$module is not installed."
            $message1 = Write-Output "The module may be installed by running 'Install-Module $module -Force -Scope CurrentUser -Confirm:$false' in an elevated PowerShell window."
            Colorize Red ($message)
            Colorize Yellow ($message1)
            $install = Read-Host -Prompt "Would you like to attempt installation now? (Y|N)"
            If ($install -eq 'y') {
                Install-Module $module -Scope CurrentUser -Force -Confirm:$false
                $count ++
            }
        }
        Else {
            Write-Output "$module is installed."
            $count ++
        }
    }

    If ($count -lt 1) {
        Write-Output ""
        Write-Output ""
        $message = Write-Output "Dependency checks failed. Please install all missing modules before running this script."
        Colorize Red ($message)
        Confirm-Close
    }
    Else {
        Connect-Service
    }

}

Confirm-InstalledModules

Function Add-BlockedSender ($SendingUser) {
    #Check the size of the Tenant block list
    $listSender = Get-TenantAllowBlockListItems -ListType Sender -Block

    #Get the item count in the block lists
    If ($listSender.Count -le 1000) {
        #Determine how many more entries can be added and alert the user
        $sum = 1000 - $listSender.Count

        #Let the user know what's happening
        Write-Output "Microsoft limits the total number of entries in the Tenant block lists to 1,000 entries. You have $($sum) remaining."
        Write-Output "Adding $($SendingUser) to the Tenant Block list."

        #Do the things
        New-TenantAllowBlockListItems -ListType Sender -Block -Entries $SendingUser -NoExpiration -Notes "Added to block list on $($global:date) by $($AdminAccount)."
    }
    Else {

        #Let the user know what's happening
        Write-Output "Tenant list maximum size exceeded. Blocking via user's mailboxes instead."
        Write-Output "Adding $($SendingUser) to all mailboxes Block list."
        
        Get-Mailbox -ResultSize Unliimited | Set-MailboxJunkEmailConfiguration -BlockedSendersandDomains @{Add = $SendingUser }
    }

    Connect-IPPSSession -UserPrincipalName $AdminAccount
}

Function New-Search ($selection) {
    #Update the user
    Write-Output "Creating the content search"

    #Create the content search
    New-ComplianceSearch -Name $global:searchName -ExchangeLocation all -AllowNotFoundExchangeLocationsEnabled $true -ContentMatchQuery $selection -Confirm:$false

    #Update the user
    Write-Output "Beginning the search."

    #Run content search
    Start-ComplianceSearch $global:searchName
}

Function Invoke-BySender {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            HelpMessage = 'Email Address or Domain to Block')]
        [string] $SendingUser
    )

    #Define the content search name
    $global:searchName = "$($SendingUser)_Search_$($global:date)"

    Add-BlockedSender -SendingUser $SendingUser

    New-Search -selection "From:$SendingUser"
}

Function Invoke-BySubject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            HelpMessage = 'Email Address or Domain to Block')]
        [string] $subject
    )

    #Define the content search name
    $global:searchName = "$($subject)_Search_$($global:date)"

    New-Search -selection "Subject:$subject"
}

If ($BySender.IsPresent) {
    Invoke-BySender
}
ElseIf ($BySubject.IsPresent) {
    Invoke-BySubject
}
Else {
    Invoke-BySender
}

Function Start-Cleanup {
    #Export the results for documentation purposes
    New-ComplianceSearchAction $global:searchName -Preview

    #Update the user
    Write-Output "Exporting the results of the search for review. Please check this directory for a file named $($global:searchName)_Report.txt"
    
    (Get-ComplianceSearchAction "$($global:searchName)_Preview").Results | Out-File "$($global:searchName)_Report.txt"

    New-ComplianceSearchAction -SearchName "$($global:searchName)" -Purge -PurgeType $DeleteType -Force -Confirm:$false
    
    Get-ComplianceSearchAction "$($global:searchName)_Purge"
}

Function Get-SearchStatus {
    $search = Get-ComplianceSearch $global:searchName

    $status = $search.Status

    If ($status -ne "Completed") {
        do {
            $search = Get-ComplianceSearch $global:searchName
            $status = $search.Status
            Start-Sleep -Seconds 30
        } until ($status -eq "Completed")
    }
    
    If ($status -eq "Completed") {
        Start-Cleanup
    }
}


Get-SearchStatus