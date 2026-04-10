<#
.SYNOPSIS
    Connect to Exchange Online and Microsoft Purview to block senders and purge phishing/spam emails
    
.DESCRIPTION
    This script automates the process of:
    1. Blocking a sender at the tenant level
    2. Creating a compliance search to find emails from that sender
    3. Purging those emails from all mailboxes
    
    Updated for ExchangeOnlineManagement v3.9.0+ requirements (August 2025)
    
.PARAMETER AdminAccount
    Admin Username (UserPrincipalName) with proper permissions
    
.PARAMETER BySender
    Search and remove emails by sender address or domain
    
.PARAMETER BySubject
    Search and remove emails by subject line
    
.PARAMETER DeleteType
    Type of deletion: Hard (permanent) or Soft (recoverable)
    
.NOTES
    Requirements:
    - ExchangeOnlineManagement module v3.9.0 or later
    - Roles: eDiscovery Manager or eDiscovery Administrator
    - Roles: Search and Purge role (Organization Management or Data Investigator role groups)
    - Valid Microsoft 365 license assigned to admin account
    
    Limitations:
    - Maximum 100 items per mailbox can be purged at once
    - Unindexed items are not deleted
    - Items from Microsoft Teams are not deleted
    
.EXAMPLE
    .\Exchange-SeekandDestroy-Updated.ps1 -AdminAccount admin@contoso.com -BySender -DeleteType Hard
    
.EXAMPLE
    .\Exchange-SeekandDestroy-Updated.ps1 -AdminAccount admin@contoso.com -BySubject -DeleteType Soft
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = 'Admin Username (UPN)')]
    [string]$AdminAccount,
    
    [Parameter(Mandatory = $false, HelpMessage = 'Search by Sender')]
    [switch]$BySender,
    
    [Parameter(Mandatory = $false, HelpMessage = 'Search by Subject')]
    [switch]$BySubject,
    
    [Parameter(Mandatory = $true, HelpMessage = 'Delete Type for Discovered Messages')]
    [ValidateSet('Hard', 'Soft', IgnoreCase = $true)]
    [string]$DeleteType
)

# Global variables
$global:date = Get-Date -Format "dd-MM-yyyy"
$global:searchName = ""
$global:purgeInProgress = $false

#region Helper Functions

Function Write-ColorOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Green', 'Yellow', 'Red', 'Cyan', 'White')]
        [string]$Color = 'White'
    )
    
    Write-Host $Message -ForegroundColor $Color
}

Function Confirm-Close {
    Read-Host "`nPress Enter to Exit"
    Exit
}

Function Test-ModuleVersion {
    <#
    .SYNOPSIS
    Verifies ExchangeOnlineManagement module meets minimum version requirement
    #>
    
    $requiredVersion = [Version]"3.9.0"
    $installedModule = Get-InstalledModule -Name "ExchangeOnlineManagement" -ErrorAction SilentlyContinue
    
    if (-not $installedModule) {
        Write-ColorOutput "ERROR: ExchangeOnlineManagement module is not installed." -Color Red
        Write-ColorOutput "Install with: Install-Module ExchangeOnlineManagement -Force -Scope CurrentUser" -Color Yellow
        return $false
    }
    
    $installedVersion = [Version]$installedModule.Version
    
    if ($installedVersion -lt $requiredVersion) {
        Write-ColorOutput "ERROR: ExchangeOnlineManagement v$installedVersion is installed, but v$requiredVersion or later is required." -Color Red
        Write-ColorOutput "Update with: Update-Module ExchangeOnlineManagement -Force" -Color Yellow
        Write-ColorOutput "You may need to uninstall older versions first." -Color Yellow
        return $false
    }
    
    Write-ColorOutput "ExchangeOnlineManagement v$installedVersion is installed (minimum v$requiredVersion required)." -Color Green
    return $true
}

Function Connect-Services {
    <#
    .SYNOPSIS
    Connects to Exchange Online and Security & Compliance PowerShell
    .DESCRIPTION
    IMPORTANT: For purge operations, the -EnableSearchOnlySession switch is REQUIRED
    as of ExchangeOnlineManagement v3.9.0 (August 2025)
    #>
    
    try {
        Write-ColorOutput "`nConnecting to Exchange Online..." -Color Cyan
        Connect-ExchangeOnline -UserPrincipalName $AdminAccount -ShowBanner:$false -ErrorAction Stop
        Write-ColorOutput "Successfully connected to Exchange Online." -Color Green
        
        Write-ColorOutput "`nConnecting to Security & Compliance PowerShell with Search-Only Session..." -Color Cyan
        Write-ColorOutput "(Required for purge operations as of August 2025)" -Color Yellow
        Connect-IPPSSession -UserPrincipalName $AdminAccount -EnableSearchOnlySession -ShowBanner:$false -ErrorAction Stop
        Write-ColorOutput "Successfully connected to Security & Compliance PowerShell." -Color Green
        
        return $true
    }
    catch {
        Write-ColorOutput "`nERROR: Failed to connect to services." -Color Red
        Write-ColorOutput "Error: $($_.Exception.Message)" -Color Red
        return $false
    }
}

Function Add-SenderToBlockList {
    <#
    .SYNOPSIS
    Adds sender to tenant block list or individual mailbox block lists
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$SendingUser
    )
    
    try {
        # Check current tenant block list size
        $listSender = Get-TenantAllowBlockListItems -ListType Sender -Block -ErrorAction SilentlyContinue
        $currentCount = if ($listSender) { $listSender.Count } else { 0 }
        
        if ($currentCount -lt 1000) {
            $remaining = 1000 - $currentCount
            Write-ColorOutput "`nTenant block list has $remaining of 1000 slots available." -Color Cyan
            Write-ColorOutput "Adding '$SendingUser' to tenant block list..." -Color Yellow
            
            New-TenantAllowBlockListItems -ListType Sender -Block -Entries $SendingUser -NoExpiration     -Notes "Blocked on $global:date by $AdminAccount via seek-and-destroy script" -ErrorAction Stop
            
            Write-ColorOutput "Successfully added to tenant block list." -Color Green
        }
        else {
            Write-ColorOutput "`nWARNING: Tenant block list is at maximum capacity (1000 entries)." -Color Yellow
            Write-ColorOutput "Adding '$SendingUser' to individual mailbox block lists instead..." -Color Yellow
            
            $mailboxes = Get-Mailbox -ResultSize Unlimited
            $successCount = 0
            
            foreach ($mailbox in $mailboxes) {
                try {
                    Set-MailboxJunkEmailConfiguration -Identity $mailbox.Identity -BlockedSendersAndDomains @{Add = $SendingUser } -ErrorAction Stop
                    $successCount++
                }
                catch {
                    Write-ColorOutput "Failed to update mailbox: $($mailbox.UserPrincipalName)" -Color Red
                }
            }
            
            Write-ColorOutput "Added to $successCount mailbox block lists." -Color Green
        }
    }
    catch {
        Write-ColorOutput "ERROR: Failed to add sender to block list." -Color Red
        Write-ColorOutput "Error: $($_.Exception.Message)" -Color Red
    }
}

Function New-ComplianceContentSearch {
    <#
    .SYNOPSIS
    Creates and starts a compliance search
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Query
    )
    
    try {
        Write-ColorOutput "`n========== Creating Compliance Search ==========" -Color Cyan
        Write-ColorOutput "Search Name: $global:searchName" -Color White
        Write-ColorOutput "Query: $Query" -Color White
        
        # Check if search already exists
        $existingSearch = Get-ComplianceSearch -Identity $global:searchName -ErrorAction SilentlyContinue
        
        if ($existingSearch) {
            Write-ColorOutput "`nA search named '$global:searchName' already exists." -Color Yellow
            
            # Stop if running
            if ($existingSearch.Status -eq "Running") {
                Write-ColorOutput "Stopping existing search..." -Color Yellow
                Stop-ComplianceSearch -Identity $global:searchName -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 5
            }
            
            Write-ColorOutput "Removing existing search..." -Color Yellow
            Remove-ComplianceSearch -Identity $global:searchName -Confirm:$false -ErrorAction Stop
            Start-Sleep -Seconds 3
        }
        
        # Create new search
        Write-ColorOutput "`nCreating new compliance search..." -Color Yellow
        New-ComplianceSearch -Name $global:searchName -ExchangeLocation All -AllowNotFoundExchangeLocationsEnabled $true -ContentMatchQuery $Query -Confirm:$false -ErrorAction Stop
        
        Write-ColorOutput "Search created successfully." -Color Green
        
        # Start the search
        Write-ColorOutput "Starting compliance search..." -Color Yellow
        Start-ComplianceSearch -Identity $global:searchName -ErrorAction Stop
        Write-ColorOutput "Search started successfully." -Color Green
        
        return $true
    }
    catch {
        Write-ColorOutput "`nERROR: Failed to create or start compliance search." -Color Red
        Write-ColorOutput "Error: $($_.Exception.Message)" -Color Red
        return $false
    }
}

Function Wait-ComplianceSearchCompletion {
    <#
    .SYNOPSIS
    Monitors compliance search status until completion
    #>
    
    Write-ColorOutput "`n========== Monitoring Search Progress ==========" -Color Cyan
    $startTime = Get-Date
    
    do {
        try {
            $search = Get-ComplianceSearch -Identity $global:searchName -ErrorAction Stop
            $status = $search.Status
            $items = $search.Items
            $size = $search.Size
            
            $elapsed = (Get-Date) - $startTime
            $elapsedFormatted = "{0:mm}m {0:ss}s" -f $elapsed
            
            Write-ColorOutput "`r[Elapsed: $elapsedFormatted] Status: $status | Items: $items | Size: $size" -Color Yellow
            
            if ($status -eq "Completed") {
                break
            }
            
            Start-Sleep -Seconds 10
        }
        catch {
            Write-ColorOutput "`nERROR: Failed to get search status." -Color Red
            Write-ColorOutput "Error: $($_.Exception.Message)" -Color Red
            return $false
        }
    } while ($status -ne "Completed")
    
    Write-ColorOutput "`n`nSearch completed!" -Color Green
    Write-ColorOutput "Total items found: $items" -Color White
    Write-ColorOutput "Total size: $size" -Color White
    
    return $true
}

Function Invoke-EmailPurge {
    <#
    .SYNOPSIS
    Purges emails found by the compliance search
    .DESCRIPTION
    Handles the iterative purge process with the 100-item-per-mailbox limitation
    #>
    
    Write-ColorOutput "`n========== Beginning Purge Operations ==========" -Color Cyan
    
    # Verify search exists and is completed
    try {
        $search = Get-ComplianceSearch -Identity $global:searchName -ErrorAction Stop
        
        if ($search.Status -ne "Completed") {
            Write-ColorOutput "ERROR: Search must be completed before purging." -Color Red
            return $false
        }
        
        if ($search.Items -eq 0) {
            Write-ColorOutput "No items found to purge. Exiting." -Color Yellow
            return $true
        }
        
        Write-ColorOutput "Items to purge: $($search.Items)" -Color White
        Write-ColorOutput "Purge type: $DeleteType" -Color White
        
        # Confirm with user
        Write-ColorOutput "`nWARNING: This will delete emails from user mailboxes!" -Color Red
        $confirmation = Read-Host "Type 'YES' to proceed with purge"
        
        if ($confirmation -ne 'YES') {
            Write-ColorOutput "Purge cancelled by user." -Color Yellow
            return $false
        }
        
    }
    catch {
        Write-ColorOutput "ERROR: Failed to verify search status." -Color Red
        Write-ColorOutput "Error: $($_.Exception.Message)" -Color Red
        return $false
    }
    
    # Execute purge operations
    $purgeType = "$($DeleteType)Delete"
    $iteration = 1
    $maxIterations = 50 # Safety limit to prevent infinite loops
    
    # Check for potential issues before starting purge
    Write-ColorOutput "`n--- Pre-Purge Diagnostics ---" -Color Cyan
    try {
        # Check for mailboxes with holds
        Write-ColorOutput "Checking for mailboxes with holds..." -Color Yellow
        $mailboxesWithHolds = Get-Mailbox -ResultSize Unlimited | 
        Where-Object { $_.LitigationHoldEnabled -eq $true -or $_.InPlaceHolds.Count -gt 0 }
        
        if ($mailboxesWithHolds) {
            $holdCount = ($mailboxesWithHolds | Measure-Object).Count
            Write-ColorOutput "WARNING: $holdCount mailboxes have holds enabled. Items in these mailboxes may not be purgeable." -Color Yellow
            
            # Show first few examples
            $mailboxesWithHolds | Select-Object -First 5 | ForEach-Object {
                Write-ColorOutput "  - $($_.UserPrincipalName): LitigationHold=$($_.LitigationHoldEnabled)" -Color Yellow
            }
        }
        else {
            Write-ColorOutput "No litigation holds detected." -Color Green
        }
    }
    catch {
        Write-ColorOutput "Could not check for holds (this is non-critical)" -Color Yellow
    }
    
    Write-Host ""
    
    do {
        try {
            Write-ColorOutput "`n--- Purge Iteration $iteration ---" -Color Cyan
            
            # Create unique action name for this iteration
            $actionName = "$($global:searchName)_Purge_$iteration"
            
            # Check if action already exists and remove it
            $existingAction = Get-ComplianceSearchAction -Identity $actionName -ErrorAction SilentlyContinue
            if ($existingAction) {
                Remove-ComplianceSearchAction -Identity $actionName -Confirm:$false -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }
            
            Write-ColorOutput "Executing purge action..." -Color Yellow
            New-ComplianceSearchAction -SearchName $global:searchName     -Purge     -PurgeType $purgeType     -Force     -Confirm:$false     -ErrorAction Stop | Out-Null
            
            # Wait for purge action to complete
            Write-ColorOutput "Waiting for purge action to complete..." -Color Yellow
            $actionName = "$($global:searchName)_Purge"
            $actionCompleted = $false
            $waitTime = 0
            $maxWaitTime = 600 # 10 minutes maximum wait
            
            do {
                Start-Sleep -Seconds 10
                $waitTime += 10
                
                $actionStatus = Get-ComplianceSearchAction -Identity $actionName -ErrorAction SilentlyContinue
                
                if ($actionStatus) {
                    $status = $actionStatus.Status
                    Write-ColorOutput "  [${waitTime}s] Action Status: $status" -Color Cyan
                    
                    if ($status -eq "Completed" -or $status -eq "CompletedWithErrors") {
                        $actionCompleted = $true
                        
                        # Parse and display results
                        if ($actionStatus.Results) {
                            Write-ColorOutput "  Results: $($actionStatus.Results)" -Color White
                            
                            # Extract item count from results
                            if ($actionStatus.Results -match "Item count: (\d+)") {
                                $purgedCount = $matches[1]
                                Write-ColorOutput "  Successfully purged: $purgedCount items" -Color Green
                            }
                        }
                        
                        if ($status -eq "CompletedWithErrors") {
                            Write-ColorOutput "  WARNING: Purge completed with errors. Some items may not have been deleted." -Color Yellow
                        }
                    }
                    elseif ($status -eq "Failed") {
                        Write-ColorOutput "  ERROR: Purge action failed!" -Color Red
                        $actionCompleted = $true # Exit loop
                    }
                }
                else {
                    Write-ColorOutput "  WARNING: Cannot retrieve action status." -Color Yellow
                }
                
                if ($waitTime -ge $maxWaitTime) {
                    Write-ColorOutput "  WARNING: Maximum wait time exceeded ($maxWaitTime seconds)" -Color Yellow
                    $actionCompleted = $true # Exit loop
                }
                
            } while (-not $actionCompleted)
            
            # Re-run search to check remaining items
            Write-ColorOutput "Re-running search to verify remaining items..." -Color Yellow
            
            # Remove old search action to avoid conflicts
            $oldAction = Get-ComplianceSearchAction -Identity "$($global:searchName)_Purge" -ErrorAction SilentlyContinue
            if ($oldAction) {
                Remove-ComplianceSearchAction -Identity "$($global:searchName)_Purge" -Confirm:$false -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 5
            }
            
            # Restart the search
            Start-ComplianceSearch -Identity $global:searchName -Force -ErrorAction Stop
            
            # Wait for search to complete
            $searchCompleted = $false
            $searchWait = 0
            do {
                Start-Sleep -Seconds 10
                $searchWait += 10
                
                $updatedSearch = Get-ComplianceSearch -Identity $global:searchName -ErrorAction Stop
                $searchStatus = $updatedSearch.Status
                
                Write-ColorOutput "  [${searchWait}s] Search Status: $searchStatus" -Color Cyan
                
                if ($searchStatus -eq "Completed") {
                    $searchCompleted = $true
                }
                
                if ($searchWait -ge 300) {
                    # 5 minute timeout
                    Write-ColorOutput "  WARNING: Search verification timeout" -Color Yellow
                    break
                }
            } while (-not $searchCompleted)
            
            $remaining = $updatedSearch.Items
            Write-ColorOutput "Remaining items after purge: $remaining" -Color White
            
            $iteration++
            
            if ($iteration -gt $maxIterations) {
                Write-ColorOutput "`nWARNING: Maximum iteration limit reached ($maxIterations)." -Color Yellow
                Write-ColorOutput "There may still be items remaining. This could be due to:" -Color Yellow
                Write-ColorOutput "- Items protected by retention policies or litigation hold" -Color Yellow
                Write-ColorOutput "- Unindexed items (not purged by this process)" -Color Yellow
                Write-ColorOutput "- Items in Teams (not purged by this process)" -Color Yellow
                break
            }
            
        }
        catch {
            Write-ColorOutput "`nERROR: Purge operation failed." -Color Red
            Write-ColorOutput "Error: $($_.Exception.Message)" -Color Red
            
            # Check if it's a permissions error
            if ($_.Exception.Message -like "*parameter name 'Purge'*") {
                Write-ColorOutput "`nYou may be missing the 'Search and Purge' role." -Color Red
                Write-ColorOutput "This role is required and is assigned to Organization Management or Data Investigator role groups." -Color Yellow
            }
            
            return $false
        }
        
    } while ($remaining -gt 0)
    
    Write-ColorOutput "`n========== Purge Completed ==========" -Color Green
    Write-ColorOutput "Total purge iterations: $($iteration - 1)" -Color White
    
    return $true
}

Function Invoke-BySender {
    <#
    .SYNOPSIS
    Search and destroy workflow for sender-based queries
    #>
    
    $SendingUser = Read-Host "`nEnter the email address or domain to block and purge (e.g., attacker@evil.com or @evil.com)"
    
    if ([string]::IsNullOrWhiteSpace($SendingUser)) {
        Write-ColorOutput "ERROR: No sender specified." -Color Red
        return $false
    }
    
    # Define search name
    $global:searchName = "SeekDestroy_Sender_$($SendingUser.Replace('@','_').Replace('.','_'))_$global:date"
    
    Write-ColorOutput "`n========== Seek and Destroy: By Sender ==========" -Color Cyan
    Write-ColorOutput "Target: $SendingUser" -Color White
    Write-ColorOutput "Search Name: $global:searchName" -Color White
    
    # Block the sender
    Add-SenderToBlockList -SendingUser $SendingUser
    
    # Create and start search
    $query = "From:$SendingUser"
    if (-not (New-ComplianceContentSearch -Query $query)) {
        return $false
    }
    
    # Wait for search completion
    if (-not (Wait-ComplianceSearchCompletion)) {
        return $false
    }
    
    # Execute purge
    if (-not (Invoke-EmailPurge)) {
        return $false
    }
    
    return $true
}

Function Invoke-BySubject {
    <#
    .SYNOPSIS
    Search and destroy workflow for subject-based queries
    #>
    
    $Subject = Read-Host "`nEnter the email subject to search for and purge (e.g., 'Your account has been compromised')"
    
    if ([string]::IsNullOrWhiteSpace($Subject)) {
        Write-ColorOutput "ERROR: No subject specified." -Color Red
        return $false
    }
    
    # Define search name
    $sanitizedSubject = $Subject.Substring(0, [Math]::Min(30, $Subject.Length)) -replace '[^a-zA-Z0-9]', '_'
    $global:searchName = "SeekDestroy_Subject_$($sanitizedSubject)_$global:date"
    
    Write-ColorOutput "`n========== Seek and Destroy: By Subject ==========" -Color Cyan
    Write-ColorOutput "Target Subject: $Subject" -Color White
    Write-ColorOutput "Search Name: $global:searchName" -Color White
    
    # Create and start search
    $query = "Subject:`"$Subject`""
    if (-not (New-ComplianceContentSearch -Query $query)) {
        return $false
    }
    
    # Wait for search completion
    if (-not (Wait-ComplianceSearchCompletion)) {
        return $false
    }
    
    # Execute purge
    if (-not (Invoke-EmailPurge)) {
        return $false
    }
    
    return $true
}

#endregion

#region Main Script Execution

Write-ColorOutput "`n===================================================" -Color Cyan
Write-ColorOutput "  Exchange Online Seek and Destroy Script" -Color Cyan
Write-ColorOutput "  Updated for ExchangeOnlineManagement v3.9.0+" -Color Cyan
Write-ColorOutput "===================================================" -Color Cyan
Write-ColorOutput "`nAdmin Account: $AdminAccount" -Color White
Write-ColorOutput "Delete Type: $DeleteType" -Color White
Write-ColorOutput "Date: $global:date" -Color White

# Step 1: Verify module version
Write-ColorOutput "`n[Step 1/4] Verifying ExchangeOnlineManagement module..." -Color Cyan
if (-not (Test-ModuleVersion)) {
    Confirm-Close
}

# Step 2: Connect to services
Write-ColorOutput "`n[Step 2/4] Connecting to Exchange Online and Security & Compliance..." -Color Cyan
if (-not (Connect-Services)) {
    Confirm-Close
}

# Step 3: Determine search type and execute
Write-ColorOutput "`n[Step 3/4] Executing search and destroy workflow..." -Color Cyan

$success = $false

if ($BySubject.IsPresent) {
    $success = Invoke-BySubject
}
else {
    # Default to BySender if neither is specified
    $success = Invoke-BySender
}

# Step 4: Cleanup
Write-ColorOutput "`n[Step 4/4] Cleaning up..." -Color Cyan

try {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    Write-ColorOutput "Disconnected from Exchange Online." -Color Green
}
catch {
    # Ignore disconnect errors
}

if ($success) {
    Write-ColorOutput "`n===================================================" -Color Green
    Write-ColorOutput "  Script completed successfully!" -Color Green
    Write-ColorOutput "===================================================" -Color Green
}
else {
    Write-ColorOutput "`n===================================================" -Color Red
    Write-ColorOutput "  Script encountered errors!" -Color Red
    Write-ColorOutput "===================================================" -Color Red
}

Confirm-Close

#endregion

<#param (
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
    Connect-IPPSSession -UserPrincipalName $AdminAccount -EnableSearchOnlySession -ShowBanner:$false
    Connect-ExchangeOnline -UserPrincipalName $AdminAccount -ShowBanner:$false
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
        
        Get-Mailbox -ResultSize Unlimited | Set-MailboxJunkEmailConfiguration -BlockedSendersandDomains @{Add = $SendingUser }
    }

    #Connect-IPPSSession -UserPrincipalName $AdminAccount
}

Function New-Search ($selection) {

    Write-Output "Creating the content search"

    # Check if the search already exists
    $existingSearch = Get-ComplianceSearch -Identity $global:searchName -ErrorAction SilentlyContinue

    if ($null -ne $existingSearch) {

        Write-Output "A search named '$($global:searchName)' already exists."

        # Stop if running
        if ($existingSearch.Status -eq "Running") {
            Write-Output "Stopping existing search..."
            Stop-ComplianceSearch $global:searchName
            Start-Sleep -Seconds 5
        }

        Write-Output "Removing existing search..."
        Remove-ComplianceSearch $global:searchName -Confirm:$false
        Start-Sleep -Seconds 5
    }

    # Create new search
    New-ComplianceSearch -Name $global:searchName -ExchangeLocation all -AllowNotFoundExchangeLocationsEnabled $true -ContentMatchQuery $selection -Confirm:$false

    Write-Output "Beginning the search."

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
    Write-Host "Search completed. Beginning cleanup operations..." -ForegroundColor Green
    Write-Host "Reconnecting to Exchange Online without Search-Only session to perform purge actions..." -ForegroundColor Green

    # Determine purge type
    $purgeType = "$($DeleteType)Delete"

    Write-Output "Beginning purge operations..."

    do {

        Write-Output "Executing purge..."

        New-ComplianceSearchAction -SearchName $global:searchName -Purge -PurgeType $purgeType -Force -Confirm:$false

        Start-Sleep -Seconds 60

        $remaining = (Get-ComplianceSearch $global:searchName).Items

        Write-Output "Remaining messages: $remaining"

    } while ($remaining -gt 0)

    Write-Output "Purge completed."
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

Start-Sleep -Seconds 10
Get-SearchStatus #>