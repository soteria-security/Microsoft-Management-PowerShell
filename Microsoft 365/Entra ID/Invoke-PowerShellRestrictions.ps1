<#
.SYNOPSIS
    Restrict Azure AD, PnP SharePoint, Microsoft Intune, Microsoft Azure, and Microsoft Graph PowerShell Modules to Explicilty Assigned Users
.DESCRIPTION
    Restrict Azure AD, PnP SharePoint, Microsoft Intune, Microsoft Azure, and Microsoft Graph PowerShell Modules to Explicilty Assigned Users
.INPUTS
    Directory Role, File Path, or Individual User
.COMPONENT
    PowerShell Microsoft Graph PowerShell Module
.ROLE
    Sufficient rights in Azure AD
.FUNCTIONALITY
    Restrict Azure AD, PnP SharePoint, Microsoft Intune, Microsoft Azure, and Microsoft Graph PowerShell Modules to Explicilty Assigned Users
#>


$credit = @'
Credit where credit is due:
    Scripts modified from originals by BillSluss here - https://github.com/OfficeDev/O365-EDU-Tools/tree/master/SDS%20Scripts/Block%20PowerShell
'@


function Show-Menu {
    param (
        [string]$Title = 'Microsoft 365 Tenant PowerShell Restrictions'
    )
    Clear-Host
    Write-Host "====================== $Title ======================"

    Write-Host "                   |   |||||||||||||||||||||||||||||||||||||||||||    | "
    Write-Host "                   |   |                                         |    | "
    Write-Host "                   |   |       Author - ThoughtContagion         |    | "
    Write-Host "                   |   |                                         |    | "
    Write-Host "                   |   |||||||||||||||||||||||||||||||||||||||||||    | " 
    Write-Host ""
    Write-Host ""
    Write-Host $credit
    Write-Host ""
    Write-Host ""
    Write-Host "Press '1' to choose an Azure Active Directory Directory Role."
    Write-Host "Press '2' to provide a csv file with a list of admins by UserPrincipalName."
    Write-Host "Press '3' to provide an individual user by email."
    Write-Host "Press 'Q' to quit."
}

$global:servicePrincipals = @()

Function Confirm-Applications {
    #Define the applications to restrict
    $aad = "1b730954-1685-4b74-9bfd-dac224a7b894"

    $msGraph = "14d82eec-204b-4c2f-b7e8-296a70dab67e"

    $PnP = '31359c7f-bd7e-475c-86db-fdb8c937548e'

    $Intune = 'd1ddf0e4-d672-4dae-b554-9d5bdfd93547'

    $Azure = '1950a258-227b-4e31-a9cf-717495945fc2'

    $appIds = @($aad, $msGraph, $PnP, $Intune, $Azure)

    Foreach ($appId in $appIds) {
        $servicePrincipal = (Invoke-GraphRequest -Method Get -Uri "https://graph.microsoft.com/beta/servicePrincipals?filter=appid eq '$appId'").Value

        If ($servicePrincipal) {
            $global:servicePrincipals += $servicePrincipal
        }
        
        #Create a Service Principal for the application if it does not already exist
        if (-not $servicePrincipal) {
            $body = @{
                appId                     = $appId
                appRoleAssignmentRequired = $true
            }

            $servicePrincipal = (Invoke-GraphRequest -Method Post -Uri "https://graph.microsoft.com/beta/servicePrincipals" -ContentType 'application/json' -Body ($body | ConvertTo-Json))
            
            $servicePrincipal = (Invoke-GraphRequest -Method Get -Uri "https://graph.microsoft.com/beta/servicePrincipals?filter=appid eq '$appId'").Value

            If ($servicePrincipal) {
                $global:servicePrincipals += $servicePrincipal
            }
        }
    }
}

Function Confirm-DirRole {
    #Define the allowed users/roles
    $DirectoryRole = Read-Host -Prompt "Please Enter the DisplayName Property for the Chosen Role (eg Global Administrator)"

    $role = (Invoke-GraphRequest GET -Uri "https://graph.microsoft.com/beta/directoryRoles?filter=displayName eq '$DirectoryRole'").Value.id

    $admins = (Invoke-GraphRequest GET -Uri "https://graph.microsoft.com/beta/directoryRoles/$($role)/members").Value

    #Call the Applications to Restrict
    Confirm-Applications
    
    #Assign the Admins to the Applications
    foreach ($admin in $admins) {
        Foreach ($servicePrincipal in $global:servicePrincipals) {
            Try {
                Write-Host "Adding $(($admin).displayName) to $(($servicePrincipal).DisplayName)"

                $body = @{
                    principalId = $admin.id
                    resourceId  = $servicePrincipal.id
                    appRoleId   = '00000000-0000-0000-0000-000000000000'
                }

            
                (Invoke-GraphRequest -Method Post -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($servicePrincipal.id)/appRoleAssignedTo" -ContentType 'application/json' -Body ($body | ConvertTo-Json) -ErrorAction Stop)
            }
            Catch {
                $exc = $_

                If ($exc -match 'EntitlementGrant entry already exists.') {
                    Write-Host "$(($admin).displayName) already assigned to $(($servicePrincipal).DisplayName)" -ForegroundColor Yellow
                }
            }
        }
    }
}

Function Confirm-ListAdmins {
    #Define the allowed users/roles
    $path = Read-Host "Please Enter the Path to the File Containing your List of Admin Accounts"

    $admins = import-csv $path
    
    #Call the Applications to Restrict
    Confirm-Applications

    #Assign the Admins to the Applications
    foreach ($admin in $admins) {
        $user = (Invoke-GraphRequest -Method Get -Uri "https://graph.microsoft.com/v1.0/users/$($admin)").Value

        Foreach ($servicePrincipal in $global:servicePrincipals) {
            Try {
                Write-Host "Adding $(($user).displayName) to $(($servicePrincipal).DisplayName)"

                $body = @{
                    principalId = $user.id
                    resourceId  = $servicePrincipal.id
                    appRoleId   = '00000000-0000-0000-0000-000000000000'
                }

                
                (Invoke-GraphRequest -Method Post -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($servicePrincipal.id)/appRoleAssignedTo" -ContentType 'application/json' -Body ($body | ConvertTo-Json) -ErrorAction Stop)
            }
            Catch {
                $exc = $_

                If ($exc -match 'EntitlementGrant entry already exists.') {
                    Write-Host "$(($user).displayName) already assigned to $(($servicePrincipal).DisplayName)" -ForegroundColor Yellow
                }
            }
        }
    }
}

Function Confirm-StandAloneAdmin {
    #Define the allowed users/roles
    $admin = Read-Host "Please Enter the Email Address of the Target User"
    
    #Call the Applications to Restrict
    Confirm-Applications

    #Assign the Admins to the Applications
    $user = (Invoke-GraphRequest -Method Get -Uri "https://graph.microsoft.com/v1.0/users?`$filter=mail eq '$($admin)'").Value

    Foreach ($servicePrincipal in $global:servicePrincipals) {
        Try {
            Write-Host "Adding $(($user).displayName) to $(($servicePrincipal).DisplayName)"

            $body = @{
                principalId = $user.id
                resourceId  = $servicePrincipal.id
                appRoleId   = '00000000-0000-0000-0000-000000000000'
            }

            (Invoke-GraphRequest -Method Post -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($servicePrincipal.id)/appRoleAssignedTo" -ContentType 'application/json' -Body ($body | ConvertTo-Json) -ErrorAction Stop)
        }`
            Catch {
            $exc = $_

            If ($exc -match 'EntitlementGrant entry already exists') {
                Write-Host "$(($user).displayName) already assigned to $(($servicePrincipal).DisplayName)" -ForegroundColor Yellow
            }
        }
    }
}


do {
    Show-Menu
    
    $selection = Read-Host "Please make a selection"
    
    switch ($selection) {
        '1' {
            'Restricting Azure AD, PnP SharePoint, Microsoft Intune, Microsoft Azure, and Microsoft Graph PowerShell Modules to a Directory Role'
            Confirm-DirRole
        } '2' {
            'Restricting Azure AD, PnP SharePoint, Microsoft Intune, Microsoft Azure, and Microsoft Graph PowerShell Modules to a list of admins'
            Confirm-ListAdmins
        } '3' {
            'Adding the specified user to Azure AD, PnP SharePoint, Microsoft Intune, Microsoft Azure, and Microsoft Graph PowerShell Modules'
            Confirm-StandAloneAdmin
        } 
    }
    pause
}
until ($selection -like '*')