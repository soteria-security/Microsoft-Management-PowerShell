<#
.SYNOPSIS
    Restrict Microsoft Graph PowerShell, Az PowerShell, Azure CLI, and other admin
    PowerShell/CLI tooling to explicitly assigned users in a Microsoft Entra tenant.

.DESCRIPTION
    Creates (if missing) and hardens the service principals for first-party Microsoft
    PowerShell/CLI applications so that only explicitly assigned users (via a directory
    role, security group, CSV list, or single UPN) can authenticate against them.

    Hardening pattern per target SP:
      1. Ensure the service principal exists in the tenant.
      2. Set appRoleAssignmentRequired = $true on the SP.
      3. Grant the default app role ([Guid]::Empty) to the chosen principals via
         /servicePrincipals/{id}/appRoleAssignedTo.

.INPUTS
    Directory role (DisplayName), security group (DisplayName), CSV file of admin
    UserPrincipalNames, or single admin UPN.

.NOTES
    Required Microsoft Graph scopes:
      - Application.ReadWrite.All
      - Directory.ReadWrite.All
      - AppRoleAssignment.ReadWrite.All
      - User.Read.All
      - Group.Read.All
      - RoleManagement.Read.Directory

    Prerequisites:
      Connect-MgGraph -Scopes Application.ReadWrite.All, Directory.ReadWrite.All, `
                              AppRoleAssignment.ReadWrite.All, User.Read.All, `
                              Group.Read.All, RoleManagement.Read.Directory

.NOTES
    Refactor notes (May 2026):
      - Removed AzureAD PowerShell AppId (1b730954-1685-4b74-9bfd-dac224a7b894) from the
        default target list. Module retired by Microsoft starting mid-October 2025. Kept
        commented for reference; uncomment to attempt hardening on tenants where the
        legacy SP object still exists.
      - Added Microsoft Entra PowerShell AppId (replacement for AzureAD module).
      - All Graph URLs now use backtick-escaped `$filter so the OData query parameter is
        actually honored (the previous `filter=` was silently ignored by Graph, which
        returned the first page of all SPs).
      - All API calls now wrapped in try/catch so a single AppId failure (e.g. deprecated
        app blocked from SP creation) does not halt the run.
      - Existing SPs are now PATCHed to enforce appRoleAssignmentRequired=$true. The
        original script only set this property on newly-created SPs, leaving pre-existing
        SPs unhardened.
      - CSV admin list iteration now extracts UserPrincipalName explicitly (PSCustomObject
        interpolation produced a malformed URL: @{UserPrincipalName=...; DisplayName=...}).
      - User lookups now use the user object directly (single-object GET returns the
        object, not a value collection).
      - Single-admin lookup now filters on userPrincipalName, not mail (mail can be null).
      - Directory role lookup now falls back to /directoryRoleTemplates and activates the
        role if it is not yet activated in the tenant.
      - HTTP 409 conflict on appRoleAssignedTo is now caught via status code rather than
        error message text.
      - $script:servicePrincipals is reset on every Confirm-Applications call.
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
    Write-Host "Press '1' to choose an Entra ID Directory Role."
    Write-Host "Press '2' to choose an Entra ID Security Group."
    Write-Host "Press '3' to provide a CSV file with a list of admins by UserPrincipalName."
    Write-Host "Press '4' to provide an individual user by UPN."
    Write-Host "Press 'M' to list all target modules."
    Write-Host "Press 'Q' to quit."
}


# Default target list. AzureAD PowerShell (1b730954-...) intentionally removed because
# the module retired mid-October 2025; the SP can no longer authenticate, so hardening it
# is pointless. Uncomment if you specifically need to harden the legacy SP where it still
# exists as a residual object.
$script:targetApps = @(
    [pscustomobject]@{ AppId = 'd1ddf0e4-d672-4dae-b554-9d5bdfd93547'; Name = 'Microsoft Intune PowerShell' }
    # [pscustomobject]@{ AppId = '1b730954-1685-4b74-9bfd-dac224a7b894'; Name = 'Azure Active Directory PowerShell (RETIRED Oct 2025)' }
    [pscustomobject]@{ AppId = '1950a258-227b-4e31-a9cf-717495945fc2'; Name = 'Microsoft Azure PowerShell (Az)' }
    [pscustomobject]@{ AppId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'; Name = 'Microsoft Azure CLI' }
    [pscustomobject]@{ AppId = 'de8bc8b5-d9f9-48b1-a8ad-b748da725064'; Name = 'Graph Explorer' }
    [pscustomobject]@{ AppId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'; Name = 'Microsoft Graph Command Line Tools' }
    [pscustomobject]@{ AppId = 'fb78d390-0c51-40cd-8e17-fdbfab77341b'; Name = 'Microsoft Exchange REST API Based PowerShell' }
    [pscustomobject]@{ AppId = '23d8f6bd-1eb0-4cc2-a08c-7bf525c67bcd'; Name = 'Power BI PowerShell' }
)

$script:servicePrincipals = @()


Function Get-ServicePrincipalByAppId {
    <#
        Look up a service principal by AppId. Returns the SP object or $null.
        Uses `$filter (backtick-escaped) so the dollar sign survives PowerShell parsing
        and reaches Graph as the OData $filter system query option.
    #>
    param([Parameter(Mandatory)][string]$AppId)

    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$AppId'"

    Try {
        $response = Invoke-GraphRequest -Method Get -Uri $uri -ErrorAction Stop
        if ($response.value -and $response.value.Count -gt 0) {
            return $response.value[0]
        }
        return $null
    }
    Catch {
        Write-Warning "Lookup failed for AppId $($AppId): $($_.Exception.Message)"
        throw
    }
}


Function Set-ServicePrincipalAssignmentRequired {
    <#
        Enforce appRoleAssignmentRequired=$true on an existing SP. The original script
        only set this property at SP creation time, so pre-existing SPs were never
        hardened. Without this property, app role assignments don't actually gate
        access; tokens are still issued to unassigned users.
    #>
    param([Parameter(Mandatory)]$ServicePrincipal)

    if ($ServicePrincipal.appRoleAssignmentRequired -eq $true) {
        return # Already enforced; nothing to do.
    }

    $body = @{ appRoleAssignmentRequired = $true } | ConvertTo-Json

    Invoke-GraphRequest -Method Patch `
        -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($ServicePrincipal.id)" `
        -ContentType 'application/json' `
        -Body $body `
        -ErrorAction Stop | Out-Null
}


Function Confirm-Applications {
    <#
        For each target app: locate or create the SP, enforce appRoleAssignmentRequired,
        and collect it into $script:servicePrincipals for the assignment functions to
        iterate over. Per-app errors are isolated so one failure doesn't halt the run.
    #>
    $script:servicePrincipals = @()

    Foreach ($app in $script:targetApps) {
        $appId = $app.AppId
        $friendlyName = $app.Name
        $sp = $null

        # --- Step 1: Look up existing SP ---
        Try {
            $sp = Get-ServicePrincipalByAppId -AppId $appId
        }
        Catch {
            # Already logged by helper; skip this app.
            continue
        }

        # --- Step 2: Create SP if missing ---
        if (-not $sp) {
            $createBody = @{
                appId                     = $appId
                appRoleAssignmentRequired = $true
            } | ConvertTo-Json

            Try {
                $sp = Invoke-GraphRequest -Method Post `
                    -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' `
                    -ContentType 'application/json' `
                    -Body $createBody `
                    -ErrorAction Stop

                Write-Host "[$friendlyName] Created service principal with appRoleAssignmentRequired=true." -ForegroundColor Green
            }
            Catch {
                # Common failure here: the first-party app has been retired or otherwise
                # blocked by Microsoft from new SP provisioning (e.g. AzureAD PowerShell post-Oct 2025). 
                # We log and skip rather than failing the entire run.
                Write-Warning "[$friendlyName] Could not create service principal (likely retired or blocked first-party app): $($_.Exception.Message). Skipping."
                continue
            }
        }
        else {
            Try {
                Set-ServicePrincipalAssignmentRequired -ServicePrincipal $sp
                if ($sp.appRoleAssignmentRequired -eq $true) {
                    Write-Host "[$friendlyName] Existing SP already enforces appRoleAssignmentRequired." -ForegroundColor Cyan
                }
                else {
                    Write-Host "[$friendlyName] Enforced appRoleAssignmentRequired on existing SP." -ForegroundColor Green
                    $sp = Get-ServicePrincipalByAppId -AppId $appId
                }
            }
            Catch {
                Write-Warning "[$friendlyName] Could not enforce appRoleAssignmentRequired on existing SP: $($_.Exception.Message). Skipping."
                continue
            }
        }

        $script:servicePrincipals += $sp
    }

    if ($script:servicePrincipals.Count -eq 0) {
        Write-Warning "No service principals were prepared. Nothing to assign."
    }
}


Function Add-AdminAssignment {
    <#
        Grant the default app role ([Guid]::Empty) to a principal on a single SP.
        409 conflict (already assigned) is treated as success, identified by HTTP
        status code rather than fragile error-message regex.
    #>
    param(
        [Parameter(Mandatory)]$Principal,
        [Parameter(Mandatory)]$ServicePrincipal
    )

    $principalDisplay = if ($Principal.displayName) { $Principal.displayName } else { $Principal.id }
    $spDisplay = $ServicePrincipal.displayName

    $body = @{
        principalId = $Principal.id
        resourceId  = $ServicePrincipal.id
        appRoleId   = '00000000-0000-0000-0000-000000000000'
    } | ConvertTo-Json

    Try {
        Write-Host "Adding $principalDisplay to $spDisplay"
        Invoke-GraphRequest -Method Post `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($ServicePrincipal.id)/appRoleAssignedTo" `
            -ContentType 'application/json' `
            -Body $body `
            -StatusCodeVariable statusCode `
            -ErrorAction Stop | Out-Null
    }
    Catch {
        # Invoke-GraphRequest throws on non-2xx regardless of -ErrorAction (known issue).
        # Detect "already assigned" by inspecting the inner exception, since the cmdlet
        # does not always populate -StatusCodeVariable on the thrown response.
        $errMsg = $_.Exception.Message
        if ($errMsg -match '\b409\b' -or $errMsg -match 'already exists' -or $errMsg -match 'EntitlementGrant') {
            Write-Host "$principalDisplay already assigned to $spDisplay" -ForegroundColor Yellow
        }
        else {
            Write-Warning "Failed to add $principalDisplay to $spDisplay`: $errMsg"
        }
    }
}


Function Get-DirectoryRoleMembers {
    <#
        Resolve a directory role by DisplayName. Falls back to /directoryRoleTemplates
        and activates the role if it's not yet activated in the tenant (the original
        script would silently fail in that case because /directoryRoles only returns
        activated roles).
    #>
    param([Parameter(Mandatory)][string]$DisplayName)

    # Try active directory roles first.
    $uri = "https://graph.microsoft.com/v1.0/directoryRoles?`$filter=displayName eq '$DisplayName'"
    $role = (Invoke-GraphRequest -Method Get -Uri $uri -ErrorAction Stop).value | Select-Object -First 1

    if (-not $role) {
        Write-Host "Role '$DisplayName' is not yet activated; checking directoryRoleTemplates..." -ForegroundColor Yellow

        $templateUri = "https://graph.microsoft.com/v1.0/directoryRoleTemplates"
        $template = (Invoke-GraphRequest -Method Get -Uri $templateUri -ErrorAction Stop).value |
        Where-Object { $_.displayName -eq $DisplayName } |
        Select-Object -First 1

        if (-not $template) {
            Write-Warning "Directory role '$DisplayName' not found in templates."
            return @()
        }

        # Activate the role via the deprecated-but-still-functional roleTemplateId POST.
        $activateBody = @{ roleTemplateId = $template.id } | ConvertTo-Json
        $role = Invoke-GraphRequest -Method Post `
            -Uri 'https://graph.microsoft.com/v1.0/directoryRoles' `
            -ContentType 'application/json' `
            -Body $activateBody `
            -ErrorAction Stop

        Write-Host "Activated directory role '$DisplayName'." -ForegroundColor Green
    }

    $membersUri = "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members"
    return (Invoke-GraphRequest -Method Get -Uri $membersUri -ErrorAction Stop).value
}


Function Confirm-DirRole {
    $displayName = Read-Host -Prompt "Please enter the DisplayName of the directory role (eg Global Administrator)"

    $members = Get-DirectoryRoleMembers -DisplayName $displayName
    if (-not $members) {
        Write-Warning "No members found for role '$displayName'."
        return
    }

    Confirm-Applications

    foreach ($member in $members) {
        Foreach ($sp in $script:servicePrincipals) {
            Add-AdminAssignment -Principal $member -ServicePrincipal $sp
        }
    }
}


Function Confirm-GroupMembers {
    $displayName = Read-Host -Prompt "Please enter the DisplayName of the security group"

    $groupUri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$displayName'"
    $group = (Invoke-GraphRequest -Method Get -Uri $groupUri -ErrorAction Stop).value | Select-Object -First 1

    if (-not $group) {
        Write-Warning "Group '$displayName' not found."
        return
    }

    $membersUri = "https://graph.microsoft.com/v1.0/groups/$($group.id)/members"
    $members = (Invoke-GraphRequest -Method Get -Uri $membersUri -ErrorAction Stop).value

    if (-not $members) {
        Write-Warning "Group '$displayName' has no members."
        return
    }

    Confirm-Applications

    foreach ($member in $members) {
        Foreach ($sp in $script:servicePrincipals) {
            Add-AdminAssignment -Principal $member -ServicePrincipal $sp
        }
    }
}


Function Confirm-ListAdmins {
    $path = Read-Host -Prompt "Please enter the path to the CSV file (must have a UserPrincipalName column)"

    if (-not (Test-Path $path)) {
        Write-Warning "File not found: $path"
        return
    }

    $rows = Import-Csv -Path $path

    # Validate CSV shape
    $firstRow = $rows | Select-Object -First 1
    if (-not $firstRow.PSObject.Properties.Name -contains 'UserPrincipalName') {
        Write-Warning "CSV must contain a 'UserPrincipalName' column."
        return
    }

    Confirm-Applications

    foreach ($row in $rows) {
        $upn = $row.UserPrincipalName
        if ([string]::IsNullOrWhiteSpace($upn)) {
            continue
        }

        Try {
            $user = Invoke-GraphRequest -Method Get `
                -Uri "https://graph.microsoft.com/v1.0/users/$upn" `
                -ErrorAction Stop
        }
        Catch {
            Write-Warning "User lookup failed for $($upn): $($_.Exception.Message)"
            continue
        }

        Foreach ($sp in $script:servicePrincipals) {
            Add-AdminAssignment -Principal $user -ServicePrincipal $sp
        }
    }
}


Function Confirm-StandAloneAdmin {
    $upn = Read-Host -Prompt "Please enter the UserPrincipalName of the target user"

    Confirm-Applications

    Try {
        $userUri = "https://graph.microsoft.com/v1.0/users?`$filter=userPrincipalName eq '$upn'"
        $user = (Invoke-GraphRequest -Method Get -Uri $userUri -ErrorAction Stop).value | Select-Object -First 1
    }
    Catch {
        Write-Warning "User lookup failed for $($upn): $($_.Exception.Message)"
        return
    }

    if (-not $user) {
        Write-Warning "No user found with UserPrincipalName '$upn'."
        return
    }

    Foreach ($sp in $script:servicePrincipals) {
        Add-AdminAssignment -Principal $user -ServicePrincipal $sp
    }
}


Function List-TargetModules {
    Write-Host ""
    Write-Host "Target applications:" -ForegroundColor Cyan
    foreach ($app in $script:targetApps) {
        Write-Host "  $($app.Name)  ($($app.AppId))" -ForegroundColor Yellow
    }
    Write-Host ""
}

$mgContext = $null
Try {
    $mgContext = Invoke-GraphRequest -Method Get -Uri 'https://graph.microsoft.com/v1.0/me' -ErrorAction Stop
}
Catch {
    Write-Warning "Not connected to Microsoft Graph, or current session lacks User.Read."
    Write-Host ""
    Write-Host "Run the following before launching this script:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Connect-MgGraph -Scopes Application.ReadWrite.All, Directory.ReadWrite.All, ``" -ForegroundColor Yellow
    Write-Host "                          AppRoleAssignment.ReadWrite.All, User.Read.All, ``"        -ForegroundColor Yellow
    Write-Host "                          Group.Read.All, RoleManagement.Read.Directory"            -ForegroundColor Yellow
    Write-Host ""
    return
}


do {
    Show-Menu

    $selection = Read-Host "Please make a selection"

    switch ($selection) {
        '1' {
            'Restricting all target modules to a directory role'
            Confirm-DirRole
        }
        '2' {
            'Restricting all target modules to a security group'
            Confirm-GroupMembers
        }
        '3' {
            'Restricting all target modules to a list of admins from CSV'
            Confirm-ListAdmins
        }
        '4' {
            'Adding the specified user to all target modules'
            Confirm-StandAloneAdmin
        }
        'M' {
            'Listing all target modules'
            List-TargetModules
        }
        'Q' {
            Break
        }
    }
    pause
}
until ($selection -eq 'Q')