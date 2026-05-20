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
      - Pre-flight now validates Get-MgContext scopes against the required scope set and
        emits a precise "missing X, Y, Z" message instead of probing /me (which only
        needs User.Read and let unscoped sessions sail past into a wall of 403s).
      - Runtime catch blocks now branch on HTTP status code via Get-GraphErrorStatusCode:
        403 surfaces as a permissions/role message (not "likely retired/blocked"), and
        400/404 retains the retired-app interpretation. Misclassifying 403s as
        retired-app errors was actively misleading and sent users debugging the wrong
        problem.
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

# Scopes the script actually needs at runtime. Validated against the live MgGraph
# session by Test-RequiredGraphScopes before any privileged work begins.
$script:requiredScopes = @(
    'Application.ReadWrite.All'
    'Directory.ReadWrite.All'
    'AppRoleAssignment.ReadWrite.All'
    'User.Read.All'
    'Group.Read.All'
    'RoleManagement.Read.Directory'
)


Function Get-GraphErrorStatusCode {
    <#
        Extract an HTTP status code from a Graph error record. Invoke-GraphRequest does
        not reliably populate -StatusCodeVariable on a throw, and the exception type
        varies between PS editions, so we try .Response.StatusCode first and fall back
        to parsing the canonical .NET "Response status code does not indicate success: X"
        message. Returns 0 when the code can't be determined.
    #>
    param([Parameter(Mandatory)]$ErrorRecord)

    if ($ErrorRecord.Exception.Response) {
        try { return [int]$ErrorRecord.Exception.Response.StatusCode } catch { }
    }

    $msg = "$($ErrorRecord.Exception.Message)"
    switch -Regex ($msg) {
        '\bForbidden\b' { return 403 }
        '\bUnauthorized\b' { return 401 }
        '\bNotFound\b' { return 404 }
        '\bBadRequest\b' { return 400 }
        '\bConflict\b' { return 409 }
        'already exists' { return 409 }
        'EntitlementGrant' { return 409 }
        '\bTooManyRequests\b' { return 429 }
    }
    return 0
}


Function Write-ConnectInstructions {
    <#
        Print the exact reconnect command and the directory roles the signed-in account
        must hold. Called both from the pre-flight check and (potentially) any runtime
        403 so the user sees the same fix recipe wherever the failure shows up.
    #>
    param([string[]]$MissingScopes)

    Write-Host ""
    Write-Host "How to fix:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  1) Reconnect to Microsoft Graph with the full required scope set:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "       Disconnect-MgGraph -ErrorAction SilentlyContinue" -ForegroundColor Yellow
    Write-Host "       Connect-MgGraph -Scopes ``" -ForegroundColor Yellow
    Write-Host "           Application.ReadWrite.All, Directory.ReadWrite.All, ``" -ForegroundColor Yellow
    Write-Host "           AppRoleAssignment.ReadWrite.All, User.Read.All, ``" -ForegroundColor Yellow
    Write-Host "           Group.Read.All, RoleManagement.Read.Directory" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  2) The signed-in account must hold one of the following directory roles:" -ForegroundColor Yellow
    Write-Host "       - Application Administrator" -ForegroundColor Yellow
    Write-Host "       - Cloud Application Administrator" -ForegroundColor Yellow
    Write-Host "       - Global Administrator" -ForegroundColor Yellow
    Write-Host "     (Scopes alone are not enough — Graph also enforces the RBAC role.)" -ForegroundColor Yellow

    if ($MissingScopes -and $MissingScopes.Count -gt 0) {
        Write-Host ""
        Write-Host "Scopes missing from the current session:" -ForegroundColor Red
        foreach ($s in $MissingScopes) {
            Write-Host "  - $s" -ForegroundColor Red
        }
    }
    Write-Host ""
}


Function Test-RequiredGraphScopes {
    <#
        Pre-flight check. Returns an object describing connection state and any missing
        scopes before the first privileged Graph call. Replaces the original /me probe..
    #>
    $context = $null
    Try {
        $context = Get-MgContext
    }
    Catch {
        return [pscustomobject]@{
            Connected     = $false
            MissingScopes = $script:requiredScopes
            Account       = $null
            TenantId      = $null
        }
    }

    if (-not $context) {
        return [pscustomobject]@{
            Connected     = $false
            MissingScopes = $script:requiredScopes
            Account       = $null
            TenantId      = $null
        }
    }

    $currentScopes = @($context.Scopes)
    $missing = @($script:requiredScopes | Where-Object { $_ -notin $currentScopes })

    return [pscustomobject]@{
        Connected     = $true
        MissingScopes = $missing
        Account       = $context.Account
        TenantId      = $context.TenantId
    }
}


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
                # Branch on the actual HTTP status. 403 is a permissions/role problem,
                # not an app-retirement problem — the original blanket "retired/blocked"
                # message sent users debugging the wrong thing. 400/404 stays as the
                # retired-app interpretation (Microsoft returns these for first-party
                # apps that can no longer be instantiated, e.g. AzureAD PowerShell).
                $code = Get-GraphErrorStatusCode -ErrorRecord $_
                $errMsg = $_.Exception.Message

                if ($code -eq 403) {
                    Write-Warning "[$friendlyName] Forbidden (403) creating service principal. The current session lacks Application.ReadWrite.All, or the signed-in account is not in Application Administrator / Cloud Application Administrator / Global Administrator. Skipping."
                }
                elseif ($code -in 400, 404) {
                    Write-Warning "[$friendlyName] Could not create service principal (likely retired or blocked first-party app, HTTP $($code)): $($errMsg). Skipping."
                }
                else {
                    $codeText = if ($code) { "HTTP $code" } else { 'unknown status' }
                    Write-Warning "[$friendlyName] Failed to create service principal ($($codeText)): $($errMsg). Skipping."
                }
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
                $code = Get-GraphErrorStatusCode -ErrorRecord $_
                $errMsg = $_.Exception.Message

                if ($code -eq 403) {
                    Write-Warning "[$friendlyName] Forbidden (403) enforcing appRoleAssignmentRequired on existing SP. The current session lacks Application.ReadWrite.All, or the signed-in account is not in Application Administrator / Cloud Application Administrator / Global Administrator. Skipping."
                }
                else {
                    $codeText = if ($code) { "HTTP $code" } else { 'unknown status' }
                    Write-Warning "[$friendlyName] Could not enforce appRoleAssignmentRequired on existing SP ($($codeText)): $($errMsg). Skipping."
                }
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
        # Invoke-GraphRequest throws on non-2xx regardless of -ErrorAction (known issue),
        # and does not always populate -StatusCodeVariable on the thrown response, so we
        # route through Get-GraphErrorStatusCode for consistent classification.
        $code = Get-GraphErrorStatusCode -ErrorRecord $_
        $errMsg = $_.Exception.Message

        if ($code -eq 409) {
            Write-Host "$principalDisplay already assigned to $spDisplay" -ForegroundColor Yellow
        }
        elseif ($code -eq 403) {
            Write-Warning "Forbidden (403) assigning $($principalDisplay) to $($spDisplay). Session lacks AppRoleAssignment.ReadWrite.All, or the signed-in account is not in a role that can grant app role assignments."
        }
        else {
            $codeText = if ($code) { "HTTP $code" } else { 'unknown status' }
            Write-Warning "Failed to add $($principalDisplay) to $($spDisplay) ($($codeText)): $($errMsg)"
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

# Pre-flight: verify Graph connectivity AND that the session token actually carries
# every scope this script needs. The previous /me probe only required User.Read, so
# under-scoped sessions passed it and then 403d on every privileged call — leaving
# the user staring at a wall of misleading "likely retired or blocked first-party app"
# warnings. Failing fast here, with the specific missing scopes named, is the fix.
$scopeCheck = Test-RequiredGraphScopes

if (-not $scopeCheck.Connected) {
    Write-Warning "Not connected to Microsoft Graph. Run Connect-MgGraph before launching this script."
    Write-ConnectInstructions -MissingScopes $script:requiredScopes
    return
}

if ($scopeCheck.MissingScopes.Count -gt 0) {
    Write-Warning "Connected to Microsoft Graph as $($scopeCheck.Account), but $($scopeCheck.MissingScopes.Count) required scope(s) are missing from this session. Service principal creation and hardening will return HTTP 403 until you reconnect with the full scope set."
    Write-ConnectInstructions -MissingScopes $scopeCheck.MissingScopes
    return
}

Write-Host "Connected as $($scopeCheck.Account) (tenant $($scopeCheck.TenantId)) with all required scopes." -ForegroundColor Green


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