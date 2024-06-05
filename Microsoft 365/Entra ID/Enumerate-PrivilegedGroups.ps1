Function Enumerate-PrivilegedGroups {
    $Groups = (Invoke-GraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/groups?$filter=isAssignableToRole eq true').Value

    $allGroups = @()
    $licenses = (Invoke-GraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/subscribedskus").value
    $licenseErrorGroups = (Invoke-GraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/groups?filter=hasMembersWithLicenseErrors+eq+true").Value

    Foreach ($group in $Groups) {
        $licensedGroup = (Invoke-GraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/groups/$($group.id)?select=id,displayname,assignedLicenses") | Where-Object { $null -ne $_.assignedLicenses }
        $roleAssigned = $group | Where-Object { $_.isAssignableToRole -eq $true }

        $grpType = $null
        $memberShip = $null

        $members = (Invoke-GraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/groups/$($group.Id)/members").userPrincipalName

        If ($licenseErrorGroups.id -contains $group.id) {
            $hasLicenseError = $true
        }
        Else {
            $hasLicenseError = $false
        }

        If ($group.groupTypes -eq 'Unified') {
            $grpType = 'Unified'
        }
        If ((($group.groupTypes).length -eq 0) -and ($group.mailEnabled -eq $false) -and ($group.securityEnabled -eq $true)) {
            $grpType = 'Security'
        }
        If ((($group.groupTypes).length -eq 0) -and ($group.mailEnabled -eq $true) -and ($group.securityEnabled -eq $true)) {
            $grpType = 'Mail-enabled Security'
        }
        If ((($group.groupTypes).length -eq 0) -and ($group.mailEnabled -eq $true) -and ($group.securityEnabled -eq $false)) {
            $grpType = 'Distribution'
        }

        If ($group.groupTypes -eq 'DynamicMembership') {
            $memberShip = 'Dynamic'
            $grpType = 'DynamicMembership'
        }
        Else {
            $memberShip = 'Static'
        }

        $result = [PSCustomObject]@{
            Name             = $group.displayName
            Id               = $group.id
            GroupType        = $grpType
            MembershipType   = $memberShip
            AssignedLicenses = $null
            DisabledFeatures = $null
            IsRoleAssignable = $null
            AssignedRoles    = $null
            Members          = (Invoke-GraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/groups/$($group.Id)/members").value.userPrincipalName -join ','
            IsOnPremise      = $group.onPremisesSyncEnabled
            LicenseError     = $hasLicenseError
        }

        If ($licensedGroup) {
            ForEach ($license in $licensedGroup.assignedLicenses) {
                $result.AssignedLicenses += ($licenses | Where-Object { $_.skuid -eq $license.skuid }).skuPartNumber
                $result.DisabledFeatures += foreach ($plan in $license.disabledPlans) { ($licenses | Where-Object { $_.servicePlans.servicePlanId -eq $plan } |  Select-Object @{n = 'feature'; e = { ($_.servicePlans | Where-Object { $_.servicePlanId -eq $plan }).servicePlanName } }).feature }
            }
        }

        If ($roleAssigned) {
            $result.IsRoleAssignable = $true
            $roles = (invoke-GraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleAssignments?filter=principalId eq '$($roleAssigned.id)'").Value.roleDefinitionId
            $result.AssignedRoles += foreach ($role in $roles) {
                ((invoke-GraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/directoryroles?filter=roleTemplateId eq '$role'").value.displayName <# + ", " #>)
            }                    
        }

        $allGroups += $result
    }

    Return $allGroups
}

Enumerate-PrivilegedGroups
