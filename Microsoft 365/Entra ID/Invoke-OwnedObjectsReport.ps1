[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $outputPath,
    [Parameter()]
    [string]
    $targetUsers = "All"
)

#requires -Modules ImportExcel

If ($targetUsers -eq "All") {
    $users = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/users?filter=accountEnabled eq true" -Method GET).value
}
Else {
    $users = $targetUsers -split "," | ForEach-Object {
        (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/users/$_" -Method GET).value
    }
}

function Get-MSUserOwnedObjects {
    param(
        $userid
    )

    $response = (Invoke-MgGraphRequest -uri "https://graph.microsoft.com/beta/users/$userid/ownedObjects").Value

    $report = [System.Collections.Generic.List[Object]]::new()

    forEach ($item in $response) {
        switch ($item.'@odata.type') {
            '#microsoft.graph.group' { $type = 'Group' }
            '#microsoft.graph.application' { $type = 'Application' }
            '#microsoft.graph.servicePrincipal' { $type = 'Service Principal' }
        }

        If ($item.'@odata.type' -eq '#microsoft.graph.application') {
            $query = (Invoke-GraphRequest -Method Get -Uri "https://graph.microsoft.com/beta/servicePrincipals?filter=appId eq '$($item.appId)'").Value

            $type = 'Service Principal'

            $obj = [PSCustomObject][ordered]@{
                "Type"         = $type
                "Display Name" = $query.DisplayName
                "Object Id"    = $query.id
                "Description"  = $query.description
                "Notes"        = "Ownership Inherited Through Application Ownership - $($item.displayName)"
            }
    
            $report.Add($obj)
        }
        Else {
            $obj = [PSCustomObject][ordered]@{
                "Type"         = $type
                "Display Name" = $item.DisplayName
                "Object Id"    = $item.id
                "Description"  = $item.description
            }

            $report.Add($obj)
        }
    }

    $report | Sort-Object Type
}

ForEach ($user in $users) {
    $owned = Get-MSUserOwnedObjects -userid $user.id

    If ($owned) {
        $owned | Export-Excel -Path "$outputPath\MS_User_Owned_Objects.xlsx" -WorksheetName $user.displayName -AutoSize -TableStyle Medium16 -Append
    }
}