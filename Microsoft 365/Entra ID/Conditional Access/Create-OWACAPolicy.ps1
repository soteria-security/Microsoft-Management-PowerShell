[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [array]
    $GroupNames
)

[array]$groups = $GroupNames

$groupIds = @()

ForEach ($group in $groups) {
    $groupId = (Invoke-GraphRequest -Method Get -Uri "https://graph.microsoft.com/beta/groups?filter=startswith(displayName,+'$group')").Value
    $groupIds += $groupId.id
}

$action = 'Block'
$grantPolicy = 'block'
$isBlockPolicy = 'exclude'

$bodyContent = @"
    {
        "displayName": "$action OWA Policy",
        "state": "enabledForReportingButNotEnforced",
        "conditions": {
            "devices": {
                "deviceFilter": {
                    "mode": "exclude",
                    "rule": "device.deviceOwnership -eq \"Company\" -or device.isCompliant -eq True"
                }
            },
            "clientAppTypes": [
                "browser"
            ],
            "users": {
                "includeUsers": ["All"],
                "$($isBlockPolicy)Groups": [
                    "$($groupIds -join ",\n")"
                ]
            },
            "applications": {
                "includeApplications": [
                    "00000002-0000-0ff1-ce00-000000000000"
                ]
            },
            "locations": {
                "includeLocations": [
                    "All"
                ],
                "excludeLocations": [
                    "AllTrusted"
                ]
            }
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls":
            [
                "$grantPolicy"
            ]
        }
}
"@

Invoke-GraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Body $bodyContent -ContentType 'application/json'