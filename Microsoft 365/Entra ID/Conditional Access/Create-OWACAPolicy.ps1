Function Create-OWACAPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]
        $GroupName,
        [Parameter(Mandatory = $false)]
        [switch]
        $Block
    )

    [array]$groups = $GroupName

    $groupIds = @()

    ForEach ($group in $groups) {
        $groupId = (Invoke-GraphRequest -Method Get -Uri "https://graph.microsoft.com/beta/groups?filter=startswith(displayName,+'$group')").Value
        $groupId = "{\n}"
    }

    <#
    {
        "displayName": "$action OWA Policy",
        "state": "enabledForReportingButNotEnforced",
        "sessionControls": {
            "disableResilienceDefaults": null,
            "cloudAppSecurity": null,
            "persistentBrowser": null,
            "applicationEnforcedRestrictions": {
                "isEnabled": true
            },
            "signInFrequency": {
                "authenticationType": "primaryAndSecondaryAuthentication",
                "frequencyInterval": "timeBased",
                "value": 4,
                "isEnabled": true,
                "type": "hours"
            }
        },
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
                "includeGroups": [
                    "6c96716b-b32b-40b8-9009-49748bb6fcd5"
                ],
                "excludeGroups": [
                    "f753047e-de31-4c74-a6fb-c38589047723"
                ]
            },
            "applications": {
                "includeApplications": [
                    "00000002-0000-0ff1-ce00-000000000000"
                ]
            }
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": [
                "mfa"
            ]
        }
    }
    #>

    If ($block.IsPresent) {
        $action = 'Block'
        $grantPolicy = 'block'
        $isBlockPolicy = 'exclude'
    }

    $body = @{
        displayName   = "$action OWA Policy"
        state         = "enabledForReportingButNotEnforced"
        conditions    = @"
            {
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
                "$($isBlockPolicy)Groups": [
                    $($groupIds -join ",\n")
                ]
            },
            "applications": {
                "includeApplications": [
                    "00000002-0000-0ff1-ce00-000000000000"
                ]
            }
        }
"@
        grantControls = @{
            operator        = "OR"
            builtInControls = @"
            [
                "$grantPolicy"
            ]
"@
        }
    }

    Invoke-GraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Body $bodyContent -ContentType 'application/json'
}