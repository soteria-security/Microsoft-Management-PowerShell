[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [int]
    $StaleDays = 60,
    [Parameter(Mandatory = $false)]
    [string]    
    $OutputPath = ".\StaleAccounts.csv"
)

# ================================
# CONFIG
# ================================
$Now = Get-Date
$Cutoff = $Now.AddDays(-$StaleDays)

# ================================
# FUNCTIONS
# ================================
function Convert-GuidToImmutableId {
    param([Guid]$Guid)
    return [System.Convert]::ToBase64String($Guid.ToByteArray())
}

function Convert-FileTime {
    param($FileTime)
    if (!$FileTime -or $FileTime -eq 0) { return $null }
    return [DateTime]::FromFileTime($FileTime)
}

function Get-MaxDate {
    param($dates)
    return ($dates | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1)
}

# ================================
# GET AD USERS
# ================================
Write-Host "Collecting on-prem AD users..."
$adUsers = Get-ADUser -Filter * -Properties objectGUID, lastLogonTimestamp, userPrincipalName, Enabled | Select-Object @{Name = "ImmutableId"; Expression = { Convert-GuidToImmutableId $_.objectGUID } }, userPrincipalName, Enabled, @{ Name = "ADLastLogon"; Expression = { Convert-FileTime $_.lastLogonTimestamp } }

# ================================
# GET ENTRA USERS
# ================================
Write-Host "Collecting Entra users (this may take time)..."

$entraUsers = @()
$uri = "https://graph.microsoft.com/v1.0/users?`$select=id,displayName,userPrincipalName,onPremisesImmutableId,accountEnabled,signInActivity"

do {
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    $entraUsers += $response.value
    $uri = $response.'@odata.nextLink'
} while ($uri)

$entraUsers = $entraUsers | Select-Object id, displayName, userPrincipalName, onPremisesImmutableId, accountEnabled, @{Name = "LastSignIn"; Expression = { $_.signInActivity.lastSignInDateTime } }

# ================================
# GET EXCHANGE MAILBOXES
# ================================
Write-Host "Collecting Exchange mailboxes..."

$mailboxes = Get-Mailbox -ResultSize Unlimited | Select-Object DisplayName, UserPrincipalName, ExternalDirectoryObjectId, RecipientTypeDetails

$mailboxStats = @{}
Get-MailboxStatistics -ResultSize Unlimited | ForEach-Object {
    $mailboxStats[$_.DisplayName] = $_.LastLogonTime
}

# Join mailbox stats back
$mailboxes = $mailboxes | ForEach-Object {
    $_ | Add-Member -NotePropertyName LastLogonTime -NotePropertyValue $mailboxStats[$_.DisplayName] -Force
    $_
}

# ================================
# FILTER OUT SHARED/RESOURCE MAILBOXES
# ================================
Write-Host "Filtering shared/resource mailboxes..."

$excludedMailboxTypes = @(
    "SharedMailbox",
    "RoomMailbox",
    "EquipmentMailbox"
)

$mailboxes = $mailboxes | Where-Object {
    $excludedMailboxTypes -notcontains $_.RecipientTypeDetails
}

# ================================
# BUILD LOOKUPS
# ================================
$entraByImmutable = @{}
$entraByUPN = @{}
$entraById = @{}

foreach ($u in $entraUsers) {
    if ($u.onPremisesImmutableId) {
        $entraByImmutable[$u.onPremisesImmutableId] = $u
    }
    if ($u.userPrincipalName) {
        $entraByUPN[$u.userPrincipalName.ToLower()] = $u
    }
    $entraById[$u.id] = $u
}

$mailboxByObjectId = @{}
foreach ($m in $mailboxes) {
    if ($m.ExternalDirectoryObjectId) {
        $mailboxByObjectId[$m.ExternalDirectoryObjectId] = $m
    }
}

# ================================
# CORRELATE + COMPUTE ACTIVITY
# ================================
Write-Host "Correlating identities..."

$results = @()

foreach ($ad in $adUsers) {

    $entra = $null

    # Primary match: ImmutableId
    if ($ad.ImmutableId -and $entraByImmutable.ContainsKey($ad.ImmutableId)) {
        $entra = $entraByImmutable[$ad.ImmutableId]
    }
    # Fallback: UPN
    elseif ($ad.userPrincipalName -and $entraByUPN.ContainsKey($ad.userPrincipalName.ToLower())) {
        $entra = $entraByUPN[$ad.userPrincipalName.ToLower()]
    }

    $mailbox = $null
    if ($entra -and $mailboxByObjectId.ContainsKey($entra.id)) {
        $mailbox = $mailboxByObjectId[$entra.id]
    }

    $lastActivity = Get-MaxDate @(
        $ad.ADLastLogon,
        $entra.LastSignIn,
        $mailbox.LastLogonTime
    )

    $isStale = $true
    if ($lastActivity -and $lastActivity -gt $Cutoff) {
        $isStale = $false
    }

    $results += [PSCustomObject]@{
        DisplayName        = $entra.displayName
        AD_UPN             = $ad.userPrincipalName
        Entra_UPN          = $entra.userPrincipalName
        Enabled_AD         = $ad.Enabled
        Enabled_Entra      = $entra.accountEnabled
        AD_LastLogon       = $ad.ADLastLogon
        Entra_LastSignIn   = $entra.LastSignIn
        Exchange_LastLogon = $mailbox.LastLogonTime
        LastActivity       = $lastActivity
        IsStale            = $isStale
        HasMailbox         = [bool]$mailbox
    }
}

# ================================
# OUTPUT
# ================================
Write-Host "Filtering stale accounts (> $StaleDays days)..."

$stale = $results | Where-Object { $_.IsStale -eq $true }

$stale | Sort-Object LastActivity |
Export-Csv -Path ".\StaleAccounts.csv" -NoTypeInformation

Write-Host "Done. Output: StaleAccounts.csv"
Write-Host "Total stale accounts:" $stale.Count