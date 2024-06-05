<# 
.Synopsis
    Gather Exchange Mail Domains, Check and Validate DMARC, SPF, and DKIM Records for Damains in use.
.Description
    Gather Exchange Mail Domains, Check and Validate DMARC, SPF, and DKIM Records for Damains in use.
.Inputs
    Optional - Domains
.Component
    PowerShell, ExchangeOnline Module
.Role
    Exchange Admin or Higher Role Required to Gather Domains from Email Addresses
.Functionality
    Gather Exchange Mail Domains, Check and Validate DMARC, SPF, and DKIM Records for Damains in use.
.Example
    ./Get-MailDomainsStatus.ps1
.Example
    ./Get-MailDomainsStatus.ps1 -Domains domain1,domain2,domain3
#>


param (
	[Parameter(Mandatory = $false,
		HelpMessage = 'Provided List of Domains to Query')]
	[string[]] $Domains
)

if ($null -eq $Domains) {
    Write-Output "Discovering Mail Domains...`n"
    $Domains = (Get-AcceptedDomain).DomainName
}

Write-Output "Domains to be Evaluated:"
$Domains
Write-Output ""

Start-Sleep -Seconds 3

Function Get-MailDomains {
    # Verify DKIM and DMARC records.
    Write-Output "-------- DKIM and DMARC DNS Records Report --------"
    Write-Output ""

    $Result = foreach ($Domain in $Domains) {
        Write-Output "---------------------- $Domain ----------------------"
        Write-Output "DKIM Selector 1 CNAME Record:"
        nslookup -q=cname selector1._domainkey.$Domain 8.8.8.8 | Select-String "canonical name"
        Write-Output ""
        Write-Output "DKIM Selector 2 CNAME Record:"
        nslookup -q=cname selector2._domainkey.$Domain 8.8.8.8 | Select-String "canonical name"
        Write-Output ""
        Write-Output "DMARC TXT Record:"
        (nslookup -q=txt _dmarc.$Domain 8.8.8.8 | Select-String "DMARC1") -replace "`t", ""
        Write-Output ""
        Write-Output "SPF TXT Record:"
        (nslookup -q=txt $Domain 8.8.8.8 | Select-String "spf1") -replace "`t", ""
        Write-Output "-----------------------------------------------------"
        Write-Output ""
        Write-Output ""
    }
    $Result
}

Get-MailDomains