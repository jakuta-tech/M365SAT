# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure that DMARC records are published for all Exchange Domains
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx2112($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx2112"
		FindingName	     = "CIS MEx 2.1.12 - An Connection filter IP allow-list is found!"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "9"
		Description	     = "Without additional verification like mail flow rules, email from sources in the IP Allow List skips spam filtering and sender authentication (SPF, DKIM, DMARC) checks. This method creates a high risk of attackers successfully delivering email to the Inbox that would otherwise be filtered. Messages that are determined to be malware or high confidence phishing are filtered."
		Remediation	     = "Run the PowerShell Command to remediate the issue."
		PowerShellScript = 'Set-HostedConnectionFilterPolicy -Identity Default -IPAllowList @{}'
		DefaultValue	 = "IPAllowList @{}"
		ExpectedValue    = "IPAllowList @{}"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "3"
		RiskRating	     = "Medium"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Configure connection filtering'; 'URL' = "https://learn.microsoft.com/en-us/defender-office-365/connection-filter-policies-configure" },
			@{ 'Name' = 'Use the IP Allow List'; 'URL' = "https://learn.microsoft.com/en-us/defender-office-365/create-safe-sender-lists-in-office-365#use-the-ip-allow-list" },
			@{ 'Name' = 'User and tenant settings conflict'; 'URL' = "https://learn.microsoft.com/en-us/defender-office-365/how-policies-and-protections-are-combined#user-and-tenant-settings-conflict" })
	}
}


function Inspect-CISMEx2112
{	
	Try
	{
		$HostedConnectionFilterPolicy = Get-HostedConnectionFilterPolicy -Identity Default
		
		If (-not [String]::IsNullOrEmpty($HostedConnectionFilterPolicy.IPAllowList) -or $HostedConnectionFilterPolicy.IPAllowList -ne "{}")
		{
			$HostedConnectionFilterPolicy | Format-Table -AutoSize | Out-File "$path\CISMEx2112-HostedConnectionFilterPolicy.txt"
			$endobject = Build-CISMEx2112($HostedConnectionFilterPolicy)
			Return $endobject
		}
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CISMEx2112


