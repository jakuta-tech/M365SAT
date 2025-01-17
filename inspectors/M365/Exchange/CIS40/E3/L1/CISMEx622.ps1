# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure mail transport rules do not whitelist specific domains
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx622($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx622"
		FindingName	     = "CIS MEx 6.2.2 - Mail transport rules whitelist specific domains!"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "3"
		Description	     = "Whitelisting domains in transport rules bypasses regular malware and phishing scanning, which can enable an attacker to launch attacks against your users from a safe haven domain."
		Remediation	     = "Check all Transport Rules and run the powershell command to remove them:"
		PowerShellScript = 'Get-TransportRule | Where-Object {($_.setscl -eq -1 -and $_.SenderDomainIs -ne $null)} | Remove-TransportRule $_.Name'
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Best practices for configuring mail flow rules in Exchange Online'; 'URL' = "https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/configuration-best-practices" },
			@{ 'Name' = 'Mail flow rules (transport rules) in Exchange Online'; 'URL' = "https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules" })
	}
	return $inspectorobject
}


function Inspect-CISMEx622
{
	Try
	{
		
		$domainwlrules = Get-TransportRule | Where-Object { ($_.setscl -eq -1 -and $null -ne $_.SenderDomainIs) } | Select-Object Name, SenderDomainIs
		
		If ($domainwlrules.Count -ne 0)
		{
			$domainwlrules | Format-List | Out-File -FilePath "$path\CISMEx622-SenderDomainIs.txt"
			$endobject = Build-CISMEx622($domainwlrules)
			return $endobject
		}
		return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CISMEx622


