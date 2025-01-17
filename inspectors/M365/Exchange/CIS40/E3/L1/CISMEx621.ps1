# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft Exchange
# Purpose: Forms of mail forwarding are not blocked and/or not disabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx621($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx621"
		FindingName	     = "CIS MEx 6.2.1 - Forms of mail forwarding are not blocked and/or not disabled"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "6"
		Description	     = "Attackers often create these rules to exfiltrate data from your tenancy, this could be accomplished via access to an end-user account or otherwise. An insider could also use one of these methods as an secondary channel to exfiltrate sensitive data."
		Remediation	     = "Check all Transport Rules and run the powershell command to remove them:"
		PowerShellScript = 'Get-TransportRule | Where-Object {$_.RedirectMessageTo -ne $null} | ft Name,RedirectMessageTo | Remove-TransportRule $_.Name; Get-HostedOutboundSpamFilterPolicy | Set-HostedOutboundSpamFilterPolicy -AutoForwardingMode Off
		'
		DefaultValue	 = "AllowedOOFType: External <br> AutoForwardEnabled: True"
		ExpectedValue    = "AllowedOOFType: Not External <br> AutoForwardEnabled: False"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "2"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Procedures for mail flow rules in Exchange Server'; 'URL' = 'https://docs.microsoft.com/en-us/exchange/policy-and-compliance/mail-flow-rules/mail-flow-rule-procedures?view=exchserver-2019' },
			@{ 'Name' = 'Control automatic external email forwarding in Microsoft 365'; 'URL' = 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/outbound-spam-policies-external-email-forwarding?view=o365-worldwide' },
			@{ 'Name' = 'All you need to know about automatic email forwarding in Exchange Online'; 'URL' = 'https://techcommunity.microsoft.com/t5/exchange-team-blog/all-you-need-to-know-about-automatic-email-forwarding-in/ba-p/2074888#:~:text=%20%20%20Automatic%20forwarding%20option%20%20,%' })
	}
	return $inspectorobject
}

function Audit-CISMEx621
{
	try
	{
		$TransportRules = Get-TransportRule | Where-Object { $null -ne $_.RedirectMessageTo } | Select-Object Name, RedirectMessageTo
		$OutboundSpamFilterPolicy = Get-HostedOutboundSpamFilterPolicy | Select-Object Name, AutoForwardingMode
		if ($TransportRules.Count -igt 0)
		{
			if ($OutboundSpamFilterPolicy.AutoForwardingMode -eq "Off"){
				$OutboundSpamFilterPolicy | Format-List | Out-File -FilePath "$path\CISMEx621-AffectedTransportRules.txt"
			}
			$TransportRules | Format-List | Out-File -FilePath "$path\CISMEx621-AffectedTransportRules.txt" -Append
			$finalobject = Build-CISMEx621($TransportRules)
			return $finalobject
		}
		else
		{
			return $null
		}
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISMEx621