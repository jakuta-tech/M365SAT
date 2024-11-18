# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure that an anti-phishing policy has been created
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx217($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx217"
		FindingName	     = "CIS MEx 2.1.7 - Anti-Phishing policy not has been created or correctly configured"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "15"
		Description	     = "Protects users from phishing attacks (like impersonation and spoofing), and uses safety tips to warn users about potentially harmful messages."
		Remediation	     = "Rune the following command to create a new AntiPhishPolicy"
		PowerShellScript = '$domains = (Get-AcceptedDomain).Name; $params = @{} New-AntiPhishPolicy @params; New-AntiPhishRule -Name "AntiPhish Rule" -AntiPhishPolicy "AntiPhish Policy" -RecipientDomainIs $domains'
		DefaultValue	 = "No Policy"
		ExpectedValue    = "A Policy"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Anti-phishing protection in Microsoft 365'; 'URL' = "https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-protection-about" },
		@{ 'Name' = 'Configure anti-phishing policies in EOP'; 'URL' = "https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-policies-eop-configure" })
	}
	return $inspectorobject
}

function Inspect-CISMEx217
{
	$AntiPhishPolicyViolation = @()
	Try
	{
		try
		{
			$params = @("name","Enabled","PhishThresholdLevel","EnableTargetedUserProtection","EnableOrganizationDomainsProtection","EnableMailboxIntelligence","EnableMailboxIntelligenceProtection","EnableSpoofIntelligence","TargetedUserProtectionAction","TargetedDomainProtectionAction","MailboxIntelligenceProtectionAction","EnableFirstContactSafetyTips","EnableSimilarUsersSafetyTips","EnableSimilarDomainsSafetyTips","EnableUnusualCharactersSafetyTips","TargetedUsersToProtect","HonorDmarcPolicy")
			$AntiPhishPolicy = Get-AntiPhishPolicy | Format-List $params | Where-Object { $_.IsDefault -eq $true }
			if ($AntiPhishPolicy.count -eq 0)
			{
				$AntiPhishPolicy = Get-AntiPhishPolicy | Format-List $params
			}
			if ($AntiPhishPolicy.enabled -eq $false)
			{
				$AntiPhishPolicyViolation += "Enabled: $($AntiPhishPolicy.enabled)"
			}
			if ($AntiPhishPolicy.PhishThresholdLevel -ilt 3)
			{
				$AntiPhishPolicyViolation += "PhishThresholdLevel: $($AntiPhishPolicy.PhishThresholdLevel)"
			}
			if ($AntiPhishPolicy.EnableTargetedUserProtection -eq $false)
			{
				$AntiPhishPolicyViolation += "EnableTargetedUserProtection: $($AntiPhishPolicy.EnableTargetedUserProtection)"
			}
			if ($AntiPhishPolicy.EnableOrganizationDomainsProtection -eq $false)
			{
				$AntiPhishPolicyViolation += "EnableOrganizationDomainsProtection: $($AntiPhishPolicy.EnableOrganizationDomainsProtection)"
			}
			if ($AntiPhishPolicy.EnableMailboxIntelligence -eq $false)
			{
				$AntiPhishPolicyViolation += "EnableMailboxIntelligence: $($AntiPhishPolicy.EnableMailboxIntelligence)"
			}
			if ($AntiPhishPolicy.EnableMailboxIntelligenceProtection -eq $false)
			{
				$AntiPhishPolicyViolation += "EnableMailboxIntelligenceProtection: $($AntiPhishPolicy.EnableMailboxIntelligenceProtection)"
			}
			if ($AntiPhishPolicy.EnableSpoofIntelligence -eq $false)
			{
				$AntiPhishPolicyViolation += "EnableSpoofIntelligence: $($AntiPhishPolicy.EnableSpoofIntelligence)"
			}
			if ($AntiPhishPolicy.TargetedUserProtectionAction -ne 'Quarantine')
			{
				$AntiPhishPolicyViolation += "TargetedUserProtectionAction: $($AntiPhishPolicy.TargetedUserProtectionAction)"
			}
			if ($AntiPhishPolicy.TargetedDomainProtectionAction -ne 'Quarantine')
			{
				$AntiPhishPolicyViolation += "TargetedDomainProtectionAction: $($AntiPhishPolicy.TargetedDomainProtectionAction)"
			}
			if ($AntiPhishPolicy.MailboxIntelligenceProtectionAction -ne 'Quarantine')
			{
				$AntiPhishPolicyViolation += "MailboxIntelligenceProtectionAction: $($AntiPhishPolicy.MailboxIntelligenceProtectionAction)"
			}
			if ($AntiPhishPolicy.EnableFirstContactSafetyTips -eq $false)
			{
				$AntiPhishPolicyViolation += "EnableFirstContactSafetyTips: $($AntiPhishPolicy.EnableFirstContactSafetyTips)"
			}
			if ($AntiPhishPolicy.EnableSimilarUsersSafetyTips -eq $false)
			{
				$AntiPhishPolicyViolation += "EnableSimilarUsersSafetyTips: $($AntiPhishPolicy.EnableSimilarUsersSafetyTips)"
			}
			if ($AntiPhishPolicy.EnableSimilarDomainsSafetyTips -eq $false)
			{
				$AntiPhishPolicyViolation += "EnableSimilarDomainsSafetyTips: $($AntiPhishPolicy.EnableSimilarDomainsSafetyTips)"
			}
			if ($AntiPhishPolicy.EnableUnusualCharactersSafetyTips -eq $false)
			{
				$AntiPhishPolicyViolation += "EnableUnusualCharactersSafetyTips: $($AntiPhishPolicy.EnableUnusualCharactersSafetyTips)"
			}
			if ($AntiPhishPolicy.TargetedUsersToProtect.count -eq 0)
			{
				$AntiPhishPolicyViolation += "TargetedUsersToProtect: $($AntiPhishPolicy.TargetedUsersToProtect)"
			}
			if ($AntiPhishPolicy.HonorDmarcPolicy -eq $false)
			{
				$AntiPhishPolicyViolation += "HonorDmarcPolicy: $($AntiPhishPolicy.HonorDmarcPolicy)"
			}
		}
		catch
		{
			$AntiPhishPolicyViolation += "No AntiPhish Policy Available"
		}
		If ($AntiPhishPolicyViolation.count -igt 0)
		{
			$AntiPhishPolicy | Format-Table -AutoSize | Out-File "$path\CISMEx217-AntiPhishPolicySettings.txt"
			$endobject = Build-CISMEx217($AntiPhishPolicyViolation)
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

return Inspect-CISMEx217


