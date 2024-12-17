# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft Teams
# Purpose: Ensure 'external access' is restricted in the Teams admin center
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm821($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMTm821"
		FindingName	     = "CISM Tm 8.2.1 - External access is not restricted in the Teams admin center!"
		ProductFamily    = "Microsoft Teams"
		RiskScore	     = "8"
		Description	     = "Allowing users to communicate with Skype or Teams users outside of an organization presents a potential security threat as external users can interact with organization users over Skype for Business or Teams. While legitimate, productivity-improving scenarios exist, they are outweighed by the risk of data loss, phishing, and social engineering attacks against organization users via Teams. Therefore, it is recommended to restrict external communications in order to minimize the risk of security incidents."
		Remediation	     = "Use the PowerShell script to disallow External Communication"
		PowerShellScript = 'Set-CsTenantFederationConfiguration -AllowFederatedUsers $false'
		DefaultValue	 = "All True \n AllowedDomains : AllowAllKnownDomains"
		ExpectedValue    = "All False"
		ReturnedValue    = $findings
		Impact		     = "2"
		Likelihood	     = "4"
		RiskRating	     = "Medium"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'IT Admins - Manage external meetings and chat with people and organizations using Microsoft identities'; 'URL' = "https://learn.microsoft.com/en-us/microsoftteams/trusted-organizations-external-meetings-chat?tabs=organization-settings" },
		@{ 'Name' = 'DarkGate malware delivered via Microsoft Teams - detection and response'; 'URL' = "https://levelblue.com/blogs/security-essentials/darkgate-malware-delivered-via-microsoft-teams-detection-and-response" },
		@{ 'Name' = 'Midnight Blizzard conducts targeted social engineering over Microsoft Teams'; 'URL' = "https://www.microsoft.com/en-us/security/blog/2023/08/02/midnight-blizzard-conducts-targeted-social-engineering-over-microsoft-teams/" },
		@{ 'Name' = 'GIFShell Attack Lets Hackers Create Reverse Shell through Microsoft Teams GIFs'; 'URL' = "https://www.bitdefender.com/en-us/blog/hotforsecurity/gifshell-attack-lets-hackers-create-reverse-shell-through-microsoft-teams-gifs" })
	}
	return $inspectorobject
}

function Audit-CISMTm821
{
	try
	{
		$ViolatedTeamsSettings = @()
		$TeamsExternalAccess = Get-CsTenantFederationConfiguration
		if ($TeamsExternalAccess.AllowFederatedUsers -eq $True)
		{
			$ViolatedTeamsSettings += "AllowFederatedUsers: True"
		}
		if ($TeamsExternalAccess.AllowedDomains.count -lt 1 -or $TeamsExternalAccess.AllowedDomains -eq "AllowAllKnownDomains")
		{
			$ViolatedTeamsSettings += "AllowedDomains: $($TeamsExternalAccess.AllowedDomains)"
		}
		if ($ViolatedTeamsSettings.Count -igt 0)
		{
			$TeamsExternalAccess | Format-Table -AutoSize | Out-File "$path\CISMTm821-TeamsTenantFederationConfiguration.txt"
			$endobject = Build-CISMTm821($ViolatedTeamsSettings)
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
return Audit-CISMTm821