# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft Teams
# Purpose: Ensure communication with unmanaged Teams users is disabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm824($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMTm824"
		FindingName	     = "CISM Tm 8.2.4 - Communication with Skype users is enabled"
		ProductFamily    = "Microsoft Teams"
		RiskScore	     = "8"
		Description	     = "Skype was deprecated July 31, 2021. Disabling communication with skype users reduces the attack surface of the organization. If a partner organization or satellite office wishes to collaborate and has not yet moved off of Skype, then a valid exception will need to be considered for this recommendation."
		Remediation	     = "Use the PowerShell script to disallow External Communication"
		PowerShellScript = 'Set-CsTenantFederationConfiguration -AllowPublicUsers $false'
		DefaultValue	 = "AllowPublicUsers : True"
		ExpectedValue    = "AllowPublicUsers : False"
		ReturnedValue    = $findings
		Impact		     = "2"
		Likelihood	     = "4"
		RiskRating	     = "Medium"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'IT Admins - Manage external meetings and chat with people and organizations using Microsoft identities'; 'URL' = "https://learn.microsoft.com/en-us/microsoftteams/trusted-organizations-external-meetings-chat?tabs=organization-settings" })
	}
	return $inspectorobject
}

function Audit-CISMTm824
{
	try
	{
		$ViolatedTeamsSettings = @()
		$TeamsExternalAccess = Get-CsTenantFederationConfiguration
		if ($TeamsExternalAccess.AllowPublicUsers -eq $True)
		{
			$ViolatedTeamsSettings += "AllowPublicUsers: True"
		}
		if ($ViolatedTeamsSettings.Count -igt 0)
		{
			$TeamsExternalAccess | Format-Table -AutoSize | Out-File "$path\CISMTm824-TeamsTenantFederationConfiguration.txt"
			$endobject = Build-CISMTm824($ViolatedTeamsSettings)
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
return Audit-CISMTm824