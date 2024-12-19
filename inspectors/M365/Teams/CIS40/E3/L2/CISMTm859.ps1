# Date: 14-05-2024
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft Teams
# Purpose: Ensure meeting recording is off by default
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm859($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMTm859"
		FindingName	     = "CISM Tm 8.5.9 - Meeting recording is on by default"
		ProductFamily    = "Microsoft Teams"
		RiskScore	     = "15"
		Description	     = "Disabling meeting recordings in the Global meeting policy ensures that only authorized users, such as organizers, co-organizers, and leads, can initiate a recording. This measure helps safeguard sensitive information by preventing unauthorized individuals from capturing and potentially sharing meeting content. Restricting recording capabilities to specific roles allows organizations to exercise greater control over what is recorded, aligning it with the meeting's confidentiality requirements."
		Remediation	     = "Use the PowerShell script to disallow External Access"
		PowerShellScript = 'Set-CsTeamsMeetingPolicy -Identity Global -AllowCloudRecording $false'
		DefaultValue	 = "True (On)"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Teams settings and policies reference'; 'URL' = "https://learn.microsoft.com/en-US/microsoftteams/settings-policies-reference?WT.mc_id=TeamsAdminCenterCSH#meeting-engagement" })
	}
	return $inspectorobject
}

function Audit-CISMTm859
{
	try
	{
		$ViolatedTeamsSettings = @()
		$MicrosoftTeamsCheck = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowCloudRecording
		
		
		if ($MicrosoftTeamsCheck.AllowCloudRecording -eq $True)
		{
			$MicrosoftTeamsCheck | Format-Table -AutoSize | Out-File "$path\CISMTm859-TeamsMeetingPolicy.txt"
			$endobject = Build-CISMTm859($MicrosoftTeamsCheck.AllowCloudRecording)
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
return Audit-CISMTm859