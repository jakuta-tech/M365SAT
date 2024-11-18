# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft Sharepoint
# Purpose: SharePoint default sharing link permission is not set
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)
function Build-CISMSp7211($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMSp7211"
		FindingName	     = "CIS MSp 7.2.11 - SharePoint default sharing link permission is not set"
		ProductFamily    = "Microsoft Sharepoint"
		RiskScore	     = "15"
		Description	     = "Setting the view permission as the default ensures that users must deliberately select the edit permission when sharing a link. This approach reduces the risk of unintentionally granting edit privileges to a resource that only requires read access, supporting the principle of least privilege."
		Remediation	     = "Use the PowerShell Script to enable this setting:"
		PowerShellScript = 'Set-SPOTenant -DefaultLinkPermission View'
		DefaultValue	 = "Edit"
		ExpectedValue    = "View"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'File and folder links'; 'URL' = 'https://learn.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off#file-and-folder-links' })
	}
	return $inspectorobject
}

function Audit-CISMSp7211
{
	try
	{
		$Module = Get-Module PnP.PowerShell -ListAvailable
		if(-not [string]::IsNullOrEmpty($Module))
		{
			# Actual Script
			$AffectedOptions = @()
			$SharepointSetting = Get-PnPTenant
			if ($SharepointSetting.DefaultLinkPermission -ne "View")
			{
				$AffectedOptions += "DefaultLinkPermission: $($SharepointSetting.DefaultLinkPermission)"
			}
			# Validation
			if ($AffectedOptions.Count -ne 0)
			{
				$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp7211-SPOTenant.txt"
				$finalobject = Build-CISMSp7211($AffectedOptions)
				return $finalobject
			}
			return $null
		}
		else
		{
			# Actual Script
			$AffectedOptions = @()
			$SharepointSetting = Get-SPOTenant
			if ($SharepointSetting.DefaultLinkPermission -ne $True)
			{
				$AffectedOptions += "DefaultLinkPermission: $($SharepointSetting.DefaultLinkPermission)"
			}
			# Validation
			if ($AffectedOptions.Count -ne 0)
			{
				$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp7211-SPOTenant.txt"
				$finalobject = Build-CISMSp7211($AffectedOptions)
				return $finalobject
			}
			return $null
		}
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISMSp7211