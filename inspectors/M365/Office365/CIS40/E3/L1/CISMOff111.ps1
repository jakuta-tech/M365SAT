# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft 365
# Purpose: Ensure Administrative accounts are separate and cloud-only
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMOff111($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMOff111"
		FindingName	     = "CIS MOff 1.1.1 -  Ensure Administrative accounts are separate and cloud-only"
		ProductFamily    = "Microsoft Office 365"
		RiskScore	     = "12"
		Description	     = "In a hybrid environment, having separate accounts will help ensure that in the event of a breach in the cloud, that the breach does not affect the on-prem environment and vice versa."
		Remediation	     = "You can review the list of accounts containing a license and change them in the Microsoft 365 Portal"
		PowerShellScript = 'https://admin.microsoft.com/'
		DefaultValue	 = "-"
		ExpectedValue    = "0"
		ReturnedValue    = $findings
		Impact		     = "4"
		Likelihood	     = "3"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Add users and assign licenses at the same time'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/admin/add-users/add-users?view=o365-worldwide" },
		@{ 'Name' = 'Step 2. Protect your Microsoft 365 privileged accounts'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/enterprise/protect-your-global-administrator-accounts?view=o365-worldwide" },
		@{ 'Name' = 'Use cloud native accounts for Microsoft Entra roles'; 'URL' = "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices#9-use-cloud-native-accounts-for-microsoft-entra-roles" },
		@{ 'Name' = 'What is Microsoft Entra ID?'; 'URL' = "https://learn.microsoft.com/en-us/entra/fundamentals/whatis" },
		@{ 'Name' = 'Microsoft Entra built-in roles'; 'URL' = "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference" })
	}
	return $inspectorobject
}

function Audit-CISMOff111
{
	try
	{
		$DirectoryRoles = Get-MgDirectoryRole
		$PrivilegedRoles = $DirectoryRoles | Where-Object { $_.DisplayName -like "*Administrator*" -or $_.DisplayName -eq "Global Reader"}
		$RoleMembers = $PrivilegedRoles | ForEach-Object { Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id } | Select-Object Id -Unique
		$PrivilegedUsers = $RoleMembers | ForEach-Object { Get-MgUser -UserId $_.Id -Property UserPrincipalName, DisplayName, Id, OnPremisesSyncEnabled }
		$NonCloudMFAAdmins = $PrivilegedUsers | Where-Object { $_.OnPremisesSyncEnabled -eq $true } | Select-Object DisplayName,UserPrincipalName,OnPremisesSyncEnabled
		if ($NonCloudMFAAdmins.Count -igt 0)
		{
			$endobject = Build-CISMOff111($NonCloudMFAAdmins)
			Return $endobject
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}

return Audit-CISMOff111