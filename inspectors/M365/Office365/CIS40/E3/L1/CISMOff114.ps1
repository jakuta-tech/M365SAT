# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft 365
# Purpose: Checks if Guest Users are found within your tenant
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMOff114($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMOff114"
		FindingName	     = "CIS MOff 1.1.4 - Administrative Accounts Assigned Licenses with Full Application Access"
		ProductFamily    = "Microsoft Office 365"
		RiskScore	     = "0"
		Description	     = "Ensuring administrative accounts do not use licenses with applications assigned to them will reduce the attack surface of high privileged identities in the organization's environment. Granting access to a mailbox or other collaborative tools increases the likelihood that privileged users might interact with these applications, raising the risk of exposure to social engineering attacks or malicious content. These activities should be restricted to an unprivileged 'daily driver' account."
		Remediation	     = "Remove the licenses that are not needed for administrators.."
		PowerShellScript = 'https://admin.microsoft.com/'
		DefaultValue	 = "0"
		ExpectedValue    = "0"
		ReturnedValue    = $findings.Count
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Add users and assign licenses at the same time'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/admin/add-users/add-users?view=o365-worldwide" },
		@{ 'Name' = 'Step 2. Protect your Microsoft 365 privileged accounts'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/enterprise/protect-your-global-administrator-accounts?view=o365-worldwide" },
		@{ 'Name' = 'Use cloud native accounts for Microsoft Entra roles'; 'URL' = "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices#9-use-cloud-native-accounts-for-microsoft-entra-roles" },
		@{ 'Name' = 'What is Microsoft Entra ID?'; 'URL' = "https://learn.microsoft.com/en-us/entra/fundamentals/whatis" },
		@{ 'Name' = 'Microsoft Entra built-in roles'; 'URL' = "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference" })
	}
	return $inspectorobject
}

function Audit-CISMOff114
{
	Try
	{
		$DirectoryRoles = Get-MgDirectoryRole
		$PrivilegedRoles = $DirectoryRoles | Where-Object { $_.DisplayName -like "*Administrator*" -or $_.DisplayName -eq "Global Reader" }
		$RoleMembers = $PrivilegedRoles | ForEach-Object { Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id } | Select-Object Id -Unique
		$PrivilegedUsers = $RoleMembers | ForEach-Object { Get-MgUser -UserId $_.Id -Property UserPrincipalName, DisplayName, Id }
		$Report = [System.Collections.Generic.List[Object]]::new()
		foreach ($Admin in $PrivilegedUsers) {
			$License = $null
			$License = (Get-MgUserLicenseDetail -UserId $Admin.Id).SkuPartNumber -join ", "
			$Object = [PSCustomObject][ordered]@{
				DisplayName = $Admin.DisplayName
				UserPrincipalName = $Admin.UserPrincipalName
				License = $License
			}
			if ($Object.License.Count -igt 0){
				$Report.Add($Object)
			}
		}

		
		If ($Report.Count -igt 0)
		{
			$Report | Format-Table -AutoSize UserPrincipalName, UserType | Out-File "$path\CISMOff114-AdministrativeAccountsReport.txt"
			$endobject = Build-CISMOff114($Report)
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

return Audit-CISMOff114


