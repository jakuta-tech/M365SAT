# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure Microsoft Azure Management is limited to administrative roles
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5228($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz5228"
		FindingName	     = "CIS MAz 5.2.2.8 - Admin center access is not limited to administrative roles"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "10"
		Description	     = "Conditional Access (CA) policies are not enforced for other role types, including administrative unit-scoped or custom roles. By restricting access to built-in directory roles, users granted privileged permissions outside of these roles will be blocked from accessing admin centers. Restricting access to Microsoft Admin Portals while impactful, covers a gap that is otherwise not bridged by Conditional Access."
		Remediation	     = "Unfortunately we cannot accurately detect if correctly configured. If you have a existing policy. Please verify if the settings are configured correctly."
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies'
		DefaultValue	 = "No - Non-administrators can access the Microsoft admin portals."
		ExpectedValue    = "Yes - Only Administrators can access the Microsoft admin portals."
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Conditional Access: Microsoft Admin Portals'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps#microsoft-admin-portals' })
	}
	return $inspectorobject
}

function Audit-CISMAz5228
{
	try
	{
		# Actual Script
		$Violation = @()
		$DirectoryRoles = Get-MgRoleManagementDirectoryRoleDefinition
		$PrivilegedRoles = ($DirectoryRoles | Where-Object { $_.DisplayName -like "*Administrator*" -or $_.DisplayName -eq "Global Reader"}).TemplateId


		$PolicyExistence = Get-MgIdentityConditionalAccessPolicy | Where-Object {((-not ($PrivilegedRoles | Compare-Object $_.Conditions.Users.ExcludeRoles) -as [bool]) -eq $true) -and ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeApplications -eq "MicrosoftAdminPortals") -and $_.GrantControls.BuiltInControls -eq "block"}
		$PolicyExistence = Get-MgIdentityConditionalAccessPolicy | Select-Object * | Where-Object { $_.DisplayName -like "*administrative*" }
		$PolicyExistence | Format-Table -AutoSize | Out-File "$path\CISMAz5228-AdministrativeConditionalAccessPolicy.txt"
		if ($PolicyExistence.Count -ne 0)
		{
			foreach ($Policy in $PolicyExistence)
			{
				if ($Policy.State -eq "disabled")
				{
					$Violation += $Policy.Id
				}
				else
				{
					#Multiple Checks to determine if the policy is not configured correctly
					$PolicyInfo = Invoke-MgGraphRequest -Method GET "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/$($Policy.Id)"
					if ([string]::IsNullOrEmpty($PolicyInfo.conditions.userRiskLevels) -or -not [string]::IsNullOrEmpty($PolicyInfo.conditions.signInRiskLevels))
					{
						$Violation += $Policy.Id
					}
					elseif ($PolicyInfo.conditions.applications.includeApplications -ne "All" -or $PolicyInfo.conditions.users.includeUsers -ne "All")
					{
						$Violation += $Policy.Id
					}
				}
				
			}
		}
		else
		{
			$Violation += "Could not verify is policy exists!"
		}
		# Validation
		if ($Violation.Count -ne 0)
		{
			$finalobject = Build-CISMAz5228($Violation)
			return $finalobject
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISMAz5228