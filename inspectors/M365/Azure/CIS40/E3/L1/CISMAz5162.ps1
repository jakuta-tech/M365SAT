# Date: 8-11-2024
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that guest user access is restricted
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISMAz5162($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz5162"
		FindingName	     = "CIS MAz 5.1.6.2 - Guest user access is not restricted!"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "10"
		Description	     = "By limiting guest access to the most restrictive state this helps prevent malicious group and user object enumeration in the Microsoft 365 environment. This first step, known as reconnaissance in The Cyber Kill Chain, is often conducted by attackers prior to more advanced targeted attacks."
		Remediation	     = "Use one of the PowerShell script to remediate the issue"
		PowerShellScript = 'Update-MgPolicyAuthorizationPolicy -GuestUserRoleId "10dae51f-b6af-4016-8d66-8c2a99b929b3" or Update-MgPolicyAuthorizationPolicy -GuestUserRoleId "2af84b1e-32c8-42b7-82bc-daa82404023b"'
		DefaultValue	 = "PowerShell: 10dae51f-b6af-4016-8d66-8c2a99b929b3"
		ExpectedValue    = "PowerShell: 10dae51f-b6af-4016-8d66-8c2a99b929b3 or 2af84b1e-32c8-42b7-82bc-daa82404023b"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Restrict guest access permissions in Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/users/users-restrict-guest-permissions' },
		@{ 'Name' = 'The Cyber Kill Chain'; 'URL' = 'https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html' })
	}
	return $inspectorobject
}

function Audit-CISMAz5162
{
	try
	{
		# Actual Script
		$AuthPolicy = Get-MgPolicyAuthorizationPolicy
		
		
		# Validation
		if ($AuthPolicy.GuestUserRoleId -eq 'a0b1b346-4d3e-4e8b-98f8-753987be4970')
		{
			$AuthPolicy | Format-List | Out-File "$path\CISMAz5162-AuthorizationPolicy.txt"
			$finalobject = Build-CISMAz5162("Guest users have the same access as members (most inclusive)")
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
return Audit-CISMAz5162