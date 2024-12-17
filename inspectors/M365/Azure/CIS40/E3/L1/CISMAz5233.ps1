#Requires -module Az.Accounts
# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5233($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz5233"
		FindingName	     = "CISM MAz 5.2.3.3 - Password Protection is not enabled within your organization for on-prem Active Directory"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "5"
		Description	     = "This feature protects an organization by prohibiting the use of weak or leaked passwords. In addition, organizations can create custom banned password lists to prevent their users from using easily guessed passwords that are specific to their industry. Deploying this feature to Active Directory will strengthen the passwords that are used in the environment."
		Remediation	     = "You can manually change the settings for the Password Protection Policy to enable on-prem protection."
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/PasswordProtection'
		DefaultValue	 = "Enable - Yes \n Mode - Audit"
		ExpectedValue    = "Enable - Yes \n Mode - Enforced"
		ReturnedValue    = "$findings"
		Impact		     = "1"
		Likelihood	     = "5"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Enable on-premises Microsoft Entra Password Protection'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-ban-bad-on-premises-operations' })
	}
	return $inspectorobject
}

function Audit-CISMAz5233
{
	try
	{
		$AffectedOptions = @()
		# Actual Script
		$MethodsRequired = [PSCustomObject]@{}
		((Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groupSettings").value | Where-Object { $_.displayName -eq "Password Rule Settings" }).values | ForEach-Object { $MethodsRequired | Add-Member -NotePropertyName $_.Name -NotePropertyValue $_.value }
		# Validation
		if ($MethodsRequired.bannedPasswordCheckOnPremisesMode -ne 'Enforced')
		{
			$AffectedOptions += "PolicyMode: $($MethodsRequired.bannedPasswordCheckOnPremisesMode)"
		}
		if ($MethodsRequired.enableBannedPasswordCheckOnPremises -eq $false)
		{
			$AffectedOptions += "Password protection for Windows Server Active Directory: $($MethodsRequired.enableBannedPasswordCheckOnPremises)"
		}
		if ($AffectedOptions.count -igt 0)
		{
			$AffectedOptions | Format-Table -AutoSize | Out-File "$path\CISMAz5233-PasswordPolicy.txt"
			$finalobject = Build-CISMAz5233($AffectedOptions)
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

return Audit-CISMAz5233