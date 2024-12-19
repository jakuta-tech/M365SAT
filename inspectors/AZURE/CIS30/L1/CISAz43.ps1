# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that 'Enable key rotation reminders' is enabled for each Storage Account
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz43($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz43"
		FindingName	     = "CIS Az 4.3 - Setting 'Enable key rotation reminders' is not enabled for each Storage Account"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Reminders such as those generated by this recommendation will help maintain a regular and healthy cadence for activities which improve the overall efficacy of a security program. Cryptographic key rotation periods will vary depending on your organization's security requirements and the type of data which is being stored in the Storage Account. For example, PCI DSS mandates that cryptographic keys be replaced or rotated 'regularly,'and advises that keys for static data stores be rotated every 'few months.'For the purposes of this recommendation, 90 days will prescribed for the reminder. Review and adjustment of the 90 day period is recommended, and may even be necessary. Your organization's security requirements should dictate the appropriate setting"
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'Get-AzStorageAccount | Set-AzStorageAccount -Name $_.StorageAccountName -KeyExpirationPeriodInDay 90'
		DefaultValue	 = "Null"
		ExpectedValue    = "KeyExpirationPeriodInDay: 90"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Create a storage account'; 'URL' = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-account-create?tabs=azure-portal#regenerate-storage-access-keys' },
		@{ 'Name' = 'PA-1: Separate and limit highly privileged/administrative users'; 'URL' = 'https://pcidssguide.com/pci-dss-key-rotation-requirements/' },
		@{ 'Name' = 'IM-3: Manage application identities securely and automatically'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-3-manage-application-identities-securely-and-automatically' },
		@{ 'Name' = 'GS-6: Define and implement identity and privileged access strategy'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy' },
		@{ 'Name' = 'IM-8: Restrict the exposure of credentials and secrets'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-8-restrict-the-exposure-of-credentials-and-secrets' },
		@{ 'Name' = 'PCI DSS Key Rotation Requirements'; 'URL' = 'https://pcidssguide.com/pci-dss-key-rotation-requirements/' },
		@{ 'Name' = 'NIST 800-57 Rev. 5 - Recommendation for Key Management'; 'URL' = 'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf' })
	}
	return $inspectorobject
}

function Audit-CISAz43
{
	try
	{
		$violation = @()
		$accounts = Get-AzStorageAccount -ErrorAction SilentlyContinue
		ForEach ($account in $accounts){
			if ($account.KeyPolicy.KeyExpirationPeriodInDays -lt 90 -or $null -eq $account.KeyPolicy.KeyExpirationPeriodInDays){
				$violation += $account.StorageAccountName
			}elseif ($null -eq $account.KeyCreationTime.Key1 -or $null -eq $account.KeyCreationTime.Key2){
				$violation += $account.StorageAccountName
			}
		}

		if ($violation.Count -igt 0){
			$finalobject = Build-CISAz43($violation)
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
return Audit-CISAz43