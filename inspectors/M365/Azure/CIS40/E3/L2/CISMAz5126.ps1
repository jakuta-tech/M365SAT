#Requires -module Az.Accounts
# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure 'LinkedIn account connections' is disabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISMAz5126($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz5126"
		FindingName	     = "CIS MAz 5.1.2.6 - LinkedIn Account Connections is enabled!"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "5"
		Description	     = "Disabling LinkedIn integration prevents potential phishing attacks and risk scenarios where an external party could accidentally disclose sensitive information."
		Remediation	     = "Change the value to 1 (No) to disable LinkedIn"
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/UserSettings/menuId/UserSettings'
		DefaultValue	 = "0"
		ExpectedValue    = "1"
		ReturnedValue    = "$findings"
		Impact		     = "1"
		Likelihood	     = "5"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Integrate LinkedIn account connections in Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/users/linkedin-integration' },
		@{ 'Name' = 'LinkedIn account connections data sharing and consent'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/users/linkedin-user-consent' })
	}
	return $inspectorobject
}

function Audit-CISMAz5126
{
	try
	{
		$AffectedOptions = @()
		# Actual Script
		$LinkedInCheck = Invoke-MultiMicrosoftAPI -Url 'https://main.iam.ad.ext.azure.com/api/Directories/Properties' -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -Method 'GET'
		
		# Validation
		if ($LinkedInCheck.enableLinkedInAppFamily -ne 1)
		{
			$AffectedOptions += "enableLinkedInAppFamily: $($LinkedInCheck.enableLinkedInAppFamily)"
		}
		if ($AffectedOptions.count -igt 0)
		{
			$LinkedInCheck | Format-List | Out-File "$path\CISMAz5126-LinkedInSettings.txt"
			$finalobject = Build-CISMAz5126($AffectedOptions)
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

function Invoke-MultiMicrosoftAPI
{
	param (
		#The whole URL to call
		[Parameter()]
		[String]$Url,
		#The Name of the Resource
		[Parameter()]
		[String]$Resource,
		[Parameter()]
		#Body if a POST or PUT
		[Object]$Body,
		[Parameter()]
		#Specify the HTTP Method you wish to use. Defaults to GET
		[ValidateSet("GET", "POST", "OPTIONS", "DELETE", "PUT")]
		[String]$Method = "GET"
	)
	
	try
	{
		[Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext]$Context = (Get-AzContext | Select-Object -first 1)
	}
	catch
	{
		Connect-AzAccount -ErrorAction Stop
		[Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext]$Context = (Get-AzContext | Select-Object -first 1)
	}
	
	#Specify Resource
	$apiToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id, $null, "Never", $null, $Resource)
	
	# Creating the important header
	$header = [ordered]@{
		'Authorization' = 'Bearer ' + $apiToken.AccessToken.ToString()
		'Content-Type'  = 'application/json'
		'X-Requested-With' = 'XMLHttpRequest'
		'x-ms-client-request-id' = [guid]::NewGuid()
		'x-ms-correlation-id' = [guid]::NewGuid()
	}
	# URL Where PUT Request is being done. You can extract this from F12 
	
	$method = 'GET'
	
	#In Case your Method is PUT or POST to edit something. Change things here
	
	if ($method -eq 'PUT')
	{
		# Remediation Scripts HERE
		$contentpart1 = '{"restrictNonAdminUsers":false}'
		
		#Convert the content (DUMMY)
		$Body = $contentpart1
		
		#Execute Request
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -Body $Body -ErrorAction Stop
	}
	elseif ($method -eq 'POST')
	{
		#Execute Request
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -Body $Body -ErrorAction Stop
	}
	elseif ($method -eq 'GET')
	{
		#Execute Request
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -ErrorAction Stop
	}
	return $Response
}
return Audit-CISMAz5126