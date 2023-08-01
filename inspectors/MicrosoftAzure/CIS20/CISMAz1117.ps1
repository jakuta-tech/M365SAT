#Requires -module Az.Accounts
# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that collaboration invitations are sent to allowed domains only
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz1117($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz1117"
		FindingName	     = "CIS MAz 1.1.17 - collaboration invitations are not sent to allowed domains only"
		ProductFamily    = "Microsoft Azure"
		CVS			     = "7.8"
		Description	     = "Azure Active Directory (Azure AD) B2B collaboration is a feature within External Identities allows for guest invitations to an organization. Ensure users can only send invitations to specified domains. By specifying allowed domains for collaborations, external users companies are explicitly identified. Also, this prevents internal users from inviting unknown external users such as personal accounts and give them access to resources."
		Remediation	     = "Change the value to most-restrictive. In the portal itself and add only the desired tenants to the list."
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AllowlistPolicyBlade'
		DefaultValue	 = "Allow invitations to be sent to any domain (most inclusive) (False)"
		ExpectedValue    = "Allow invitations only to the specified domains (most restrictive) (True)"
		ReturnedValue    = "$findings"
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Allow or block invitations to B2B users from specific organizations'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/external-identities/allow-deny-list' })
	}
	return $inspectorobject
}

function Audit-CISMAz1117
{
	try
	{
		$AffectedOptions = @()
		# Actual Script
		$B2BPolicy = Invoke-MultiMicrosoftAPI -Url 'https://main.iam.ad.ext.azure.com/api/B2B/b2bPolicy' -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -Method 'GET'
		
		# Validation
		if ($B2BPolicy.isAllowlist -eq $false)
		{
			$AffectedOptions += "Allow invitations to be sent to any domain (most inclusive)"
		}
		if ($AffectedOptions.count -igt 0)
		{
			$finalobject = Build-CISMAz1117($AffectedOptions)
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
return Audit-CISMAz1117