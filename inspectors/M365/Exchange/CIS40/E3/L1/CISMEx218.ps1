# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v4.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure that SPF records are published for all Exchange Domains
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx218($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx218"
		FindingName	     = "CIS MEx 2.1.8 - SPF records are not published for all Exchange Domains"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "9"
		Description	     = "SPF records allow Exchange Online Protection and other mail systems know where messages from domains are allowed to originate. This information can be used by that system to determine how to treat the message based on if it is being spoofed or is valid."
		Remediation	     = "Create an SPF TXT DNS record as described in the references below. Remember that configuring SPF may affect the deliverability of mail from that domain. An SPF rollout should be measured and gradual."
		PowerShellScript = 'Not Available!'
		DefaultValue	 = "Null for all custom domains"
		ExpectedValue    = "v=spf1 include:spf.protection.outlook.com include:<domain name> -all"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "3"
		RiskRating	     = "Medium"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Set Up SPF in Office 365 to Help Prevent Spoofing'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/set-up-spf-in-office-365-to-help-prevent-spoofing?view=o365-worldwide" },
			@{ 'Name' = 'Explaining SPF Records'; 'URL' = "https://postmarkapp.com/blog/explaining-spf" }
			@{ 'Name' = 'Set up SPF to identify valid email sources for your Microsoft 365 domain'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-spf-configure?view=o365-worldwide" })
	}
	return $inspectorobject
}


function Inspect-CISMEx218
{
	Try
	{
		if ($PSVersionTable.PSVersion.Major -eq 7){
			if($IsLinux){
				$domains = (Get-AcceptedDomain).DomainName | Where-Object { $_.Id -notlike "*.onmicrosoft.com" }
				$domains_without_records = @()
				ForEach ($domain in $domains)
				{
					try
					{
						$spf_record = (host -t txt $domain) | where-object {$_ -match "v=spf1 include:spf.protection.outlook.com"}
						if ([string]::IsNullOrEmpty($spf_record) -eq $true)
						{
							$domains_without_records += $domain
						}
					}
					catch
					{
						$domains_without_records += $domain
					}
				}
			}
			else{
				$domains = (Get-AcceptedDomain).DomainName | Where-Object { $_.Id -notlike "*.onmicrosoft.com" }
				$domains_without_records = @()
				
				# The redirection is kind of a cheesy hack to prevent the output from
				# cluttering the screen.
				ForEach ($domain in $domains)
				{
					try
					{
						$spf_record = (Resolve-DnsName -Name $domain -Type TXT | Where-Object { $_.Strings -match 'v=spf1' }).Strings
						if ([string]::IsNullOrEmpty($spf_record) -eq $true)
						{
							$domains_without_records += $domain
						}
					}
					catch
					{
						$domains_without_records += $domain
					}
				}
			}
		}else{
			$domains = (Get-AcceptedDomain).DomainName | Where-Object { $_.Id -notlike "*.onmicrosoft.com" }
			$domains_without_records = @()
			
			# The redirection is kind of a cheesy hack to prevent the output from
			# cluttering the screen.
			ForEach ($domain in $domains)
			{
				try
				{
					$spf_record = (Resolve-DnsName -Name $domain -Type TXT | Where-Object { $_.Strings -match 'v=spf1' }).Strings
					if ([string]::IsNullOrEmpty($spf_record) -eq $true)
					{
						$domains_without_records += $domain
					}
				}
				catch
				{
					$domains_without_records += $domain
				}
			}
		}
		
		
		If ($domains_without_records.Count -ne 0)
		{
			$domains_without_records | Format-Table -AutoSize | Out-File "$path\CISMEx218-DomainsWithoutSPF.txt"
			$endobject = Build-CISMEx218($domains_without_records)
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

return Inspect-CISMEx218


