# . "..\M365SAT.psm1"
function Get-M365SATCSVReport
{
	Param ($object,
		$OutPath,
		$inspectors)

        # Initalize Dates
        $StartDate = $object.StartDate
        $ReportDate = $object.EndDate

        # Sort all findings
        $SortedFindings = $object.Findings | Sort-Object $_.ID

        #CompanyName
        try{
            # Microsoft Graph Variant
            $CompanyName = (Get-MgOrganization).DisplayName
            $TenantName = (((Get-MgOrganization).VerifiedDomains |  Where-Object { ($_.Name -like "*.onmicrosoft.com") -and ($_.Name -notlike "*mail.onmicrosoft.com") }).Name -split '.onmicrosoft.com')[0]
        }catch{
            # Microsoft Exchange Variant
            $CompanyName = (Get-AcceptedDomain | Where-Object { $_.Default -eq 'True' }).DomainName
            $TenantName = ((Get-AcceptedDomain |  Where-Object {  { $_.Default -eq 'True' } -and ($_.DomainName -like "*.onmicrosoft.com") -and ($_.DomainName -notlike "*mail.onmicrosoft.com") }).DomainName -split '.onmicrosoft.com')[0]
        }

        # Initialize Empty List
        $FinalFindings = @()

        # Create a count of findings
        $FindingCounter = 0

        foreach ($finding in $SortedFindings){
            if ($null -NE $finding.ReturnedValue){
                $FindingCounter += 1

                # Create empty list for References
                $refs = New-Object System.Collections.ArrayList
                foreach ($Reference in $finding.References){
                    $refs.Add("$($Reference.Name) : $($Reference.URL)") | Out-Null
                }
                $finalrefs = $refs -join '^'
                $refs.Clear()
            }
            $result = [PSCustomObject]@{
                UUID                 = $finding.UUID
                ID			         = $finding.ID
                Title                = $finding.Title
                ProductFamily        = $finding.ProductFamily
                DefaultValue	     = $finding.DefaultValue
                ExpectedValue        = $finding.ExpectedValue
                ReturnedValue        = $("$($finding.ReturnedValue)" | Out-String).Trim()
                'Remediation Status' = $finding.Status
                'Notes'              = " "
                Description	         = $finding.Description
                Impact               = $finding.Impact
                Remediation          = $(($finding.Remediation) -join " ")
                References           = $finalrefs
            }
            $FinalFindings += $result
        }
        $FinalFindings | Export-Csv "$OutPath\$($TenantName)_$(Get-Date -Format "yyyyMMddhhmmss").csv" -Delimiter '^' -NoTypeInformation -Append -Force
}