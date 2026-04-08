<#
.SYNOPSIS
    Discovery script for Configuration Manager Get-SecureBootUpdateData CI

.DESCRIPTION
    Checks if the specified WMI class exists and has been updated in the specified number of days

.NOTES
  Author: Eric Schloss
  Version: 1.0
  Created: 2026-03-30

#>

$ClassName = "SecureBootUpdateData"
$DetectionDays = 4

$SecureBootUpdateData = Get-CimInstance -ClassName $ClassName -ErrorAction SilentlyContinue

If($SecureBootUpdateData)
{
    $LastUpdate = Get-Date -Date $SecureBootUpdateData.CollectionTime

    If($LastUpdate -ge (Get-Date).AddDays(-$($DetectionDays)))
    {
        Write-Host "Compliant"
    }
    Else
    {
        Write-Host "Non-compliant"
    }
}
else
{
    Write-Host "Data does not exist"
}