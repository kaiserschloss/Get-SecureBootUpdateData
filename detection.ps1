#detection
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