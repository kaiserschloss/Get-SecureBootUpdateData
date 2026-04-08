<#
.SYNOPSIS
    Remediation script for Configuration Manager Get-SecureBootUpdateData CI

.DESCRIPTION
    Based on https://support.microsoft.com/en-us/topic/sample-secure-boot-inventory-data-collection-script-d02971d2-d4b5-42c9-b58a-8527f0ffa30b
    Pulls secure boot update data from the example script and stores it in the specified WMI class. This data can them be pulled into
    Configuration Manager via hardware inventory.

.NOTES
  Author: Eric Schloss
  Version: 1.0
  Created: 2026-03-30

#>

function Get-CimTypeFromValue
{
    param($Value)

    if ($null -eq $Value)
    {
        return [System.Management.CimType]::String
    }

    switch ($Value.GetType().FullName)
    {
        'System.Boolean'  { return [System.Management.CimType]::Boolean }
        'System.UInt16'   { return [System.Management.CimType]::UInt16 }
        'System.UInt32'   { return [System.Management.CimType]::UInt32 }
        'System.UInt64'   { return [System.Management.CimType]::UInt64 }
        'System.Int16'    { return [System.Management.CimType]::SInt16 }
        'System.Int32'    { return [System.Management.CimType]::SInt32 }
        'System.Int64'    { return [System.Management.CimType]::SInt64 }
        'System.DateTime' { return [System.Management.CimType]::String } # store ISO8601 string like you already do
        default           { return [System.Management.CimType]::String }
    }
}


function Ensure-WmiClass
{
    param(
        [string]$Namespace,
        [string]$ClassName,
        [System.Collections.IDictionary]$Status,
        [string]$KeyPropName
    )

    # If class exists, do nothing
    if (Get-CimClass -Namespace $Namespace -ClassName $ClassName -ErrorAction SilentlyContinue)
    {
        return
    }

    # Create class
    $newClass = New-Object System.Management.ManagementClass($Namespace, [String]::Empty, $null)
    $newClass["__CLASS"] = $ClassName
    #$newClass.Qualifiers.Add("Static", $true) | Out-Null  # typical for “tattoo” classes (optional)

    # Key property (required)
    $newClass.Properties.Add($KeyPropName, [System.Management.CimType]::String, $false) | Out-Null
    $newClass.Properties[$KeyPropName].Qualifiers.Add("Key", $true) | Out-Null

    # Add remaining properties
    foreach ($k in $Status.Keys) {
        if ($k -eq $KeyPropName) { continue }

        $cimType = Get-CimTypeFromValue -Value $Status[$k]
        $newClass.Properties.Add($k, $cimType, $false) | Out-Null
    }

    # Commit schema
    $null = $newClass.Put()
}

function Get-WmiClassSchemaMap
{
    param([string]$Namespace, [string]$ClassName)

    $class = Get-CimClass -Namespace $Namespace -ClassName $ClassName -ErrorAction Stop
    $map = @{}
    foreach ($p in $class.CimClassProperties) { $map[$p.Name] = $p.CimType }
    return $map
}

function Convert-ToSchemaValue
{
    param(
        [object]$Value,
        [Microsoft.Management.Infrastructure.CimType]$CimType
    )

    if ($null -eq $Value) { return $null }

    # unwrap if needed
    if ($Value -is [psobject]) { $Value = $Value.PSObject.BaseObject }

    # Empty strings should not be pushed into numeric/bool props
    if ($CimType -ne [Microsoft.Management.Infrastructure.CimType]::String) {
        if ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value)) { return $null }
    }

    switch ($CimType.ToString()) {
        'Boolean' { return [bool]$Value }
        'SInt32'  { return [int]$Value }   # explicit cast avoids IConvertible pain [2](http://www.jose.it-berater.org/wmi/wql/datetime.htm)
        default   { return [string]$Value }
    }
}

function Build-WmiArguments {
    param(
        [System.Collections.IDictionary]$Status,
        [hashtable]$SchemaMap,
        [string]$KeyPropName
    )

    $args = @{}

    # Always include key (must be present)
    $args[$KeyPropName] = [string]$Status[$KeyPropName]

    foreach ($k in $Status.Keys) {
        if ($k -eq $KeyPropName) { continue }
        if (-not $SchemaMap.ContainsKey($k)) { continue }

        $converted = Convert-ToSchemaValue -Value $Status[$k] -CimType $SchemaMap[$k]

        # IMPORTANT: don't send nulls for value-type fields
        if ($null -eq $converted -and ($SchemaMap[$k].ToString() -in @('Boolean','SInt32'))) {
            continue
        }

        $args[$k] = $converted
    }

    return $args
}

function Write-Log
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("LogContent")]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [ValidateSet("normal","debug")]
        [string]$MessageType="normal",

        [Parameter(Mandatory=$false)]
        [Alias('LogPath')]
        [string]$Path=$LogFile,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Error","Warn","Info")]
        [string]$Level="Info",
        
        [Parameter(Mandatory=$false)]
        [switch]$NoClobber
    )

    Begin
    {
        # Set VerbosePreference to Continue so that verbose messages are displayed.
        $VerbosePreference = 'Continue'
    }
    Process
    {
        
        # If the file already exists and NoClobber was specified, do not write to the log.
        if ((Test-Path $Path) -AND $NoClobber) {
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name."
            Return
            }

        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
        elseif (!(Test-Path $Path)) {
            Write-Verbose "Creating $Path."
            $NewLogFile = New-Item $Path -Force -ItemType File
            }

        else {
            # Nothing to see here yet.
            }

        # Format Date for our Log File
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        # Write message to error, warning, or verbose pipeline and specify $LevelText
        switch ($Level) {
            'Error' {
                Write-Error $Message
                $LevelText = 'ERROR:'
                }
            'Warn' {
                Write-Warning $Message
                $LevelText = 'WARNING:'
                }
            'Info' {
                Write-Verbose $Message
                $LevelText = 'INFO:'
                }
            }
        
        # Write log entry to $Path
        $WriteDebugMessage = $false
        If($LogLevel -eq "debug")
        {
            If($MessageType -eq "debug")
            {
                $WriteDebugMessage = $true
            }
        }

        Switch($MessageType)
        {
            "normal" { "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append }
            "debug"  { if($LogLevel -eq "debug"){ "$FormattedDate $LevelText [DEBUG]::$Message" | Out-File -FilePath $Path -Append } }
        }
    }
    End
    {
    }
}

$LogFile = "C:\Windows\Logs\Software\Get-SecureBootUpdateData.log"

Write-Log -Message "**********************************************************************************"

# 1. HostName
# PS Version: All | Admin: No | System Requirements: None
try 
{
    $hostname = $env:COMPUTERNAME
    if ([string]::IsNullOrEmpty($hostname))
    {
        $hostname = "Unknown"
    }
}
catch
{
    $hostname = "Error"
}
Write-Log -Message "Hostname: $hostname"

# 2. CollectionTime
# PS Version: All | Admin: No | System Requirements: None
try
{
    $collectionTime = Get-Date
    if ($null -eq $collectionTime)
    {
        $collectionTime = "Unknown"
    }
}
catch
{
    $collectionTime = "Error"
}
Write-Log -Message "Collection Time: $collectionTime"

# Registry: Secure Boot Main Key (3 values)

# 3. SecureBootEnabled
# PS Version: 3.0+ | Admin: May be required | System Requirements: UEFI/Secure Boot capable system
try
{
    $secureBootEnabled = Confirm-SecureBootUEFI -ErrorAction Stop
}
catch
{
    # Try registry fallback
    try {
        $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name UEFISecureBootEnabled -ErrorAction Stop
        $secureBootEnabled = [bool]$regValue.UEFISecureBootEnabled
    }
    catch
    {
        $secureBootEnabled = $null
    }
}
Write-Log -Message "Secure Boot Enabled: $secureBootEnabled"

# 4. HighConfidenceOptOut
# PS Version: All | Admin: May be required | System Requirements: None
try
{
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name HighConfidenceOptOut -ErrorAction Stop
    $highConfidenceOptOut = $regValue.HighConfidenceOptOut
}
catch
{
    # HighConfidenceOptOut is optional - not present on most systems
    $highConfidenceOptOut = $null
}
Write-Log -Message "High Confidence Opt Out: $highConfidenceOptOut"

# 4b. MicrosoftUpdateManagedOptIn
# PS Version: All | Admin: May be required | System Requirements: None
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name MicrosoftUpdateManagedOptIn -ErrorAction Stop
    $microsoftUpdateManagedOptIn = $regValue.MicrosoftUpdateManagedOptIn  
}
catch
{
    # MicrosoftUpdateManagedOptIn is optional - not present on most systems
    $microsoftUpdateManagedOptIn = $null
}
Write-Log -Message "Microsoft Update Managed Opt In: $microsoftUpdateManagedOptIn"

# 5. AvailableUpdates
# PS Version: All | Admin: May be required | System Requirements: None
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name AvailableUpdates -ErrorAction Stop
    $availableUpdates = $regValue.AvailableUpdates
    if ($null -ne $availableUpdates) {
        # Convert to hexadecimal format
        $availableUpdatesHex = "0x{0:X}" -f $availableUpdates
        Write-Log -Message "Available Updates: $availableUpdatesHex"
    } else {
        Write-Log -Message "Available Updates: Not Available"
    }
} catch {
    Write-Log -Message "AvailableUpdates registry key not found or inaccessible" -Level Warn
    $availableUpdates = $null
    Write-Log -Message "Available Updates: Not Available"
}

# 5b. AvailableUpdatesPolicy (GPO-controlled persistent value)
# PS Version: All | Admin: May be required | System Requirements: None
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name AvailableUpdatesPolicy -ErrorAction Stop
    $availableUpdatesPolicy = $regValue.AvailableUpdatesPolicy
    if ($null -ne $availableUpdatesPolicy) {
        # Convert to hexadecimal format
        $availableUpdatesPolicyHex = "0x{0:X}" -f $availableUpdatesPolicy
        Write-Log -Message "Available Updates Policy: $availableUpdatesPolicyHex"
    } else {
        Write-Log -Message "Available Updates Policy: Not Set"
    }
} catch {
    # AvailableUpdatesPolicy is optional - only set when GPO is applied
    $availableUpdatesPolicy = $null
    Write-Log -Message "Available Updates Policy: Not Set"
}

# Registry: Servicing Key (3 values)

# 6. UEFICA2023Status
# PS Version: All | Admin: May be required | System Requirements: None
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name UEFICA2023Status -ErrorAction Stop
    $uefica2023Status = $regValue.UEFICA2023Status
    Write-Log -Message "Windows UEFI CA 2023 Status: $uefica2023Status"
} catch {
    Write-Log -Message "Windows UEFI CA 2023 Status registry key not found or inaccessible" -Level Warn
    $uefica2023Status = $null
    Write-Log -Message "Windows UEFI CA 2023 Status: Not Available"
}

# 7. UEFICA2023Error
# PS Version: All | Admin: May be required | System Requirements: None
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name UEFICA2023Error -ErrorAction Stop
    $uefica2023Error = $regValue.UEFICA2023Error
    Write-Log -Message "UEFI CA 2023 Error: $uefica2023Error"
} catch {
    # UEFICA2023Error only exists if there was an error - absence is good
    $uefica2023Error = $null
    Write-Log -Message "UEFI CA 2023 Error: None"
}

# 8. UEFICA2023ErrorEvent
# PS Version: All | Admin: May be required | System Requirements: None
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name UEFICA2023ErrorEvent -ErrorAction Stop
    $uefica2023ErrorEvent = $regValue.UEFICA2023ErrorEvent
    Write-Log -Message "UEFI CA 2023 Error Event: $uefica2023ErrorEvent"
} catch {
    $uefica2023ErrorEvent = $null
    Write-Log -Message "UEFI CA 2023 Error Event: Not Available"
}

# Registry: Device Attributes (7 values: 9-15)

# 9. OEMManufacturerName
# PS Version: All | Admin: May be required | System Requirements: None
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name OEMManufacturerName -ErrorAction Stop
    $oemManufacturerName = $regValue.OEMManufacturerName
    if ([string]::IsNullOrEmpty($oemManufacturerName)) {
        Write-Log -Message "OEMManufacturerName is empty" -Level Warn
        $oemManufacturerName = "Unknown"
    }
    Write-Log -Message "OEM Manufacturer Name: $oemManufacturerName"
} catch {
    Write-Log -Message "OEMManufacturerName registry key not found or inaccessible" -Level Warn
    $oemManufacturerName = $null
    Write-Log -Message "OEM Manufacturer Name: Not Available"
}

# 10. OEMModelSystemFamily
# PS Version: All | Admin: May be required | System Requirements: None
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name OEMModelSystemFamily -ErrorAction Stop
    $oemModelSystemFamily = $regValue.OEMModelSystemFamily
    if ([string]::IsNullOrEmpty($oemModelSystemFamily)) {
        Write-Log -Message "OEMModelSystemFamily is empty" -Level Warn
        $oemModelSystemFamily = "Unknown"
    }
    Write-Log -Message "OEM Model System Family: $oemModelSystemFamily"
} catch {
    Write-Log -Message "OEMModelSystemFamily registry key not found or inaccessible" -Level Warn
    $oemModelSystemFamily = $null
    Write-Log -Message "OEM Model System Family: Not Available"
}

# 11. OEMModelNumber
# PS Version: All | Admin: May be required | System Requirements: None
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name OEMModelNumber -ErrorAction Stop
    $oemModelNumber = $regValue.OEMModelNumber
    if ([string]::IsNullOrEmpty($oemModelNumber)) {
        Write-Log -Message "OEMModelNumber is empty" -Level Warn
        $oemModelNumber = "Unknown"
    }
    Write-Log -Message "OEM Model Number: $oemModelNumber"
} catch {
    Write-Log -Message "OEMModelNumber registry key not found or inaccessible" -Level Warn
    $oemModelNumber = $null
    Write-Log -Message "OEM Model Number: Not Available"
}

# 12. FirmwareVersion
# PS Version: All | Admin: May be required | System Requirements: None
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name FirmwareVersion -ErrorAction Stop
    $firmwareVersion = $regValue.FirmwareVersion
    if ([string]::IsNullOrEmpty($firmwareVersion)) {
        Write-Log -Message "FirmwareVersion is empty" -Level Warn
        $firmwareVersion = "Unknown"
    }
    Write-Log -Message "Firmware Version: $firmwareVersion"
} catch {
    Write-Log -Message "FirmwareVersion registry key not found or inaccessible" -Level Warn
    $firmwareVersion = $null
    Write-Log -Message "Firmware Version: Not Available"
}

# 13. FirmwareReleaseDate
# PS Version: All | Admin: May be required | System Requirements: None
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name FirmwareReleaseDate -ErrorAction Stop
    $firmwareReleaseDate = $regValue.FirmwareReleaseDate
    if ([string]::IsNullOrEmpty($firmwareReleaseDate)) {
        Write-Log -Message "FirmwareReleaseDate is empty" -Level Warn
        $firmwareReleaseDate = "Unknown"
    }
    Write-Log -Message "Firmware Release Date: $firmwareReleaseDate"
} catch {
    Write-Log -Message "FirmwareReleaseDate registry key not found or inaccessible" -Level Warn
    $firmwareReleaseDate = $null
    Write-Log -Message "Firmware Release Date: Not Available"
}

# 14. OSArchitecture
# PS Version: All | Admin: No | System Requirements: None
try {
    $osArchitecture = $env:PROCESSOR_ARCHITECTURE
    if ([string]::IsNullOrEmpty($osArchitecture)) {
        # Try registry fallback
        $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name OSArchitecture -ErrorAction Stop
        $osArchitecture = $regValue.OSArchitecture
    }
    if ([string]::IsNullOrEmpty($osArchitecture)) {
        Write-Log -Message "OSArchitecture could not be determined" -Level Warn
        $osArchitecture = "Unknown"
    }
    Write-Log -Message "OS Architecture: $osArchitecture"
} catch {
    Write-Log -Message "Error retrieving OSArchitecture: $_" -Level Warn
    $osArchitecture = "Unknown"
    Write-Log -Message "OS Architecture: $osArchitecture"
}

# 15. CanAttemptUpdateAfter (FILETIME)
# PS Version: All | Admin: May be required | System Requirements: None
try {
    $regValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes" -Name CanAttemptUpdateAfter -ErrorAction Stop
    $canAttemptUpdateAfter = $regValue.CanAttemptUpdateAfter
    # Convert FILETIME to UTC DateTime — registry stores as REG_BINARY (byte[]) or REG_QWORD (long)
    if ($null -ne $canAttemptUpdateAfter) {
        try {
            if ($canAttemptUpdateAfter -is [byte[]]) {
                $fileTime = [BitConverter]::ToInt64($canAttemptUpdateAfter, 0)
                $canAttemptUpdateAfter = [DateTime]::FromFileTime($fileTime).ToUniversalTime()
            } elseif ($canAttemptUpdateAfter -is [long]) {
                $canAttemptUpdateAfter = [DateTime]::FromFileTime($canAttemptUpdateAfter).ToUniversalTime()
            }
        } catch {
            Write-Log -Message "Could not convert CanAttemptUpdateAfter FILETIME to DateTime" -Level Warn
        }
    }
    Write-Log -Message "Can Attempt Update After: $canAttemptUpdateAfter"
} catch {
    Write-Log -Message "CanAttemptUpdateAfter registry key not found or inaccessible" -Level Warn
    $canAttemptUpdateAfter = $null
    Write-Log -Message "Can Attempt Update After: Not Available"
}

# Event Logs: System Log (10 values: 16-25)

# 16-25. Event Log queries
# Event IDs:
#   1801 - Update initiated, reboot required
#   1808 - Update completed successfully
#   1795 - Firmware returned error (capture error code)
#   1796 - Error logged with error code (capture code)
#   1800 - Reboot needed (NOT an error - update will proceed after reboot)
#   1802 - Known firmware issue blocked update (capture KI_<number> from SkipReason)
#   1803 - Matching KEK update not found (OEM needs to supply PK signed KEK)
# PS Version: 3.0+ | Admin: May be required for System log | System Requirements: None
try {
    # Query all relevant Secure Boot event IDs
    $allEventIds = @(1795, 1796, 1800, 1801, 1802, 1803, 1808)
    $events = @(Get-WinEvent -FilterHashtable @{LogName='System'; ID=$allEventIds} -MaxEvents 50 -ErrorAction Stop)

    if ($events.Count -eq 0) {
        Write-Log -Message "No Secure Boot events found in System log" -Level Warn
        $latestEventId = $null
        $bucketId = $null
        $confidence = $null
        $skipReasonKnownIssue = $null
        $event1801Count = 0
        $event1808Count = 0
        $event1795Count = 0
        $event1795ErrorCode = $null
        $event1796Count = 0
        $event1796ErrorCode = $null
        $event1800Count = 0
        $rebootPending = $false
        $event1802Count = 0
        $knownIssueId = $null
        $event1803Count = 0
        $missingKEK = $false
        Write-Log -Message "Latest Event ID: Not Available"
        Write-Log -Message "Bucket ID: Not Available"
        Write-Log -Message "Confidence: Not Available"
        Write-Log -Message "Event 1801 Count: 0"
        Write-Log -Message "Event 1808 Count: 0"
    } else {
        # 16. LatestEventId
        $latestEvent = $events | Sort-Object TimeCreated -Descending | Select-Object -First 1
        if ($null -eq $latestEvent) {
            Write-Log -Message "Could not determine latest event" -Level Warn
            $latestEventId = $null
            Write-Log -Message "Latest Event ID: Not Available"
        } else {
            $latestEventId = $latestEvent.Id
            Write-Log -Message "Latest Event ID: $latestEventId"
        }

        # 17. BucketID - Extracted from Event 1801/1808
        if ($null -ne $latestEvent -and $null -ne $latestEvent.Message) {
            if ($latestEvent.Message -match 'BucketId:\s*(.+)') {
                $bucketId = $matches[1].Trim()
                Write-Log -Message "Bucket ID: $bucketId"
            } else {
                Write-Log -Message "BucketId not found in event message" -Level Warn
                $bucketId = $null
                Write-Log -Message "Bucket ID: Not Found in Event"
            }
        } else {
            Write-Log -Message "Latest event or message is null, cannot extract BucketId" -Level Warn
            $bucketId = $null
            Write-Log -Message "Bucket ID: Not Available"
        }

        # 18. Confidence - Extracted from Event 1801/1808
        if ($null -ne $latestEvent -and $null -ne $latestEvent.Message) {
            if ($latestEvent.Message -match 'BucketConfidenceLevel:\s*(.+)') {
                $confidence = $matches[1].Trim()
                Write-Log -Message "Confidence: $confidence"
            } else {
                Write-Log -Message "Confidence level not found in event message" -Level Warn
                $confidence = $null
                Write-Log -Message "Confidence: Not Found in Event"
            }
        } else {
            Write-Log -Message "Latest event or message is null, cannot extract Confidence" -Level Warn
            $confidence = $null
            Write-Log -Message "Confidence: Not Available"
        }

        # 18b. SkipReason - Extract KI_<number> from SkipReason in the same event as BucketId
        # This captures Known Issue IDs that appear alongside BucketId/Confidence (not just Event 1802)
        $skipReasonKnownIssue = $null
        if ($null -ne $latestEvent -and $null -ne $latestEvent.Message) {
            if ($latestEvent.Message -match 'SkipReason:\s*(KI_\d+)') {
                $skipReasonKnownIssue = $matches[1]
                Write-Log -Message "SkipReason Known Issue: $skipReasonKnownIssue" -Level Warn
            }
        }

        # 19. Event1801Count
        $event1801Array = @($events | Where-Object {$_.Id -eq 1801})
        $event1801Count = $event1801Array.Count
        Write-Log -Message "Event 1801 Count: $event1801Count"

        # 20. Event1808Count
        $event1808Array = @($events | Where-Object {$_.Id -eq 1808})
        $event1808Count = $event1808Array.Count
        Write-Log -Message "Event 1808 Count: $event1808Count"
        
        # Initialize error event variables
        $event1795Count = 0
        $event1795ErrorCode = $null
        $event1796Count = 0
        $event1796ErrorCode = $null
        $event1800Count = 0
        $rebootPending = $false
        $event1802Count = 0
        $knownIssueId = $null
        $event1803Count = 0
        $missingKEK = $false
        
        # Only check for error events if update is NOT complete
        # Skip error analysis if: 1808 is latest event OR UEFICA2023Status is "Updated"
        $updateComplete = ($latestEventId -eq 1808) -or ($uefica2023Status -eq "Updated")
        
        if (-not $updateComplete) {
            Write-Log -Message "Update not complete - checking for error events..." -Level Warn
            
            # 21. Event1795 - Firmware Error (capture error code)
            $event1795Array = @($events | Where-Object {$_.Id -eq 1795})
            $event1795Count = $event1795Array.Count
            if ($event1795Count -gt 0) {
                $latestEvent1795 = $event1795Array | Sort-Object TimeCreated -Descending | Select-Object -First 1
                if ($latestEvent1795.Message -match '(?:error|code|status)[:\s]*(?:0x)?([0-9A-Fa-f]{8}|[0-9A-Fa-f]+)') {
                    $event1795ErrorCode = $matches[1]
                }
                Write-Log -Message "Event 1795 (Firmware Error) Count: $event1795Count" $(if ($event1795ErrorCode) { "Code: $event1795ErrorCode" })
            }
            
            # 22. Event1796 - Error Code Logged (capture error code)
            $event1796Array = @($events | Where-Object {$_.Id -eq 1796})
            $event1796Count = $event1796Array.Count
            if ($event1796Count -gt 0) {
                $latestEvent1796 = $event1796Array | Sort-Object TimeCreated -Descending | Select-Object -First 1
                if ($latestEvent1796.Message -match '(?:error|code|status)[:\s]*(?:0x)?([0-9A-Fa-f]{8}|[0-9A-Fa-f]+)') {
                    $event1796ErrorCode = $matches[1]
                }
                Write-Log -Message "Event 1796 (Error Logged) Count: $event1796Count" $(if ($event1796ErrorCode) { "Code: $event1796ErrorCode" })
            }
            
            # 23. Event1800 - Reboot Needed (NOT an error - update will proceed after reboot)
            $event1800Array = @($events | Where-Object {$_.Id -eq 1800})
            $event1800Count = $event1800Array.Count
            $rebootPending = $event1800Count -gt 0
            if ($rebootPending) {
                Write-Log -Message "Event 1800 (Reboot Pending): Update will proceed after reboot"
            }
            
            # 24. Event1802 - Known Firmware Issue (capture KI_<number> from SkipReason)
            $event1802Array = @($events | Where-Object {$_.Id -eq 1802})
            $event1802Count = $event1802Array.Count
            if ($event1802Count -gt 0) {
                $latestEvent1802 = $event1802Array | Sort-Object TimeCreated -Descending | Select-Object -First 1
                if ($latestEvent1802.Message -match 'SkipReason:\s*(KI_\d+)') {
                    $knownIssueId = $matches[1]
                }
                Write-Log -Message "Event 1802 (Known Firmware Issue) Count: $event1802Count" $(if ($knownIssueId) { "KI: $knownIssueId" })
            }
            
            # 25. Event1803 - Missing KEK Update (OEM needs to supply PK signed KEK)
            $event1803Array = @($events | Where-Object {$_.Id -eq 1803})
            $event1803Count = $event1803Array.Count
            $missingKEK = $event1803Count -gt 0
            if ($missingKEK) {
                Write-Log -Message "Event 1803 (Missing KEK): OEM needs to supply PK signed KEK" -Level Warn
            }
        } else {
            Write-Log -Message "Update complete (Event 1808 or Status=Updated) - skipping error analysis"
        }
    }
} catch {
    Write-Log -Message "Error retrieving event logs. May require administrator privileges: $_" -Level Warn
    $latestEventId = $null
    $bucketId = $null
    $confidence = $null
    $skipReasonKnownIssue = $null
    $event1801Count = 0
    $event1808Count = 0
    $event1795Count = 0
    $event1795ErrorCode = $null
    $event1796Count = 0
    $event1796ErrorCode = $null
    $event1800Count = 0
    $rebootPending = $false
    $event1802Count = 0
    $knownIssueId = $null
    $event1803Count = 0
    $missingKEK = $false
    Write-Log -Message "Latest Event ID: Error" -Level Error
    Write-Log -Message "Bucket ID: Error" -Level Error
    Write-Log -Message "Confidence: Error"-Level Error
    Write-Log -Message "Event 1801 Count: 0"
    Write-Log -Message "Event 1808 Count: 0"
}

# WMI/CIM Queries (5 values)

# 26. OSVersion
# PS Version: 3.0+ (use Get-WmiObject for 2.0) | Admin: No | System Requirements: None
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    if ($null -eq $osInfo -or [string]::IsNullOrEmpty($osInfo.Version)) {
        Write-Log -Message "Could not retrieve OS version" -Level Warn
        $osVersion = "Unknown"
    } else {
        $osVersion = $osInfo.Version
    }
    Write-Log -Message -Message "OS Version: $osVersion"
} catch {
    # CIM may fail in some environments - use fallback
    $osVersion = [System.Environment]::OSVersion.Version.ToString()
    if ([string]::IsNullOrEmpty($osVersion)) { $osVersion = "Unknown" }
    Write-Log -Message "OS Version: $osVersion"
}

# 27. LastBootTime
# PS Version: 3.0+ (use Get-WmiObject for 2.0) | Admin: No | System Requirements: None
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    if ($null -eq $osInfo -or $null -eq $osInfo.LastBootUpTime) {
        Write-Log -Message "Could not retrieve last boot time" -Level Warn
        $lastBootTime = $null
        Write-Log -Message "Last Boot Time: Not Available"
    } else {
        $lastBootTime = $osInfo.LastBootUpTime
        Write-Log -Message "Last Boot Time: $lastBootTime"
    }
} catch {
    # CIM may fail in some environments - use fallback
    try {
        $lastBootTime = (Get-Process -Id 0 -ErrorAction SilentlyContinue).StartTime
    } catch {
        $lastBootTime = $null
    }
    if ($lastBootTime) { Write-Log -Message "Last Boot Time: $lastBootTime" } else { Write-Log -Message "Last Boot Time: Not Available" }
}

# 28. BaseBoardManufacturer
# PS Version: 3.0+ (use Get-WmiObject for 2.0) | Admin: No | System Requirements: None
try {
    $baseBoard = Get-CimInstance Win32_BaseBoard -ErrorAction Stop
    if ($null -eq $baseBoard -or [string]::IsNullOrEmpty($baseBoard.Manufacturer)) {
        Write-Log -Message "Could not retrieve baseboard manufacturer" -Level Warn
        $baseBoardManufacturer = "Unknown"
    } else {
        $baseBoardManufacturer = $baseBoard.Manufacturer
    }
    Write-Log -Message "Baseboard Manufacturer: $baseBoardManufacturer"
} catch {
    # CIM may fail - baseboard info is supplementary
    $baseBoardManufacturer = "Unknown"
    Write-Log -Message "Baseboard Manufacturer: $baseBoardManufacturer"
}

# 29. BaseBoardProduct
# PS Version: 3.0+ (use Get-WmiObject for 2.0) | Admin: No | System Requirements: None
try {
    $baseBoard = Get-CimInstance Win32_BaseBoard -ErrorAction Stop
    if ($null -eq $baseBoard -or [string]::IsNullOrEmpty($baseBoard.Product)) {
        Write-Log -Message "Could not retrieve baseboard product" -Level Warn
        $baseBoardProduct = "Unknown"
    } else {
        $baseBoardProduct = $baseBoard.Product
    }
    Write-Log -Message "Baseboard Product: $baseBoardProduct"
} catch {
    # CIM may fail - baseboard info is supplementary
    $baseBoardProduct = "Unknown"
    Write-Log -Message "Baseboard Product: $baseBoardProduct"
}

# 30. SecureBootTaskEnabled
# PS Version: All | Admin: No | System Requirements: Scheduled Task exists
# Checks if the Secure-Boot-Update scheduled task is enabled
$secureBootTaskEnabled = $null
$secureBootTaskStatus = "Unknown"
try {
    $taskOutput = schtasks.exe /Query /TN "\Microsoft\Windows\PI\Secure-Boot-Update" /FO CSV 2>&1
    if ($LASTEXITCODE -eq 0) {
        $taskData = $taskOutput | ConvertFrom-Csv
        if ($taskData) {
            $secureBootTaskStatus = $taskData.Status
            $secureBootTaskEnabled = ($taskData.Status -eq 'Ready' -or $taskData.Status -eq 'Running')
        }
    } else {
        $secureBootTaskStatus = "NotFound"
        $secureBootTaskEnabled = $false
    }
    if ($secureBootTaskEnabled -eq $false) {
        Write-Log -Message "SecureBoot Update Task: $secureBootTaskStatus (Enabled: $secureBootTaskEnabled)" -Level Warn
    } else {
        Write-Log -Message "SecureBoot Update Task: $secureBootTaskStatus (Enabled: $secureBootTaskEnabled)"
    }
} catch {
    $secureBootTaskStatus = "Error"
    $secureBootTaskEnabled = $false
    Write-Log -Message "SecureBoot Update Task: Error checking - $_" -Level Error
}

# 31. WinCS Key Status (F33E0C8E002 - Secure Boot Certificate Update)
# PS Version: All | Admin: Yes (for query) | System Requirements: WinCsFlags.exe
$wincsKeyApplied = $null
$wincsKeyStatus = "Unknown"
try {
    # Check common locations for WinCsFlags.exe
    $wincsFlagsPath = $null
    $possiblePaths = @(
        "$env:SystemRoot\System32\WinCsFlags.exe",
        "$env:SystemRoot\SysWOW64\WinCsFlags.exe"
    )
    foreach ($p in $possiblePaths) {
        if (Test-Path $p) { $wincsFlagsPath = $p; break }
    }
    
    if ($wincsFlagsPath) {
        # Query specific key - requires admin rights
        $queryOutput = & $wincsFlagsPath /query --key F33E0C8E002 2>&1
        $queryOutputStr = $queryOutput -join "`n"
        
        if ($LASTEXITCODE -eq 0) {
            # Check if key is applied (look for "Active Configuration" or similar indicator)
            if ($queryOutputStr -match "Active Configuration.*:.*enabled" -or $queryOutputStr -match "Configuration.*applied") {
                $wincsKeyApplied = $true
                $wincsKeyStatus = "Applied"
                Write-Log -Message "WinCS Key F33E0C8E002: Applied"
            } elseif ($queryOutputStr -match "not found|No configuration") {
                $wincsKeyApplied = $false
                $wincsKeyStatus = "NotApplied"
                Write-Log -Message "WinCS Key F33E0C8E002: Not Applied" -Level Warn
            } else {
                # Key exists - check output for state
                $wincsKeyApplied = $true
                $wincsKeyStatus = "Applied"
                Write-Log -Message "WinCS Key F33E0C8E002: Applied"
            }
        } else {
            # Check for specific error messages
            if ($queryOutputStr -match "Access denied|administrator") {
                $wincsKeyStatus = "AccessDenied"
                Write-Log -Message "WinCS Key F33E0C8E002: Access denied (run as admin)" -Level Error
            } elseif ($queryOutputStr -match "not found|No configuration") {
                $wincsKeyApplied = $false
                $wincsKeyStatus = "NotApplied"
                Write-Log -Message "WinCS Key F33E0C8E002: Not Applied" -Level Warn
            } else {
                $wincsKeyStatus = "QueryFailed"
                Write-Log -Message "WinCS Key F33E0C8E002: Query failed" -Level Error
            }
        }
    } else {
        $wincsKeyStatus = "WinCsFlagsNotFound"
        Write-Log -Message "WinCS Key F33E0C8E002: WinCsFlags.exe not found" -Level Error
    }
} catch {
    $wincsKeyStatus = "Error"
    Write-Log -Message "WinCS Key F33E0C8E002: Error checking - $_" -Level Error
}

# =============================================================================
# Remediation Detection - Status Output & Exit Code
# =============================================================================

# Build status object from all collected inventory data
$status = [ordered]@{
    UEFICA2023Status           = $uefica2023Status
    UEFICA2023Error            = $uefica2023Error
    UEFICA2023ErrorEvent       = $uefica2023ErrorEvent
    AvailableUpdates           = if ($null -ne $availableUpdates) { $availableUpdatesHex } else { $null }
    AvailableUpdatesPolicy     = if ($null -ne $availableUpdatesPolicy) { $availableUpdatesPolicyHex } else { $null }
    Hostname                   = $hostname
    CollectionTime             = if ($collectionTime -is [datetime]) { $collectionTime.ToString("o") } else { "$collectionTime" }
    SecureBootEnabled          = $secureBootEnabled
    HighConfidenceOptOut       = $highConfidenceOptOut
    MicrosoftUpdateManagedOptIn        = $microsoftUpdateManagedOptIn
    OEMManufacturerName        = $oemManufacturerName
    OEMModelSystemFamily       = $oemModelSystemFamily
    OEMModelNumber             = $oemModelNumber
    FirmwareVersion            = $firmwareVersion
    FirmwareReleaseDate        = $firmwareReleaseDate
    OSArchitecture             = $osArchitecture
    CanAttemptUpdateAfter      = if ($canAttemptUpdateAfter -is [datetime]) { $canAttemptUpdateAfter.ToString("o") } else { "$canAttemptUpdateAfter" }
    LatestEventId              = $latestEventId
    BucketId                   = $bucketId
    Confidence                 = $confidence
    SkipReasonKnownIssue       = $skipReasonKnownIssue  # KI_<number> from SkipReason in BucketId event
    Event1801Count             = $event1801Count
    Event1808Count             = $event1808Count
    # Error events with captured details
    Event1795Count             = $event1795Count          # Firmware returned error
    Event1795ErrorCode         = $event1795ErrorCode      # Error code from firmware
    Event1796Count             = $event1796Count          # Error code logged
    Event1796ErrorCode         = $event1796ErrorCode      # Captured error code
    Event1800Count             = $event1800Count          # Reboot needed (NOT an error)
    RebootPending              = $rebootPending           # True if Event 1800 present
    Event1802Count             = $event1802Count          # Known firmware issue
    KnownIssueId               = $knownIssueId            # KI_<number> from SkipReason
    Event1803Count             = $event1803Count          # Missing KEK update
    MissingKEK                 = $missingKEK              # OEM needs to supply PK signed KEK
    OSVersion                  = $osVersion
    LastBootTime               = if ($lastBootTime -is [datetime]) { $lastBootTime.ToString("o") } else { "$lastBootTime" }
    BaseBoardManufacturer      = $baseBoardManufacturer
    BaseBoardProduct           = $baseBoardProduct
    SecureBootTaskEnabled      = $secureBootTaskEnabled
    SecureBootTaskStatus       = $secureBootTaskStatus
    WinCSKeyApplied            = $wincsKeyApplied         # True if F33E0C8E002 key is applied
    WinCSKeyStatus             = $wincsKeyStatus          # Applied, NotApplied, WinCsFlagsNotFound, etc.
}

If ($Status)
{
    $Namespace   = 'root\cimv2'
    $ClassName   = 'SecureBootUpdateData'
    $KeyPropName = 'Hostname'

    Write-Log -Message "Creating WMI Class $ClassName to store the collected data."

    # --- Ensure Hostname key is set (OrderedDictionary-safe) ---
    if (-not ($status.Keys -contains $KeyPropName) -or [string]::IsNullOrWhiteSpace($status[$KeyPropName])) {
        $status[$KeyPropName] = $env:COMPUTERNAME
    }
    $hostname = [string]$status[$KeyPropName]

    # --- Ensure class exists ---
    Ensure-WmiClass -Namespace $Namespace -ClassName $ClassName -Status $status -KeyPropName $KeyPropName

    # --- Build schema-typed args (your existing helpers) ---
    $schemaMap = Get-WmiClassSchemaMap -Namespace $Namespace -ClassName $ClassName
    $wmiArgs   = Build-WmiArguments -Status $status -SchemaMap $schemaMap -KeyPropName $KeyPropName

    # --- Upsert instance (NO Set-WmiInstance PutType) ---
    $filter   = "Hostname='{0}'" -f ($hostname -replace "'","''")
    $existing = Get-CimInstance -Namespace $Namespace -ClassName $ClassName -Filter $filter -ErrorAction SilentlyContinue

    if ($null -eq $existing) {
        # Create instance with key only (always safe)
        New-CimInstance -Namespace $Namespace -ClassName $ClassName `
            -Property @{ $KeyPropName = $hostname } -ErrorAction Stop | Out-Null

        # Refresh instance object
        $existing = Get-CimInstance -Namespace $Namespace -ClassName $ClassName -Filter $filter -ErrorAction Stop
    }

    # Update using schema-typed args
    $existing | Set-CimInstance -Property $wmiArgs -ErrorAction Stop | Out-Null
}
else
{
   Write-Log -Message "There was no data to store." -Level Error 
}

Write-Log -Message "**********************************************************************************"