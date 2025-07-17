Function View-DriverTimeline {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $DriverEvents = @() 
    }
    Process {
        if ($Event.EventId -eq 6) {
            $DriverEvents += $Event
        }
    }
    End {
        $DriverEvents | Select-Object `
            UTCtime,
            @{Name="GUID"; Expression={"-"}},
            @{Name="Process"; Expression={"-"}},
            @{Name="Event"; Expression={"Driver Load (6)"}},
            @{Name="EventDetails"; Expression={
                if ($_.Signed) {
                    "ImageLoaded: $($_.ImageLoaded) | Signed: $($_.Signed) | Status: $($_.SignatureStatus) | Signature: $($_.Signature)"
                } else {
                    "ImageLoaded: $($_.ImageLoaded)"
                }
            }} | 
            Sort-Object UTCtime | Format-Table -AutoSize -Wrap
    }
}

Function View-DriverTimelineList {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $DriverEvents = @() 
    }
    Process {
        if ($Event.EventId -eq 6) {
            $DriverEvents += $Event
        }
    }
    End {
        $DriverEvents | Select-Object `
            'UTCtime',
            'HostName',
            @{Name="Event"; Expression={"Driver Load (6)"}},
            @{Name="EventDetails"; Expression={
                if ($_.Signed) {
                    "ImageLoaded: $($_.ImageLoaded) | Signed: $($_.Signed) | Status: $($_.SignatureStatus) | Signature: $($_.Signature)"
                } else {
                    "ImageLoaded: $($_.ImageLoaded)"
                }
            }} |
            Sort-Object UTCtime
    }
}

function View-DriverSummary {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $DriverEvents = @() 
    }
    Process {
        if ($Event.EventId -eq 6) {
            $DriverEvents += $Event
        }
    }
    End {
        if ($DriverEvents.Count -gt 0) {
            $DriverEvents | Select-Object @{
                Name = "DriverInfo"
                Expression = { "DriverName: $($_.DriverName) | DriverDir: $($_.DriverDir)" }
            }, UTCtime, @{
                Name = "Event"
                Expression = { "Driver Load (6)" }
            }, @{
                Name = "EventDetails"
                Expression = { 
                    if ($_.Signed) {
                        "ImageLoaded: $($_.ImageLoaded) | Signed: $($_.Signed) | Status: $($_.SignatureStatus) | Signature: $($_.Signature)"
                    } else {
                        "ImageLoaded: $($_.ImageLoaded)"
                    }
                }
            } | Sort-Object DriverInfo, UTCtime | 
            Format-Table UTCtime, Event, EventDetails -GroupBy DriverInfo -AutoSize -Wrap |
            Out-String -stream | ForEach-Object {
                if ($_ -match "DriverInfo:.*") {
                write-host $_ -ForegroundColor green
            }
            else {
                write-host $_
                }
            }
        }
    }
}

function View-DriverInteractiveTable {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $DriverEvents = @() 
    }
    Process {
        if ($Event.EventId -eq 6) {
            $DriverEvents += $Event
        }
    }
    end {
        # Create a view with the standard first 5 fields, then Event ID 6 specific fields
        $DriverEvents | Select-Object UTCtime,
            @{Name="GUID"; Expression={ "" }},
            @{Name="Process"; Expression={ "" }},
            @{Name="Event"; Expression={ "Driver Load (6)" }},
            @{Name="EventDetails"; Expression={ 
                if ($_.Signed) {
                    "ImageLoaded: $($_.ImageLoaded) | Signed: $($_.Signed) | Status: $($_.SignatureStatus) | Signature: $($_.Signature)"
                } else {
                    "ImageLoaded: $($_.ImageLoaded)"
                }
            }},
            HostName,
            EventId,
            EventType,
            ImageLoaded,
            Hashes,
            Signed,
            Signature,
            SignatureStatus,
            MD5,
            SHA256,
            SHA1,
            IMPHASH,
            DriverName,
            DriverDir,
            TimeCreated |
            Out-GridView -Title "Driver Load Information"
    }
}

function View-DriverSignature {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event,
        [parameter(Mandatory = $false, Position = 0)]
        [string] $DriverPath = $false
    )
    Begin {
        $DriverEvents = @()
    }
    process {
        if ($Event.EventId -eq 6) {
            if ($DriverPath -eq $false) {
                $DriverEvents += $Event
            }
            else {
                $DriverEvents += $Event | where-object { $_.ImageLoaded -eq $DriverPath }
            }
        }
    }
    end {
        $DriverEvents | Select-Object Signed, Signature, SignatureStatus, ImageLoaded, `
        @{Name="Driver"; Expression = {"{0}"-f $_.DriverName}} | sort-object Driver `
        | format-list Signed, Signature, SignatureStatus, ImageLoaded -GroupBy Driver | Out-String -stream `
        | ForEach-Object {
            if ($_ -match "Driver:.*") {
                write-host $_ -ForegroundColor Cyan
            }
            else {
                write-host $_
            }
        }
    }
} 

Function View-DriverHashes {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event,
        [parameter(Mandatory = $false)]
        [string] $MD5 = $false,
        [parameter(Mandatory = $false)]
        [string] $SHA256 = $false,
        [parameter(Mandatory = $false)]
        [string] $IMPHASH = $false
    )
    Begin {
        $DriverEvents = @()
    }
    Process {
        If ($Event.EventId -eq 6) {
            if ($MD5 -ne $false) {
                $DriverEvents += $Event | where-object { $_.MD5 -eq $MD5 }
            }
            elseif ($SHA256 -ne $false) {
                $DriverEvents += $Event | where-object { $_.SHA256 -eq $SHA256 }
            }
            elseif ($IMPHASH -ne $false) {
                $DriverEvents += $Event | where-object { $_.IMPHASH -eq $IMPHASH }
            }
            else {
                $DriverEvents += $Event
            }
        }
    }
    end {
        $DriverEvents | Select-Object MD5, SHA256, IMPHASH, Hashes, ImageLoaded, `
        @{Name="Driver"; Expression = {"{0}"-f $_.DriverName}} | Sort-Object Driver `
        | Format-List MD5, SHA256, IMPHASH, Hashes, ImageLoaded -GroupBy Driver | Out-String -stream `
        | ForEach-Object {
            if ($_ -match "Driver:.*") {
                write-host $_ -ForegroundColor Cyan
            }
            else {
                write-host $_
            }
        }
    }
}

function Investigate-DriverInfo {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [parameter(Mandatory = $false)]
        [string] $DriverName = $false,

        [parameter(Mandatory = $false)]
        [string] $ImageLoaded = $false,

        [parameter(Mandatory = $false)]
        [string] $Signature = $false,

        [parameter(Mandatory = $false)]
        [string] $SignatureStatus = $false,

        [parameter(Mandatory = $false)]
        [string] $Signed = $false,

        [parameter(Mandatory = $false)]
        [string] $UtcTime = $false,

        [parameter(Mandatory = $false)]
        [string] $HostName = $false,

        [parameter(Mandatory = $false)]
        [int] $PastSeconds = 0,

        [parameter(Mandatory = $false)]
        [int] $PastMinutes = 0,
        
        [parameter(Mandatory = $false)]
        [int] $PastHours = 0,

        [parameter(Mandatory = $false)]
        [int] $PastDays = 0,

        [parameter(Mandatory = $false)]
        [datetime] $FromLocalTime,

        [parameter(Mandatory = $false)]
        [datetime] $ToLocalTime,

        [parameter(Mandatory = $false)]
        [datetime] $FromUtcTime,

        [parameter(Mandatory = $false)]
        [datetime] $ToUtcTime,

        [parameter(Mandatory = $false, ParameterSetName="EventLogs")]
        [string] $ComputerName = $Env:COMPUTERNAME,

        [parameter(Mandatory = $false, ParameterSetName="EventLogs")]
        [pscredential] $Credential,

        [parameter(Mandatory = $true, ParameterSetName="LogFile")]
        [string[]] $LogFile,

        [parameter(Mandatory = $false)]
        [string] $Hashes = $false,

        [parameter(Mandatory = $false)]
        [string] $MD5 = $false,

        [parameter(Mandatory = $false)]
        [string] $SHA256 = $false,

        [parameter(Mandatory = $false)]
        [string] $SHA1 = $false,

        [parameter(Mandatory = $false)]
        [string] $IMPHASH = $false,

        [parameter(Mandatory = $false)]
        [string] $DriverDir = $false,

        [parameter(Mandatory = $false)]
        [ValidateSet("Detailed", "Timeline", "TimelineList", "Summary", "InteractiveTable", "Signature", "Hashes")]
        [string] $View = "Detailed"
    )

    # Check if mixing Local and UTC time parameters
    if (($FromLocalTime -ne $null -and $FromUtcTime -ne $null) -or
        ($ToLocalTime -ne $null -and $ToUtcTime -ne $null) -or
        ($FromLocalTime -ne $null -and $ToUtcTime -ne $null) -or
        ($FromUtcTime -ne $null -and $ToLocalTime -ne $null)) {
        Write-Error "Cannot mix LocalTime and UtcTime parameters. Please use either LocalTime or UtcTime format consistently."
        return
    }

    if ($null -eq $LogFile) {
        $Parameters = @{
            EventId = 6
            PastSeconds = $PastSeconds
            PastMinutes = $PastMinutes
            PastHours = $PastHours
            PastDays = $PastDays
            ComputerName = $ComputerName
        }

        if ($Credential) {
            $Parameters.Credential = $Credential
        }

        # Add LocalTime/UTCTime parameters if specified
        if ($FromLocalTime) {
            $Parameters.FromLocalTime = $FromLocalTime
            $Parameters.ToLocalTime = $ToLocalTime
        }
        elseif ($FromUtcTime) {
            $Parameters.FromUtcTime = $FromUtcTime
            $Parameters.ToUtcTime = $ToUtcTime
        }
    }
    else {
        $Parameters = @{
            EventId = 6
            LogFile = $LogFile
            PastSeconds = $PastSeconds
            PastMinutes = $PastMinutes
            PastHours = $PastHours
            PastDays = $PastDays
        }
    }

    $BaseQuery = Get-SysmonRawEvents @Parameters | ConvertTo-GarudaObjects
    
    if ($DriverName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.DriverName -like $DriverName}
    }

    if ($ImageLoaded -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.ImageLoaded -like $ImageLoaded}
    }

    if ($Signature -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Signature -like $Signature}
    }

    if ($SignatureStatus -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.SignatureStatus -like $SignatureStatus}
    }

    if ($Signed -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Signed -like $Signed}
    }

    if ($UtcTime -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.UtcTime -like $UtcTime}
    }

    if ($HostName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.HostName -like $HostName}
    }

    if ($Hashes -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Hashes -like $Hashes}
    }

    if ($MD5 -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.MD5 -like $MD5}
    }

    if ($SHA256 -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.SHA256 -like $SHA256}
    }

    if ($SHA1 -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.SHA1 -like $SHA1}
    }

    if ($IMPHASH -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.IMPHASH -like $IMPHASH}
    }

    if ($DriverDir -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.DriverDir -like $DriverDir}
    }

    $Query = $BaseQuery
    
    # Displaying results based on the chosen views
    switch ($View) {
        "Detailed" { 
            $Query
            break
        }
        "Timeline" {
            $Query | View-DriverTimeline
            break
        }
        "TimelineList" {
            $Query | View-DriverTimelineList
            break
        }
        "Summary" {
            $Query | View-DriverSummary
            break
        }
        "InteractiveTable" {
            $Query | View-DriverInteractiveTable
            break
        }
        "Signature" {
            $Query | View-DriverSignature
            break
        }
        "Hashes" {
            $Query | View-DriverHashes
            break
        }
    }
}

# Export the functions
Export-ModuleMember -Function View-DriverTimeline, View-DriverTimelineList, View-DriverSummary, 
                             View-DriverInteractiveTable, View-DriverSignature, View-DriverHashes,
                             Investigate-DriverInfo
