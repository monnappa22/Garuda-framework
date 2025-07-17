function View-ServiceConfigSummary {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ServiceConfigEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 16) {
            $ServiceConfigEvents += $Event
        }
    }
    end {
        $ServiceConfigEvents | Select-Object @{
                Name = "ConfigInfo"
                Expression = { "Sysmon Service Configuration Change" }
            }, UTCtime, @{
                Name = "Event"
                Expression = { "Service Configuration Change (16)" }
            }, @{
                Name = "EventDetails"
                Expression = { "Configuration: $($_.Configuration) | ConfigurationFileHash: $($_.ConfigurationFileHash)" }
            } | Sort-Object ConfigInfo, UTCtime | 
            Format-Table UTCtime, Event, EventDetails -GroupBy ConfigInfo -AutoSize -Wrap |
            Out-String -stream | ForEach-Object {
                if ($_ -match "ConfigInfo:.*") {
                    write-host $_ -ForegroundColor green
                }
                else {
                    write-host $_
                }
            }
    }
}

function View-ServiceConfigInteractiveTable {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ServiceConfigEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 16) {
            $ServiceConfigEvents += $Event
        }
    }
    end {
        $ServiceConfigEvents | Select-Object UTCtime,
            @{Name="GUID"; Expression={ "" }},
            @{Name="Process"; Expression={ "" }},
            @{Name="Event"; Expression={ "Service Configuration Change (16)" }},
            @{Name="EventDetails"; Expression={ "Configuration: $($_.Configuration) | ConfigurationFileHash: $($_.ConfigurationFileHash)" }},
            # Event identification
            EventId,
            EventType,
            # Host information
            HostName,
            # Service Configuration specific fields
            Configuration,
            ConfigurationFileHash,
            # Time-related fields
            TimeCreated |
            Out-GridView -Title "Sysmon Service Configuration Changes"
    }
}

function View-ServiceConfigTimeline {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ServiceConfigEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 16) {
            $ServiceConfigEvents += $Event
        }
    }
    End {
        $ServiceConfigEvents | Select-Object `
            UTCtime,
            @{Name="GUID"; Expression={ "" }},
            @{Name="Process"; Expression={ "" }},
            @{Name="Event"; Expression={ "Service Configuration Change (16)" }},
            @{Name="EventDetails"; Expression={ "Configuration: $($_.Configuration) | ConfigurationFileHash: $($_.ConfigurationFileHash)" }} | 
            Sort-Object UTCtime | Format-Table -AutoSize -Wrap
    }
}

function View-ServiceConfigTimelineList {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ServiceConfigEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 16) {
            $ServiceConfigEvents += $Event
        }
    }
    End {
        $ServiceConfigEvents | Select-Object `
            UTCtime,
            HostName,
            @{Name="Event"; Expression={ "Service Configuration Change (16)" }},
            @{Name="EventDetails"; Expression={ "Configuration: $($_.Configuration) | ConfigurationFileHash: $($_.ConfigurationFileHash)" }} | 
            Sort-Object UTCtime
    }
}

function Investigate-ServiceConfigInfo {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [parameter(Mandatory = $false)]
        [string] $Configuration = $false,

        [parameter(Mandatory = $false)]
        [string] $ConfigurationFileHash = $false,

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
        [ValidateSet("Detailed", "Summary", "InteractiveTable", "Timeline", "TimelineList")]
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
            EventId = 16
            PastSeconds = $PastSeconds
            PastMinutes = $PastMinutes
            PastHours = $PastHours
            PastDays = $PastDays
            ComputerName = $ComputerName
            Credential = $Credential
        }

        # Add LocalTime/UTCTime parameters if specified
        if ($FromLocalTime) {
            $Parameters.FromLocalTime = $FromLocalTime
            if ($ToLocalTime) {
                $Parameters.ToLocalTime = $ToLocalTime
            }
            else {
                $Parameters.ToLocalTime = Get-Date
            }
        }
        elseif ($FromUtcTime) {
            $Parameters.FromUtcTime = $FromUtcTime
            if ($ToUtcTime) {
                $Parameters.ToUtcTime = $ToUtcTime
            }
            else {
                $Parameters.ToUtcTime = (Get-Date).ToUniversalTime()
            }
        }
    }
    else {
        $Parameters = @{
            EventId = 16
            LogFile = $LogFile
            PastSeconds = $PastSeconds
            PastMinutes = $PastMinutes
            PastHours = $PastHours
            PastDays = $PastDays
        }

        # Add LocalTime/UTCTime parameters if specified
        if ($FromLocalTime) {
            $Parameters.FromLocalTime = $FromLocalTime
            if ($ToLocalTime) {
                $Parameters.ToLocalTime = $ToLocalTime
            }
            else {
                $Parameters.ToLocalTime = Get-Date
            }
        }
        elseif ($FromUtcTime) {
            $Parameters.FromUtcTime = $FromUtcTime
            if ($ToUtcTime) {
                $Parameters.ToUtcTime = $ToUtcTime
            }
            else {
                $Parameters.ToUtcTime = (Get-Date).ToUniversalTime()
            }
        }
    }

    $BaseQuery = Get-SysmonRawEvents @Parameters | ConvertTo-GarudaObjects

    if ($Configuration -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Configuration -like $Configuration}
    }

    if ($ConfigurationFileHash -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.ConfigurationFileHash -like $ConfigurationFileHash}
    }

    if ($UtcTime -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.UtcTime -like $UtcTime}
    }

    if ($HostName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.HostName -like $HostName}
    }

    $Query = $BaseQuery
    
    switch ($View) {
        "Detailed" { 
            $Query
            break
        }
        "Summary" {
            $Query | View-ServiceConfigSummary
            break
        }
        "InteractiveTable" {
            $Query | View-ServiceConfigInteractiveTable
            break
        }
        "Timeline" {
            $Query | View-ServiceConfigTimeline
            break
        }
        "TimelineList" {
            $Query | View-ServiceConfigTimelineList
            break
        }
    }
}

Export-ModuleMember -Function View-ServiceConfigSummary, View-ServiceConfigInteractiveTable,
                             View-ServiceConfigTimeline, View-ServiceConfigTimelineList,
                             Investigate-ServiceConfigInfo 