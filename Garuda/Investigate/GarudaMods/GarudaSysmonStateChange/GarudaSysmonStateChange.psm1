function View-SysmonServiceStateChangeTimeline {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $SysmonServiceStateChangeEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 4) {
            $SysmonServiceStateChangeEvents += $Event
        }
    }
    End {
        $SysmonServiceStateChangeEvents | Select-Object `
            UTCtime,
            @{Name="GUID"; Expression={"-"}},
            @{Name="Process"; Expression={"-"}},
            @{Name="Event"; Expression={"Sysmon State (4)"}},
            @{Name="EventDetails"; Expression={"State: $($_.State) | Version: $($_.Version) | SchemaVersion: $($_.SchemaVersion)"}} | 
            Sort-Object UTCtime | Format-Table -AutoSize -Wrap
    }
}

function View-SysmonServiceStateChangeTimelineList {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $SysmonServiceStateChangeEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 4) {
            $SysmonServiceStateChangeEvents += $Event
        }
    }
    End {
        $SysmonServiceStateChangeEvents | Select-Object `
            'UTCtime',
            'HostName',
            @{Name="Event"; Expression={"Sysmon State (4)"}},
            @{Name="EventDetails"; Expression={"State: $($_.State) | Version: $($_.Version) | SchemaVersion: $($_.SchemaVersion)"}} |
            Sort-Object UTCtime
    }
}

function View-SysmonServiceStateChangeSummary {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $SysmonServiceStateChangeEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 4) {
            $SysmonServiceStateChangeEvents += $Event
        }
    }
    end {
        $SysmonServiceStateChangeEvents | select-object @{
            Name = "ProcessInfo"
            Expression = { "Sysmon Service State Change" }
        }, UTCtime, @{
            Name = "Event"
            Expression = { "Sysmon State (4)" }
        }, @{
            Name = "EventDetails"
            Expression = { "State: $($_.State) | Version: $($_.Version) | SchemaVersion: $($_.SchemaVersion)" }
        } | sort-object ProcessInfo, UTCtime | Format-Table UTCtime, Event, EventDetails -GroupBy ProcessInfo -Autosize -Wrap | Out-String -stream | ForEach-Object {
            if ($_ -match "ProcessInfo:.*") {
                write-host $_ -ForegroundColor green
            }
            else {
                write-host $_
            }
        }
    }
}

function View-SysmonServiceStateChangeInteractivetable {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $SysmonServiceStateChangeEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 4) {
            $SysmonServiceStateChangeEvents += $Event
        }
    }
    end {
        # Create a view with the standard first 5 fields, then Event ID 4 specific fields
        $SysmonServiceStateChangeEvents | Select-Object UTCtime,
            @{Name="GUID"; Expression={ "-" }},
            @{Name="Process"; Expression={ "-" }},
            @{Name="Event"; Expression={ "Sysmon State (4)" }},
            @{Name="EventDetails"; Expression={ "State: $($_.State) | Version: $($_.Version) | SchemaVersion: $($_.SchemaVersion)" }},
            # Event ID 4 specific fields
            HostName,
            EventId, 
            EventType,
            State, 
            Version, 
            SchemaVersion,
            TimeCreated |
            Out-GridView -Title "Sysmon Service State Change Information"
    }
}

function Investigate-SysmonServiceStateChange {
    [CmdletBinding(PositionalBinding = $false)]
    param (
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

        [parameter(Mandatory = $false)]
        [string] $UtcTime = $false,

        [parameter(Mandatory = $false)]
        [string] $HostName = $false,

        [parameter(Mandatory = $false, ParameterSetName="EventLogs")]
        [string] $ComputerName = $Env:COMPUTERNAME,

        [parameter(Mandatory = $false, ParameterSetName="EventLogs")]
        [pscredential] $Credential,

        [parameter(Mandatory = $true, ParameterSetName="LogFile")]
        [string[]] $LogFile,

        [parameter(Mandatory = $false)]
        [ValidateSet("Detailed","Timeline","TimelineList","Summary","InteractiveTable")]
        [string] $view = "Detailed"
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
            EventId = 4
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
            $Parameters.ToLocalTime = $ToLocalTime
        }
        elseif ($FromUtcTime) {
            $Parameters.FromUtcTime = $FromUtcTime
            $Parameters.ToUtcTime = $ToUtcTime
        }
    }
    else {
        $Parameters = @{
            EventId = 4
            LogFile = $LogFile
            PastSeconds = $PastSeconds
            PastMinutes = $PastMinutes
            PastHours = $PastHours
            PastDays = $PastDays
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

    $BaseQuery = Get-SysmonRawEvents @Parameters | ConvertTo-GarudaObjects

    if ($UtcTime -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.UtcTime -like $UtcTime}
    }

    if ($HostName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.HostName -like $HostName}
    }

    $Query = $BaseQuery

    # Displaying results based on the chosen views
    switch ($view) {
        "Detailed" { 
            $Query
            break
        }
        "Timeline" {
            $Query | View-SysmonServiceStateChangeTimeline
            break
        }
        "TimelineList" {
            $Query | View-SysmonServiceStateChangeTimelineList
            break
        }
        "Summary" {
            $Query | View-SysmonServiceStateChangeSummary
            break
        }
        "InteractiveTable" {
             $Query | View-SysmonServiceStateChangeInteractivetable
            break
        }
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Investigate-SysmonServiceStateChange',
    'View-SysmonServiceStateChangeTimeline',
    'View-SysmonServiceStateChangeTimelineList',
    'View-SysmonServiceStateChangeSummary',
    'View-SysmonServiceStateChangeInteractivetable'
)
