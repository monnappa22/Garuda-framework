function View-ProcTerminatedTimeline {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ProcTerminatedEvents = @() 
    }
    Process {
        if ($Event.EventId -eq 5) {
            $ProcTerminatedEvents += $Event
        }
    }
    End {
        $ProcTerminatedEvents | Select-Object `
            UTCtime,
            @{Name="GUID"; Expression={"-"}},
            @{Name="Process"; Expression={"-"}},
            @{Name="Event"; Expression={"Process Terminate (5)"}},
            @{Name="EventDetails"; Expression={"Image: $($_.Image) | ProcessId: $($_.ProcessId) | ProcessGuid: $($_.ProcessGuid)"}} | 
            Sort-Object UTCtime | Format-Table -AutoSize -Wrap
    }
}

function View-ProcTerminatedTimelineList {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ProcTerminatedEvents = @() 
    }
    Process {
        if ($Event.EventId -eq 5) {
            $ProcTerminatedEvents += $Event
        }
    }
    End {
        $ProcTerminatedEvents | Select-Object `
            'UTCtime',
            'HostName',
            @{Name="User"; Expression={$_.User}},
            @{Name="Process"; Expression={"-"}},
            @{Name="Event"; Expression={"Process Terminate (5)"}},
            @{Name="EventDetails"; Expression={"Image: $($_.Image) | ProcessId: $($_.ProcessId) | ProcessGuid: $($_.ProcessGuid)"}} |
            Sort-Object UTCtime
    }
}

function View-ProcTerminatedSummary {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ProcTerminatedEvents = @() 
    }
    Process {
        if ($Event.EventId -eq 5) {
            $ProcTerminatedEvents += $Event
        }
    }
    End {
        if ($ProcTerminatedEvents.Count -gt 0) {
            $ProcTerminatedEvents | Select-Object @{
                Name = "ProcessInfo"
                Expression = { "(-) - GUID: (-)" }
            }, UTCtime, @{
                Name = "Event"
                Expression = { "Process Terminate (5)" }
            }, @{
                Name = "EventDetails"
                Expression = { "Image: $($_.Image) | ProcessId: $($_.ProcessId) | ProcessGuid: $($_.ProcessGuid)" }
            } | Sort-Object ProcessInfo, UTCtime | 
            Format-Table UTCtime, Event, EventDetails -GroupBy ProcessInfo -AutoSize -Wrap |
            Out-String -stream | ForEach-Object {
                if ($_ -match "ProcessInfo:.*") {
                    write-host $_ -ForegroundColor green
                }
                else {
                    write-host $_
                }
            }
        }
    }
}

function View-ProcTerminatedInteractivetable {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ProcTerminatedEvents = @() 
    }
    Process {
        if ($Event.EventId -eq 5) {
            $ProcTerminatedEvents += $Event
        }
    }
    end {
        # Create a custom view with the standard first 5 fields, then Event ID 5 specific fields
        $ProcTerminatedEvents | Select-Object UTCtime,
            @{Name="GUID"; Expression={ "-" }},
            @{Name="Process"; Expression={ "-" }},
            @{Name="Event"; Expression={ "Process Terminate (5)" }},
            @{Name="EventDetails"; Expression={ "Image: $($_.Image) | ProcessId: $($_.ProcessId) | ProcessGuid: $($_.ProcessGuid)" }},
            # Event ID 5 specific fields
            HostName,
            EventId, 
            EventType,
            ProcessId, 
            ProcessGuid, 
            Image,
            ProcessName,
            User,
            ProcessDir,
            TimeCreated |
            Out-GridView -Title "Terminated Processes"
    }
}

function Investigate-ProcTerminated {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [parameter(Mandatory = $false, Position = 0)]
        [string] $ProcessGuid = $false,

        [parameter(Mandatory = $false)]
        [string] $ProcessName = $false,

        [parameter(Mandatory = $false)]
        [string] $Image= $false,

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
        [int] $ProcessId = $false,

        [parameter(Mandatory = $false)]
        [string] $User = $false,

        [parameter(Mandatory = $false)]
        [string] $ProcessDir = $false,

        [parameter(Mandatory = $false)]
        [ValidateSet("Detailed","Timeline","TimelineList","Summary","InteractiveTable")]
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
            EventId = 5
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
            EventId = 5
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

    if ($ProcessGuid -ne $false) {
        $TrimProcessGuid = $ProcessGuid.tostring().trimstart("{").trimend("}")
        $ProcessGuid = "{0}{1}{2}" -f '{', $TrimProcessGuid, '}'
        $BaseQuery = $BaseQuery | Where-Object {$_.ProcessGuid -eq $ProcessGuid.ToString()}
    }

    if ($ProcessName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.ProcessName -like $ProcessName}
    }

    if ($Image -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Image -like $Image}
    }

    if ($UtcTime -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.UtcTime -like $UtcTime}
    }

    if ($HostName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.HostName -like $HostName}
    }

    if ($ProcessId -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.ProcessId -eq $ProcessId}
    }

    if ($User -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.User -like $User}
    }

    if ($ProcessDir -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.ProcessDir -like $ProcessDir}
    }

    $Query = $BaseQuery

    switch ($View) {
        "Detailed" { 
            $Query
            break
        }
        "Timeline" {
            $Query | View-ProcTerminatedTimeline
            break
        }
        "TimelineList" {
            $Query | View-ProcTerminatedTimelineList
            break
        }
        "Summary" {
            $Query | View-ProcTerminatedSummary
            break
        }
        "InteractiveTable" {
            $Query | View-ProcTerminatedInteractivetable
            break
        }
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Investigate-ProcTerminated',
    'View-ProcTerminatedTimeline',
    'View-ProcTerminatedTimelineList',
    'View-ProcTerminatedSummary',
    'View-ProcTerminatedInteractivetable'
)
