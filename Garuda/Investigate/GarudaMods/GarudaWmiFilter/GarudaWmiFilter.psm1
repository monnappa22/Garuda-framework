function View-WmiFilterSummary {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $WmiFilterEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 19) {
            $WmiFilterEvents += $Event
        }
    }
    end {
        $WmiFilterEvents | select-object UtcTime, Name, EventNamespace, Query, `
            @{Name = "WmiFilterInfo"; Expression = { "{0} by {1}" -f $_.Operation, $_.User } } `
        | sort-object WmiFilterInfo | Format-Table UtcTime, Name, EventNamespace, Query -GroupBy WmiFilterInfo -Autosize -Wrap `
        | Out-String -stream | ForEach-Object {
            if ($_ -match "WmiFilterInfo:.*") {
                write-host $_ -ForegroundColor green
            }
            else {
                write-host $_
            }
        }
    }
}

function View-WmiFilterInteractiveTable {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $WmiFilterEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 19) {
            $WmiFilterEvents += $Event
        }
    }
    end {
        $WmiFilterEvents | Select-Object UTCtime,
            @{Name="Event"; Expression={ "WMI Filter $($_.Operation) (19)" }},
            @{Name="EventDetails"; Expression={ "Name: $($_.Name) | EventNamespace: $($_.EventNamespace) | Query: $($_.Query)" }},
            # Event identification
            EventId, 
            EventType,
            # Host and user information
            HostName,
            User,
            # WMI Filter specific fields
            Operation,
            Name,
            EventNamespace,
            Query,
            # Time-related fields
            TimeCreated |
            Out-GridView -Title "WMI Filter Information"
    }
}

function View-WmiFilterTimeline {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $WmiFilterEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 19) {
            $WmiFilterEvents += $Event
        }
    }
    End {
        $WmiFilterEvents | Select-Object `
            UTCtime,
            @{Name="User"; Expression={ $_.User }},
            @{Name="Event"; Expression={ "WMI Filter $($_.Operation) (19)" }},
            @{Name="EventDetails"; Expression={ "Name: $($_.Name) | EventNamespace: $($_.EventNamespace) | Query: $($_.Query)" }} | 
            Sort-Object UTCtime | Format-Table -AutoSize -Wrap
    }
}

function View-WmiFilterTimelineList {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $WmiFilterEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 19) {
            $WmiFilterEvents += $Event
        }
    }
    End {
        $WmiFilterEvents | Select-Object `
            UTCtime,
            HostName,
            User,
            @{Name="Event"; Expression={ "WMI Filter $($_.Operation) (19)" }},
            @{Name="EventDetails"; Expression={ "Name: $($_.Name) | EventNamespace: $($_.EventNamespace) | Query: $($_.Query)" }} | 
            Sort-Object UTCtime | Format-List
    }
}

function Investigate-WmiFilterInfo {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [parameter(Mandatory = $false)]
        [string] $Operation = $false,

        [parameter(Mandatory = $false)]
        [string] $User = $false,

        [parameter(Mandatory = $false)]
        [string] $EventNamespace = $false,

        [parameter(Mandatory = $false)]
        [string] $Name = $false,

        [parameter(Mandatory = $false)]
        [string] $Query = $false,

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

    # Build parameter hashtable for Get-SysmonRawEvents
    if ($null -eq $LogFile) {
        $Parameters = @{
            EventId = 19  # Only get WmiEventFilter events
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
            EventId = 19  # Only get WmiEventFilter events
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

    if ($Operation -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Operation -like $Operation}
    }

    if ($User -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.User -like $User}
    }

    if ($EventNamespace -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.EventNamespace -like $EventNamespace}
    }

    if ($Name -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Name -like $Name}
    }

    if ($Query -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Query -like $Query}
    }

    if ($UtcTime -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.UtcTime -like $UtcTime}
    }

    if ($HostName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.HostName -like $HostName}
    }

    $NewQuery = $BaseQuery
    
    switch ($View) {
        "Detailed" { 
            $NewQuery
            break
        }
        "Summary" {
            $NewQuery | View-WmiFilterSummary
            break
        }
        "InteractiveTable" {
            $NewQuery | View-WmiFilterInteractiveTable
            break
        }
        "Timeline" {
            $NewQuery | View-WmiFilterTimeline
            break
        }
        "TimelineList" {
            $NewQuery | View-WmiFilterTimelineList
            break
        }
    }
}

Export-ModuleMember -Function View-WmiFilterSummary, 
                             View-WmiFilterInteractiveTable, View-WmiFilterTimeline,
                             View-WmiFilterTimelineList, Investigate-WmiFilterInfo 