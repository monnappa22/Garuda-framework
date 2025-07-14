function View-WmiConsumerSummary {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $WmiConsumerEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 20) {
            $WmiConsumerEvents += $Event
        }
    }
    end {
        $WmiConsumerEvents | select-object UtcTime, Name, Type, Destination, `
            @{Name = "WmiConsumerOperation"; Expression = { "{0} by {1}" -f $_.Operation, $_.User } } `
        | sort-object WmiConsumerOperation | Format-Table UtcTime, Name, Type, Destination -GroupBy WmiConsumerOperation -Autosize -Wrap `
        | Out-String -stream | ForEach-Object {
            if ($_ -match "WmiConsumerOperation:.*") {
                write-host $_ -ForegroundColor green
            }
            else {
                write-host $_
            }
        }
    }
}

function View-WmiConsumerInteractiveTable {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $WmiConsumerEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 20) {
            $WmiConsumerEvents += $Event
        }
    }
    end {
        $WmiConsumerEvents | Select-Object UTCtime,
            @{Name="Event"; Expression={ "WMI Consumer $($_.Operation) (20)" }},
            @{Name="EventDetails"; Expression={ "Consumer: $($_.Name) | Type: $($_.Type) | Destination: $($_.Destination)" }},
            # Event identification
            EventId, 
            EventType,
            # Host and user information
            HostName,
            User,
            # WMI Consumer specific fields
            Operation,
            Name,
            Type,
            Destination |
            Out-GridView -Title "WMI Consumer Information"
    }
}

function View-WmiConsumerTimeline {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $WmiConsumerEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 20) {
            $WmiConsumerEvents += $Event
        }
    }
    End {
        $WmiConsumerEvents | Select-Object `
            UTCtime,
            @{Name="User"; Expression={ $_.User }},
            @{Name="Event"; Expression={ "WMI Consumer $($_.Operation) (20)" }},
            @{Name="EventDetails"; Expression={ "Consumer: $($_.Name) | Type: $($_.Type) | Destination: $($_.Destination)" }} | 
            Sort-Object UTCtime | Format-Table -AutoSize -Wrap
    }
}

function View-WmiConsumerTimelineList {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $WmiConsumerEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 20) {
            $WmiConsumerEvents += $Event
        }
    }
    End {
        $WmiConsumerEvents | Select-Object `
            UTCtime,
            HostName,
            User,
            @{Name="Event"; Expression={ "WMI Consumer $($_.Operation) (20)" }},
            @{Name="EventDetails"; Expression={ "Consumer: `"$($_.Name)`" | Type: $($_.Type) | Destination: `"$($_.Destination)`"" }} | 
            Sort-Object UTCtime | Format-List
    }
}

function Investigate-WmiConsumerInfo {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [parameter(Mandatory = $false)]
        [string] $Operation = $false,

        [parameter(Mandatory = $false)]
        [string] $User = $false,

        [parameter(Mandatory = $false)]
        [string] $Name = $false,

        [parameter(Mandatory = $false)]
        [string] $Type = $false,

        [parameter(Mandatory = $false)]
        [string] $Destination = $false,

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
            EventId = 20  # Only get WMI Consumer events
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
            EventId = 20  # Only get WMI Consumer events
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

    if ($Name -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Name -like $Name}
    }

    if ($Type -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Type -like $Type}
    }

    if ($Destination -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Destination -like $Destination}
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
            $NewQuery | View-WmiConsumerSummary
            break
        }
        "InteractiveTable" {
            $NewQuery | View-WmiConsumerInteractiveTable
            break
        }
        "Timeline" {
            $NewQuery | View-WmiConsumerTimeline
            break
        }
        "TimelineList" {
            $NewQuery | View-WmiConsumerTimelineList
            break
        }
    }
}

Export-ModuleMember -Function View-WmiConsumerSummary, 
                             View-WmiConsumerInteractiveTable, View-WmiConsumerTimeline,
                             View-WmiConsumerTimelineList, Investigate-WmiConsumerInfo 