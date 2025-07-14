function View-WmiBindingSummary {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $WmiBindingEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 21) {
            $WmiBindingEvents += $Event
        }
    }
    end {
        $WmiBindingEvents | select-object UtcTime, Consumer, Filter, `
            @{Name = "WmiBindingOperation"; Expression = { "{0} by {1}" -f $_.Operation, $_.User } } `
        | sort-object WmiBindingOperation | Format-Table UtcTime, Consumer, Filter -GroupBy WmiBindingOperation -Autosize -Wrap `
        | Out-String -stream | ForEach-Object {
            if ($_ -match "WmiBindingOperation:.*") {
                write-host $_ -ForegroundColor green
            }
            else {
                write-host $_
            }
        }
    }
}

function View-WmiBindingInteractiveTable {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $WmiBindingEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 21) {
            $WmiBindingEvents += $Event
        }
    }
    End {
        $WmiBindingEvents | Select-Object UTCtime,
            @{Name="Event"; Expression={ "WMI Binding $($_.Operation) (21)" }},
            @{Name="EventDetails"; Expression={ "Consumer: $($_.Consumer) | Filter: $($_.Filter)" }},
            # Event identification
            EventId,
            EventType,
            # Host and user information
            HostName,
            User,
            # WMI Binding specific fields
            Operation,
            Consumer,
            Filter | 
            Out-GridView -Title "WMI Binding Information"
    }
}

function View-WmiBindingTimeline {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $WmiBindingEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 21) {
            $WmiBindingEvents += $Event
        }
    }
    End {
        $WmiBindingEvents | Select-Object UTCtime,
            User,
            @{Name="Event"; Expression={ "WMI Binding $($_.Operation)" }},
            @{Name="EventDetails"; Expression={ "Consumer: $($_.Consumer) | Filter: $($_.Filter)" }} |
            Sort-Object UTCtime | Format-Table -AutoSize -Wrap
    }
}

function View-WmiBindingTimelineList {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $WmiBindingEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 21) {
            $WmiBindingEvents += $Event
        }
    }
    End {
        $WmiBindingEvents | Select-Object UTCtime,
            HostName,
            User,
            @{Name="Event"; Expression={ "WMI Binding $($_.Operation)" }},
            @{Name="EventDetails"; Expression={ "Consumer: $($_.Consumer) | Filter: $($_.Filter)" }} |
            Sort-Object UTCtime | Format-List
    }
}

function Investigate-WmiBindingInfo {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        # Time related parameters
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

        # Filter parameters
        [parameter(Mandatory = $false)]
        [string] $Operation = $false,

        [parameter(Mandatory = $false)]
        [string] $User = $false,

        [parameter(Mandatory = $false)]
        [string] $Consumer = $false,

        [parameter(Mandatory = $false)]
        [string] $Filter = $false,

        [parameter(Mandatory = $false)]
        [string] $UtcTime = $false,

        [parameter(Mandatory = $false)]
        [string] $HostName = $false,

        # Log source parameters
        [parameter(Mandatory = $false, ParameterSetName="EventLogs")]
        [string] $ComputerName = $Env:COMPUTERNAME,

        [parameter(Mandatory = $false, ParameterSetName="EventLogs")]
        [pscredential] $Credential,

        [parameter(Mandatory = $true, ParameterSetName="LogFile")]
        [string[]] $LogFile,

        # View parameters
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
            EventId = 21  # Only get WMI Binding events
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
            EventId = 21
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

    # Get base query from raw events
    $BaseQuery = Get-SysmonRawEvents @Parameters | ConvertTo-GarudaObjects

    # Apply filters if specified
    if ($Operation -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Operation -like $Operation}
    }
    if ($User -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.User -like $User}
    }
    if ($Consumer -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Consumer -like $Consumer}
    }
    if ($Filter -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Filter -like $Filter}
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
            $Query | View-WmiBindingSummary
            break
        }
        "InteractiveTable" {
            $Query | View-WmiBindingInteractiveTable
            break
        }
        "Timeline" {
            $Query | View-WmiBindingTimeline
            break
        }
        "TimelineList" {
            $Query | View-WmiBindingTimelineList
            break
        }
    }
}

Export-ModuleMember -Function View-WmiBindingSummary, 
                             View-WmiBindingInteractiveTable, View-WmiBindingTimeline,
                             View-WmiBindingTimelineList, Investigate-WmiBindingInfo
