function View-RawAccessTimeline {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $RawAccessEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 9) {
            $RawAccessEvents += $Event
        }
    }
    End {
        $RawAccessEvents | Select-Object `
            UTCtime,
            @{Name="GUID"; Expression={$_.ProcessGuid}},
            @{Name="Process"; Expression={ "$($_.ProcessName)($($_.ProcessId))" }},
            @{Name="Event"; Expression={ "Raw Access (9)" }},
            @{Name="EventDetails"; Expression={ "Device: $($_.Device)" }} | 
            Sort-Object UTCtime | Format-Table -AutoSize -Wrap
    }
}

function View-RawAccessTimelineList {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $RawAccessEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 9) {
            $RawAccessEvents += $Event
        }
    }
    End {
        $RawAccessEvents | Select-Object `
            UTCtime,
            HostName,
            User,
            @{Name="Process"; Expression={ "Image: $($_.Image) | ProcessId: $($_.ProcessId) | ProcessGuid: $($_.ProcessGuid)" }},
            @{Name="Event"; Expression={ "Raw Access (9)" }},
            @{Name="EventDetails"; Expression={ "Device: $($_.Device)" }} |
            Sort-Object UTCtime
    }
}

function View-RawAccessSummary {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $RawAccessEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 9) {
            $RawAccessEvents += $Event
        }
    }
    End {
        $RawAccessEvents | Select-Object @{
            Name = "ProcessInfo"
            Expression = { "Image: $($_.Image) | ProcessId: $($_.ProcessId) | ProcessGuid: $($_.ProcessGuid)" }
        }, UTCtime, @{
            Name = "Event"
            Expression = { "Raw Access (9)" }
        }, @{
            Name = "EventDetails"
            Expression = { "Device: $($_.Device)" }
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

function View-RawAccessInteractiveTable {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $RawAccessEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 9) {
            $RawAccessEvents += $Event
        }
    }
    End {
        $RawAccessEvents | Select-Object UTCtime,
            @{Name="GUID"; Expression={ $_.ProcessGuid }},
            @{Name="Process"; Expression={ "Image: $($_.Image) | ProcessId: $($_.ProcessId) | ProcessGuid: $($_.ProcessGuid)" }},
            @{Name="Event"; Expression={ "Raw Access Read (9)" }},
            @{Name="EventDetails"; Expression={ "Device: $($_.Device)" }},
            HostName,
            EventId,
            EventType,
            ProcessGuid,
            ProcessId,
            Image,
            Device,
            User,
            ProcessName,
            ProcessDir,
            TimeCreated |
            Out-GridView -Title "Raw Access Read Information"
    }
}

function Investigate-RawAccessInfo {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [parameter(Mandatory = $false)]
        [string] $ProcessName = $false,

        [parameter(Mandatory = $false)]
        [string] $ProcessId = $false,

        [parameter(Mandatory = $false)]
        [string] $ProcessGuid = $false,

        [parameter(Mandatory = $false)]
        [string] $Device = $false,

        [parameter(Mandatory = $false)]
        [string] $Image = $false,

        [parameter(Mandatory = $false)]
        [string] $User = $false,

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
        [ValidateSet("Detailed", "Timeline", "TimelineList", "Summary", "InteractiveTable")]
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
            EventId = 9
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
            EventId = 9
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

    if ($ProcessName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.ProcessName -like $ProcessName}
    }

    if ($ProcessId -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.ProcessId -like $ProcessId}
    }

    if ($ProcessGuid -ne $false) {
        $TrimProcGuid = $ProcessGuid.tostring().trimstart("{").trimend("}")
        $ProcessGuid = "{0}{1}{2}" -f '{', $TrimProcGuid, '}'
        $BaseQuery = $BaseQuery | Where-Object {$_.ProcessGuid -eq $ProcessGuid.ToString()}
    }

    if ($Device -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Device -like $Device}
    }

    if ($Image -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Image -like $Image}
    }

    if ($User -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.User -like $User}
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
        "Timeline" {
            $Query | View-RawAccessTimeline
            break
        }
        "TimelineList" {
            $Query | View-RawAccessTimelineList
            break
        }
        "Summary" {
            $Query | View-RawAccessSummary
            break
        }
        "InteractiveTable" {
            $Query | View-RawAccessInteractiveTable
            break
        }
    }
}

Export-ModuleMember -Function View-RawAccessTimeline, View-RawAccessTimelineList, View-RawAccessSummary, 
                             View-RawAccessInteractiveTable, Investigate-RawAccessInfo 