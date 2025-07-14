function View-PipeCreateSummary {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $PipeEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 17) {
            $PipeEvents += $Event
        }
    }
    end {
        $PipeEvents | select-object PipeName, User, `
            @{Name = "Process"; Expression = { "{0} (PID: {1}) - {2}" -f $_.Image, $_.ProcessId, $_.ProcessGuid } } `
        | sort-object Process | Format-Table PipeName, User -GroupBy Process -Autosize -Wrap `
        | Out-String -stream | ForEach-Object {
            if ($_ -match "Process:.*") {
                write-host $_ -ForegroundColor green
            }
            else {
                write-host $_
            }
        }
    }
}

function View-PipeCreateInteractiveTable {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $PipeEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 17) {
            $PipeEvents += $Event
        }
    }
    end {
        $PipeEvents | Select-Object UTCtime,
            @{Name="GUID"; Expression={ $_.ProcessGuid }},
            @{Name="Process"; Expression={ $_.Image }},
            @{Name="Event"; Expression={ "Pipe Created (17)" }},
            @{Name="EventDetails"; Expression={ $_.PipeName }},
            # Event identification
            EventId,
            EventType,
            # Host and user information
            HostName,
            User,
            # Process-related fields
            ProcessGuid,
            ProcessId,
            Image,
            ProcessName,
            ProcessDir,
            # Pipe specific fields
            PipeName,
            # Time-related fields
            TimeCreated |
            Out-GridView -Title "Pipe Creation Events"
    }
}

function View-PipeCreateTimeline {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $PipeEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 17) {
            $PipeEvents += $Event
        }
    }
    End {
        $PipeEvents | Select-Object `
            UTCtime,
            @{Name="GUID"; Expression={ $_.ProcessGuid }},
            @{Name="Process"; Expression={ $_.ProcessName }},
            @{Name="Event"; Expression={ "Pipe Created (17)" }},
            @{Name="EventDetails"; Expression={ $_.PipeName }} | 
            Sort-Object UTCtime | Format-Table -AutoSize -Wrap
    }
}

function View-PipeCreateTimelineList {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $PipeEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 17) {
            $PipeEvents += $Event
        }
    }
    End {
        $PipeEvents | Select-Object `
            UTCtime,
            HostName,
            User,
            @{Name="ProcessId"; Expression={ $_.ProcessId }},
            @{Name="Process"; Expression={ "$($_.Image) [$($_.ProcessGuid)]" }},
            @{Name="Event"; Expression={ "Pipe Created" }},
            @{Name="EventDetails"; Expression={ $_.PipeName }} |
            Sort-Object UTCtime | Format-List
    }
}

function Investigate-PipeCreateInfo {
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

        # Process related parameters
        [parameter(Mandatory = $false)]
        [string] $ProcessName = $false,

        [parameter(Mandatory = $false)]
        [string] $ProcessId = $false,

        [parameter(Mandatory = $false)]
        [string] $ProcessGuid = $false,

        [parameter(Mandatory = $false)]
        [string] $Image = $false,

        # Pipe specific parameters
        [parameter(Mandatory = $false)]
        [string] $PipeName = $false,

        # Other parameters
        [parameter(Mandatory = $false)]
        [string] $User = $false,

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
            EventId = 17  # Only get CreatePipe events
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
            EventId = 17  # Only get CreatePipe events
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
        $BaseQuery = $BaseQuery | Where-Object {$_.ProcessId -eq $ProcessId}
    }

    if ($ProcessGuid -ne $false) {
        $TrimProcGuid = $ProcessGuid.tostring().trimstart("{").trimend("}")
        $ProcessGuid = "{0}{1}{2}" -f '{', $TrimProcGuid, '}'
        $BaseQuery = $BaseQuery | Where-Object {$_.ProcessGuid -eq $ProcessGuid.ToString()}
    }

    if ($Image -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Image -like $Image}
    }

    if ($PipeName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.PipeName -like $PipeName}
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
        "Summary" {
            $Query | View-PipeCreateSummary
            break
        }
        "InteractiveTable" {
            $Query | View-PipeCreateInteractiveTable
            break
        }
        "Timeline" {
            $Query | View-PipeCreateTimeline
            break
        }
        "TimelineList" {
            $Query | View-PipeCreateTimelineList
            break
        }
    }
}

Export-ModuleMember -Function View-PipeCreateSummary, 
                             View-PipeCreateInteractiveTable, View-PipeCreateTimeline, View-PipeCreateTimelineList,
                             Investigate-PipeCreateInfo 