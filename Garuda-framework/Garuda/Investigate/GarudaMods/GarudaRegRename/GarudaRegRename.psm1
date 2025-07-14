function View-RegRenameSummary {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $RegEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 14) {
            $RegEvents += $Event
        }
    }
    end {
        $RegEvents | Select-Object @{
                Name = "ProcessInfo"
                Expression = { "{0} (PID: {1}) GUID: {2}" -f $_.Image, $_.ProcessId, $_.ProcessGuid }
            }, UTCtime, @{
                Name = "Event"
                Expression = { "Reg $($_.EventType) (14)" }
            }, @{
                Name = "EventDetails"
                Expression = { "$($_.TargetObject) -> $($_.NewName)" }
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

function View-RegRenameInteractiveTable {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $RegEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 14) {
            $RegEvents += $Event
        }
    }
    end {
        $RegEvents | Select-Object UTCtime,
            @{Name="GUID"; Expression={ $_.ProcessGuid }},
            @{Name="Process"; Expression={ $_.Image }},
            @{Name="Event"; Expression={ "Reg $($_.EventType) (14)" }},
            @{Name="EventDetails"; Expression={ "$($_.TargetObject) -> $($_.NewName)" }},
            # Event identification
            EventId, 
            EventType,
            # Host and user information
            HostName,
            User,
            # Process-related fields
            ProcessId, 
            ProcessGuid, 
            Image, 
            ProcessName,
            ProcessDir,
            # Registry fields
            TargetObject, 
            NewName,
            RegKey, 
            RegKeyValue, 
            RenamedRegKeyValue,
            # Time-related fields
            TimeCreated | 
            Out-GridView -Title "Registry Rename Information"
    }
}

function View-RegRenameTimeline {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $RegEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 14) {
            $RegEvents += $Event
        }
    }
    End {
        $RegEvents | Select-Object `
            UTCtime,
            @{Name="GUID"; Expression={ $_.ProcessGuid }},
            @{Name="Process"; Expression={ $_.ProcessName }},
            @{Name="Event"; Expression={ "Reg $($_.EventType) (14)" }},
            @{Name="EventDetails"; Expression={ "$($_.TargetObject) -> $($_.NewName)" }} | 
            Sort-Object UTCtime | Format-Table -AutoSize -Wrap
    }
}

function View-RegRenameTimelineList {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $RegEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 14) {
            $RegEvents += $Event
        }
    }
    End {
        $RegEvents | Select-Object `
            UTCtime,
            HostName,
            User,
            ProcessId,
            @{Name="Process"; Expression={ 
                if ($_.CommandLine) {
                    "$($_.Image) [$($_.ProcessGuid)] [$($_.CommandLine)]"
                } else {
                    "$($_.Image) [$($_.ProcessGuid)]"
                }
            }},
            @{Name="Event"; Expression={ "Reg $($_.EventType) (14)" }},
            @{Name="EventDetails"; Expression={ "$($_.TargetObject) -> $($_.NewName)" }} | 
            Sort-Object UTCtime |
            # Explicitly select only the fields we want to display to prevent unexpected fields
            Select-Object UTCtime, HostName, User, ProcessId, Process, Event, EventDetails
    }
}

function Investigate-RegRenameInfo {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [parameter(Mandatory = $false)]
        [string] $ProcessName = $false,

        [parameter(Mandatory = $false)]
        [string] $ProcessId = $false,

        [parameter(Mandatory = $false)]
        [string] $ProcessGuid = $false,

        [parameter(Mandatory = $false)]
        [string] $Image = $false,

        [parameter(Mandatory = $false)]
        [string] $TargetObject = $false,

        [parameter(Mandatory = $false)]
        [string] $NewName = $false,

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
        [string] $EventType = $false,

        [parameter(Mandatory = $false)]
        [string] $RegKey = $false,

        [parameter(Mandatory = $false)]
        [string] $RegKeyValue = $false,

        [parameter(Mandatory = $false)]
        [string] $RenamedRegKeyValue = $false,

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
            EventId = 14
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
            EventId = 14
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

    if ($Image -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Image -like $Image}
    }

    if ($TargetObject -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.TargetObject -like $TargetObject}
    }

    if ($NewName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.NewName -like $NewName}
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

    if ($EventType -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.EventType -like $EventType}
    }

    if ($RegKey -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.RegKey -like $RegKey}
    }

    if ($RegKeyValue -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.RegKeyValue -like $RegKeyValue}
    }

    if ($RenamedRegKeyValue -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.RenamedRegKeyValue -like $RenamedRegKeyValue}
    }

    $Query = $BaseQuery
    
    switch ($View) {
        "Detailed" { 
            $Query
            break
        }
        "Summary" {
            $Query | View-RegRenameSummary
            break
        }
        "InteractiveTable" {
            $Query | View-RegRenameInteractiveTable
            break
        }
        "Timeline" {
            $Query | View-RegRenameTimeline
            break
        }
        "TimelineList" {
            $Query | View-RegRenameTimelineList
            break
        }
    }
}

Export-ModuleMember -Function View-RegRenameSummary, 
                             View-RegRenameInteractiveTable, View-RegRenameTimeline,
                             View-RegRenameTimelineList, Investigate-RegRenameInfo 