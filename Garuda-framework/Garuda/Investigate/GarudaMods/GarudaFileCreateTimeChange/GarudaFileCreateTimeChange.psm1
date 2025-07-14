function View-FileCreateTimeChangeSummary {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $FileCreateTimeChangeEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 2) {
            $FileCreateTimeChangeEvents += $Event
        }
    }
    End {
        if ($FileCreateTimeChangeEvents.Count -gt 0) {
            $FileCreateTimeChangeEvents | Select-Object @{
                Name = "ProcessInfo"
                Expression = { 
                    "{0} (PID: {1}) GUID: {2}" -f $_.Image, $_.ProcessId, $_.ProcessGuid
                }
            }, UTCtime, @{
                Name = "Event"
                Expression = { "File Time Change (2)" }
            }, @{
                Name = "EventDetails"
                Expression = { $_.TargetFilename }
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

function View-FileCreateTimeChangeTimeline {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $FileCreateTimeChangeEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 2) {
            $FileCreateTimeChangeEvents += $Event
        }
    }
    End {
        $FileCreateTimeChangeEvents | Select-Object `
            UTCtime,
            @{Name="GUID"; Expression={ $_.ProcessGuid }},
            @{Name="Process"; Expression={ $_.ProcessName }},
            @{Name="Event"; Expression={ "File Time Change (2)" }},
            @{Name="EventDetails"; Expression={ $_.TargetFilename }} | 
            Sort-Object UTCtime | Format-Table -AutoSize -Wrap
    }
}

function View-FileCreateTimeChangeTimelineList {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $FileCreateTimeChangeEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 2) {
            $FileCreateTimeChangeEvents += $Event
        }
    }
    End {
        $FileCreateTimeChangeEvents | Select-Object `
            UTCtime,
            HostName,
            User,
            ProcessId,
            @{Name="Process"; Expression={ "$($_.Image) [$($_.ProcessGuid)]" }},
            @{Name="Event"; Expression={ "File Time Change (2)" }},
            @{Name="EventDetails"; Expression={ $_.TargetFilename }},
            @{Name="TimeInfo"; Expression={ "Previous: $($_.PreviousCreationUtcTime) -> New: $($_.CreationUtcTime)" }} | 
            Sort-Object UTCtime | Format-List
    }
}

function View-FileCreateTimeChangeInteractivetable {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $FileCreateTimeChangeEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 2) {
            $FileCreateTimeChangeEvents += $Event
        }
    }
    end {
        # Create a view with the standard first 5 fields, then Event ID 2 specific fields
        $FileCreateTimeChangeEvents | Select-Object UTCtime,
            @{Name="GUID"; Expression={ $_.ProcessGuid }},
            @{Name="Process"; Expression={ $_.Image }},
            @{Name="Event"; Expression={ "File Time Change (2)" }},
            @{Name="EventDetails"; Expression={ $_.TargetFilename }},
            # Event ID 2 specific fields
            HostName,
            ProcessGuid,
            ProcessId,
            Image,
            TargetFilename,
            CreationUtcTime,
            PreviousCreationUtcTime,
            User,
            EventId,
            EventType,
            TimeCreated,
            ProcessName,
            ProcessDir |
            Out-GridView -Title "File Creation Time Change Information"
    }
}




# Below is the investigation function
function Investigate-FileCreateTimeChange {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [parameter(Mandatory = $false, Position = 0)]
        [string] $ProcessGuid = $false,

        [parameter(Mandatory = $false)]
        [string] $ProcessName = $false,

        [parameter(Mandatory = $false)]
        [string] $Image= $false,

        [parameter(Mandatory = $false)]
        [string] $TargetFilename= $false,

        [parameter(Mandatory = $false)]
        [string] $UtcTime = $false,

        [parameter(Mandatory = $false)]
        [string] $HostName = $false,

        [parameter( Mandatory = $false)]
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
        [ValidateSet("Detailed","Summary","InteractiveTable", "Timeline", "TimelineList")]
        [string] $view = "Detailed",

        [parameter(Mandatory = $false)]
        [int] $ProcessId = $false,

        [parameter(Mandatory = $false)]
        [string] $CreationUtcTime = $false,

        [parameter(Mandatory = $false)]
        [string] $PreviousCreationUtcTime = $false,

        [parameter(Mandatory = $false)]
        [string] $User = $false
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
            EventId = 2
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
            EventId = 2
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

    if ($TargetFilename -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.TargetFilename -like $TargetFilename}
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

    if ($CreationUtcTime -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.CreationUtcTime -like $CreationUtcTime}
    }

    if ($PreviousCreationUtcTime -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.PreviousCreationUtcTime -like $PreviousCreationUtcTime}
    }

    if ($User -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.User -like $User}
    }

    $Query = $BaseQuery

    # Displaying results based on the chosen views
    switch ($view) {

        "Detailed" { 
            $Query
            break
        }
        "Summary" {
            $Query | View-FileCreateTimeChangeSummary
            break
        }
        "InteractiveTable" {
             $Query | View-FileCreateTimeChangeInteractivetable
            break
        }
        "Timeline" {
            $Query | View-FileCreateTimeChangeTimeline
            break
        }
        "TimelineList" {
            $Query | View-FileCreateTimeChangeTimelineList
            break
        }
 
    }
    
}
