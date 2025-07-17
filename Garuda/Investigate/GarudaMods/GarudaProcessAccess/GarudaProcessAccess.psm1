function View-ProcessAccessTimeline {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ProcessAccessEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 10) {
            $ProcessAccessEvents += $Event
        }
    }
    End {
        $ProcessAccessEvents | Select-Object `
            UTCtime,
            @{Name="GUID"; Expression={ $_.SourceProcessGuid }},
            @{Name="Process"; Expression={ "$($_.SourceProcessName)($($_.SourceProcessId))" }},
            @{Name="Event"; Expression={ "Process Access (10)" }},
            @{Name="EventDetails"; Expression={ "TargetImage: $($_.TargetImage) | TargetProcessId: $($_.TargetProcessId) | TargetProcessGuid: $($_.TargetProcessGuid) | GrantedAccess: $($_.GrantedAccess)" }} |
            Sort-Object UTCtime | Format-Table -AutoSize -Wrap
    }
}

function View-ProcessAccessTimelineList {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ProcessAccessEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 10) {
            $ProcessAccessEvents += $Event
        }
    }
    End {
        $ProcessAccessEvents | Select-Object `
            UTCtime,
            HostName,
            @{Name="User"; Expression={ "$($_.SourceUser) -> $($_.TargetUser)" }},
            @{Name="Process"; Expression={ "SourceImage: $($_.SourceImage) | SourceProcessId: $($_.SourceProcessId) | SourceProcessGuid: $($_.SourceProcessGuid)" }},
            @{Name="Event"; Expression={ "Process Access (10)" }},
            @{Name="EventDetails"; Expression={
                $details = "TargetImage: $($_.TargetImage) | TargetProcessId: $($_.TargetProcessId) | TargetProcessGuid: $($_.TargetProcessGuid) | GrantedAccess: $($_.GrantedAccess)"
                if ($_.CallTrace) {
                    "$details | CallTrace: $($_.CallTrace)"
                } else {
                    $details
                }
            }} |
            Sort-Object UTCtime
    }
}

function View-ProcessAccessSummary {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ProcessAccessEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 10) {
            $ProcessAccessEvents += $Event
        }
    }
    End {
        $ProcessAccessEvents | Select-Object @{
            Name = "ProcessInfo"
            Expression = { "{0} (PID: {1}) GUID: {2}" -f $_.SourceImage, $_.SourceProcessId, $_.SourceProcessGuid }
        }, UTCtime, @{
            Name = "Event"
            Expression = { "Process Access (10)" }
        }, @{
            Name = "EventDetails"
            Expression = { "TargetImage: $($_.TargetImage) | TargetProcessGuid: $($_.TargetProcessGuid) | GrantedAccess: $($_.GrantedAccess)" }
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

function View-ProcessAccessInteractiveTable {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ProcessAccessEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 10) {
            $ProcessAccessEvents += $Event
        }
    }
    end {
        $ProcessAccessEvents | Select-Object UTCtime,
            @{Name="GUID"; Expression={ $_.SourceProcessGuid }},
            @{Name="Process"; Expression={ "SourceImage: $($_.SourceImage) | SourceProcessId: $($_.SourceProcessId) | SourceProcessGuid: $($_.SourceProcessGuid)" }},
            @{Name="Event"; Expression={ "Process Access (10)" }},
            @{Name="EventDetails"; Expression={ 
                "TargetImage: $($_.TargetImage) | TargetProcessId: $($_.TargetProcessId) | TargetProcessGuid: $($_.TargetProcessGuid) | GrantedAccess: $($_.GrantedAccess)"
            }},
            HostName,
            EventId,
            EventType,
            SourceProcessGuid,
            SourceProcessId,
            SourceThreadId,
            SourceImage,
            TargetProcessGuid,
            TargetProcessId,
            TargetImage,
            GrantedAccess,
            CallTrace,
            SourceUser,
            TargetUser,
            SourceProcessName,
            SourceProcessDir,
            TargetProcessName,
            TargetProcessDir,
            TimeCreated |
            Out-GridView -Title "Process Access Information"
    }
}

function Investigate-ProcessAccessInfo {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [parameter(Mandatory = $false)]
        [string] $SourceProcessName = $false,

        [parameter(Mandatory = $false)]
        [string] $SourceProcessId = $false,

        [parameter(Mandatory = $false)]
        [string] $SourceProcessGuid = $false,

        [parameter(Mandatory = $false)]
        [string] $TargetProcessName = $false,

        [parameter(Mandatory = $false)]
        [string] $TargetProcessId = $false,

        [parameter(Mandatory = $false)]
        [string] $TargetProcessGuid = $false,

        [parameter(Mandatory = $false)]
        [string] $SourceImage = $false,

        [parameter(Mandatory = $false)]
        [string] $TargetImage = $false,

        [parameter(Mandatory = $false)]
        [string] $GrantedAccess = $false,

        [parameter(Mandatory = $false)]
        [string] $CallTrace = $false,

        [parameter(Mandatory = $false)]
        [string] $SourceUser = $false,

        [parameter(Mandatory = $false)]
        [string] $TargetUser = $false,

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
            EventId = 10
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
            EventId = 10
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

    if ($SourceProcessName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.SourceProcessName -like $SourceProcessName}
    }

    if ($SourceProcessId -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.SourceProcessId -like $SourceProcessId}
    }

    if ($SourceProcessGuid -ne $false) {
        $TrimSourceProcGuid = $SourceProcessGuid.tostring().trimstart("{").trimend("}")
        $SourceProcessGuid = "{0}{1}{2}" -f '{', $TrimSourceProcGuid, '}'
        $BaseQuery = $BaseQuery | Where-Object {$_.SourceProcessGuid -eq $SourceProcessGuid.ToString()}
    }

    if ($TargetProcessName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.TargetProcessName -like $TargetProcessName}
    }

    if ($TargetProcessId -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.TargetProcessId -like $TargetProcessId}
    }

    if ($TargetProcessGuid -ne $false) {
        $TrimTargetProcGuid = $TargetProcessGuid.tostring().trimstart("{").trimend("}")
        $TargetProcessGuid = "{0}{1}{2}" -f '{', $TrimTargetProcGuid, '}'
        $BaseQuery = $BaseQuery | Where-Object {$_.TargetProcessGuid -eq $TargetProcessGuid.ToString()}
    }

    if ($SourceImage -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.SourceImage -like $SourceImage}
    }

    if ($TargetImage -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.TargetImage -like $TargetImage}
    }

    if ($GrantedAccess -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.GrantedAccess -like $GrantedAccess}
    }

    if ($CallTrace -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.CallTrace -like $CallTrace}
    }

    if ($SourceUser -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.SourceUser -like $SourceUser}
    }

    if ($TargetUser -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.TargetUser -like $TargetUser}
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
            $Query | View-ProcessAccessTimeline
            break
        }
        "TimelineList" {
            $Query | View-ProcessAccessTimelineList
            break
        }
        "Summary" {
            $Query | View-ProcessAccessSummary
            break
        }
        "InteractiveTable" {
            $Query | View-ProcessAccessInteractiveTable
            break
        }
    }
}

Export-ModuleMember -Function View-ProcessAccessTimeline, View-ProcessAccessTimelineList, View-ProcessAccessSummary, 
                             View-ProcessAccessInteractiveTable, Investigate-ProcessAccessInfo 