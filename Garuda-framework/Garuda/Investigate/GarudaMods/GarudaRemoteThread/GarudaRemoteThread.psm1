function View-RemoteThreadTimeline {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $RemoteThreadEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 8) {
            $RemoteThreadEvents += $Event
        }
    }
    End {
        $RemoteThreadEvents | Select-Object `
            UTCtime,
            SourceProcessGuid,
            SourceProcessName,
            @{Name="Event"; Expression={ "Remote Thread (8)" }},
            @{Name="EventDetails"; Expression={ 
                "$($_.TargetImage) [$($_.TargetProcessGuid)] [StartAddress: $($_.StartAddress)] [StartModule: $($_.StartModule)] [StartFunction: $($_.StartFunction)]"
            }} | 
            Sort-Object UTCtime | Format-Table -AutoSize -Wrap
    }
}

function View-RemoteThreadTimelineList {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $RemoteThreadEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 8) {
            $RemoteThreadEvents += $Event
        }
    }
    End {
        $RemoteThreadEvents | Select-Object `
            UTCtime,
            HostName,
            @{Name="User"; Expression={ "$($_.SourceUser) -> $($_.TargetUser)" }},
            SourceProcessId,
            @{Name="Process"; Expression={ "$($_.SourceImage) [$($_.SourceProcessGuid)]" }},
            @{Name="Event"; Expression={ "Remote Thread (8)" }},
            @{Name="EventDetails"; Expression={ 
                "$($_.TargetImage) [$($_.TargetProcessGuid)] [StartAddress: $($_.StartAddress)] [StartModule: $($_.StartModule)] [StartFunction: $($_.StartFunction)]"
            }} |
            Sort-Object UTCtime
    }
}

function View-RemoteThreadSummary {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $RemoteThreadEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 8) {
            $RemoteThreadEvents += $Event
        }
    }
    end {
        $RemoteThreadEvents | Select-Object `
            @{Name = "ProcessInfo"; Expression = { "{0} (PID: {1}) GUID: {2}" -f $_.SourceImage, $_.SourceProcessId, $_.SourceProcessGuid }},
            UTCtime,
            @{Name = "Event"; Expression = { "Remote Thread (8)" }},
            @{Name = "EventDetails"; Expression = { 
                "$($_.TargetImage) [$($_.TargetProcessGuid)] [StartAddress: $($_.StartAddress)] [StartModule: $($_.StartModule)] [StartFunction: $($_.StartFunction)]"
            }} |
            Sort-Object ProcessInfo, UTCtime | 
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

function View-RemoteThreadInteractiveTable {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $RemoteThreadEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 8) {
            $RemoteThreadEvents += $Event
        }
    }
    end {
        # Create a view with the standard first 5 fields, then Event ID 8 specific fields
        $RemoteThreadEvents | Select-Object UTCtime,
            @{Name="GUID"; Expression={ $_.SourceProcessGuid }},
            @{Name="Process"; Expression={ $_.SourceImage }},
            @{Name="Event"; Expression={ "Remote Thread (8)" }},
            @{Name="EventDetails"; Expression={ 
                "$($_.SourceImage) [$($_.SourceProcessId)] ---> $($_.TargetImage) [$($_.TargetProcessId)]"
            }},
            HostName,
            EventId,
            EventType,
            SourceProcessGuid,
            SourceProcessId,
            SourceImage,
            TargetProcessGuid,
            TargetProcessId,
            TargetImage,
            NewThreadId,
            StartAddress,
            StartModule,
            StartFunction,
            SourceUser,
            TargetUser,
            SourceProcessName,
            SourceProcessDir,
            TargetProcessName,
            TargetProcessDir,
            TimeCreated |
            Out-GridView -Title "Remote Thread Creation Information"
    }
}

function Investigate-RemoteThreadInfo {
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
        [string] $StartAddress = $false,

        [parameter(Mandatory = $false)]
        [string] $StartModule = $false,

        [parameter(Mandatory = $false)]
        [string] $StartFunction = $false,

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
            EventId = 8
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
            EventId = 8
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

    if ($StartAddress -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.StartAddress -like $StartAddress}
    }

    if ($StartModule -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.StartModule -like $StartModule}
    }

    if ($StartFunction -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.StartFunction -like $StartFunction}
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
            $Query | View-RemoteThreadTimeline
            break
        }
        "TimelineList" {
            $Query | View-RemoteThreadTimelineList
            break
        }
        "Summary" {
            $Query | View-RemoteThreadSummary
            break
        }
        "InteractiveTable" {
            $Query | View-RemoteThreadInteractiveTable
            break
        }
    }
}

Export-ModuleMember -Function View-RemoteThreadTimeline, View-RemoteThreadTimelineList, View-RemoteThreadSummary, 
                             View-RemoteThreadInteractiveTable, Investigate-RemoteThreadInfo 