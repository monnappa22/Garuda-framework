Function View-ShortFileBlockExecutableInfo {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Process {
        If ($Event.EventId -eq 27) {
            $Event | Select-Object EventId, EventType, HostName, UTCtime, `
            ProcessId, ProcessGuid, Image, User, TargetFilename, `
            @{Name="FileInfo"; Expression={"Process: $($_.ProcessName) | File: $($_.TargetFilename) | Blocked: $($_.RuleName)"}}
        }
    }
}

function View-QuickFileBlockExecutableInfo {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $FileBlockExecutableEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 27) {
            $FileBlockExecutableEvents += $Event
        }
    }
    End {
        $FileBlockExecutableEvents | Format-Table ProcessName, ProcessGuid, TargetFilename, RuleName -Autosize -Wrap
    }
}

function View-FileBlockExecutableSummary {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $FileBlockExecutableEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 27) {
            $FileBlockExecutableEvents += $Event
        }
    }
    end {
        $FileBlockExecutableEvents | select-object UTCtime, TargetFilename, MD5, `
            @{Name = "Process"; Expression = { "{0} (PID: {1}) - {2}" -f $_.Image, $_.ProcessId, $_.ProcessGuid } } `
        | sort-object Process | Format-Table UTCtime, TargetFilename, MD5 -GroupBy Process -Autosize -Wrap `
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

function View-FileBlockExecutableInteractiveTable {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $FileBlockExecutableEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 27) {
            $FileBlockExecutableEvents += $Event
        }
    }
    end {
        $FileBlockExecutableEvents | Select-Object UTCtime,
            @{Name="GUID"; Expression={ $_.ProcessGuid }},
            @{Name="Process"; Expression={ $_.Image }},
            @{Name="Event"; Expression={ "File Block Executable (27)" }},
            @{Name="EventDetails"; Expression={ "$($_.TargetFilename)" }},
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
            # File Block Executable specific fields
            RuleName,
            TargetFilename,
            # Hash fields
            Hashes,
            MD5,
            SHA256,
            SHA1,
            IMPHASH,
            # Time-related fields
            TimeCreated |
            Out-GridView -Title "File Block Executable Information"
    }
}

function View-FileBlockExecutableTimeline {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $FileBlockExecutableEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 27) {
            $FileBlockExecutableEvents += $Event
        }
    }
    End {
        $FileBlockExecutableEvents | Select-Object `
            UTCtime,
            @{Name="GUID"; Expression={ $_.ProcessGuid }},
            @{Name="Process"; Expression={ $_.ProcessName }},
            @{Name="Event"; Expression={ "File Block Executable (27)" }},
            @{Name="EventDetails"; Expression={ "$($_.TargetFilename)" }} | 
            Sort-Object UTCtime | Format-Table -AutoSize -Wrap
    }
}

function View-FileBlockExecutableTimelineList {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $FileBlockExecutableEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 27) {
            $FileBlockExecutableEvents += $Event
        }
    }
    End {
        $FileBlockExecutableEvents | Select-Object `
            UTCtime,
            HostName,
            User,
            ProcessId,
            @{Name="Process"; Expression={ "$($_.Image) [$($_.ProcessGuid)]" }},
            @{Name="Event"; Expression={ "File Block Executable (27)" }},
            @{Name="EventDetails"; Expression={ "$($_.TargetFilename)" }},
            Hashes | 
            Sort-Object UTCtime
    }
}

function Investigate-FileBlockExecutableInfo {
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
        [string] $ProcessDir = $false,

        [parameter(Mandatory = $false)]
        [string] $TargetFilename = $false,

        [parameter(Mandatory = $false)]
        [string] $RuleName = $false,

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
        [string] $MD5 = $false,

        [parameter(Mandatory = $false)]
        [string] $SHA256 = $false,

        [parameter(Mandatory = $false)]
        [string] $SHA1 = $false,

        [parameter(Mandatory = $false)]
        [string] $IMPHASH = $false,

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
            EventId = 27
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
            EventId = 27
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

    if ($ProcessDir -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.ProcessDir -like $ProcessDir}
    }

    if ($TargetFilename -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.TargetFilename -like $TargetFilename}
    }

    if ($RuleName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.RuleName -like $RuleName}
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

    if ($MD5 -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Hashes -like "*MD5=$MD5*"}
    }

    if ($SHA256 -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Hashes -like "*SHA256=$SHA256*"}
    }

    if ($SHA1 -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Hashes -like "*SHA1=$SHA1*"}
    }

    if ($IMPHASH -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Hashes -like "*IMPHASH=$IMPHASH*"}
    }

    $Query = $BaseQuery
    
    switch ($View) {
        "Detailed" { 
            $Query
            break
        }
        "Summary" {
            $Query | View-FileBlockExecutableSummary
            break
        }
        "InteractiveTable" {
            $Query | View-FileBlockExecutableInteractiveTable
            break
        }
        "Timeline" {
            $Query | View-FileBlockExecutableTimeline
            break
        }
        "TimelineList" {
            $Query | View-FileBlockExecutableTimelineList
            break
        }
    }
}

Export-ModuleMember -Function View-FileBlockExecutableSummary, View-FileBlockExecutableInteractiveTable, 
                             View-FileBlockExecutableTimeline, View-FileBlockExecutableTimelineList,
                             Investigate-FileBlockExecutableInfo 