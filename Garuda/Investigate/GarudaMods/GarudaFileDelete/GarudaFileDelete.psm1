Function View-ShortFileDeleteInfo {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Process {
        If ($Event.EventId -eq 23) {
            $Event | Select-Object EventId, EventType, HostName, UTCtime, `
            ProcessId, ProcessGuid, Image, User, TargetFilename, `
            @{Name="FileInfo"; Expression={"Process: $($_.ProcessName) | File: $($_.TargetFilename) | Archived: $($_.Archived)"}}
        }
    }
}

function View-QuickFileDeleteInfo {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $FileDeleteEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 23) {
            $FileDeleteEvents += $Event
        }
    }
    End {
        $FileDeleteEvents | Format-Table ProcessName, ProcessGuid, TargetFilename, Archived, IsExecutable -Autosize -Wrap
    }
}

function View-FileDeleteSummary {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $FileDeleteEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 23) {
            $FileDeleteEvents += $Event
        }
    }
    end {
        $FileDeleteEvents | select-object TargetFilename, Archived, IsExecutable, `
            @{Name = "Process"; Expression = { "{0} (PID: {1}) - {2}" -f $_.Image, $_.ProcessId, $_.ProcessGuid } } `
        | sort-object Process | Format-Table TargetFilename, Archived, IsExecutable -GroupBy Process -Autosize -Wrap `
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

function View-FileDeleteInteractiveTable {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $FileDeleteEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 23) {
            $FileDeleteEvents += $Event
        }
    }
    end {
        $FileDeleteEvents | Select-Object UTCtime,
            @{Name="GUID"; Expression={ $_.ProcessGuid }},
            @{Name="Process"; Expression={ $_.Image }},
            @{Name="Event"; Expression={ "File Delete (23)" }},
            @{Name="EventDetails"; Expression={ "$($_.TargetFilename) [Archived: $($_.Archived)] [Executable: $($_.IsExecutable)]" }},
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
            # File Delete specific fields
            TargetFilename,
            IsExecutable,
            Archived,
            # Hash fields
            Hashes,
            MD5,
            SHA256,
            SHA1,
            IMPHASH,
            # Time-related fields
            TimeCreated |
            Out-GridView -Title "File Delete Information"
    }
}

function View-FileDeleteTimeline {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $FileDeleteEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 23) {
            $FileDeleteEvents += $Event
        }
    }
    End {
        $FileDeleteEvents | Select-Object `
            UTCtime,
            @{Name="GUID"; Expression={ $_.ProcessGuid }},
            @{Name="Process"; Expression={ $_.ProcessName }},
            @{Name="Event"; Expression={ "File Delete (23)" }},
            @{Name="EventDetails"; Expression={ "$($_.TargetFilename) [Archived: $($_.Archived)] [Executable: $($_.IsExecutable)]" }} | 
            Sort-Object UTCtime | Format-Table -AutoSize -Wrap
    }
}

function View-FileDeleteTimelineList {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $FileDeleteEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 23) {
            $FileDeleteEvents += $Event
        }
    }
    End {
        $FileDeleteEvents | Select-Object `
            UTCtime,
            HostName,
            User,
            ProcessId,
            @{Name="Process"; Expression={ "$($_.Image) [$($_.ProcessGuid)]" }},
            @{Name="Event"; Expression={ "File Delete (23)" }},
            @{Name="EventDetails"; Expression={ "$($_.TargetFilename) [Archived: $($_.Archived)] [Executable: $($_.IsExecutable)]" }},
            Hashes | 
            Sort-Object UTCtime
    }
}

function Investigate-FileDeleteInfo {
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
        [string] $IMPHASH = $false,

        [parameter(Mandatory = $false)]
        [string] $IsExecutable = "",

        [parameter(Mandatory = $false)]
        [string] $Archived = "",

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
            EventId = 23
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
            EventId = 23
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

    if ($IMPHASH -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Hashes -like "*IMPHASH=$IMPHASH*"}
    }

    if ($IsExecutable -ne "") {
        $BaseQuery = $BaseQuery | Where-Object {$_.IsExecutable -like $IsExecutable}
    }

    if ($Archived -ne "") {
        $BaseQuery = $BaseQuery | Where-Object {$_.Archived -like $Archived}
    }

    $Query = $BaseQuery
    
    switch ($View) {
        "Detailed" { 
            $Query
            break
        }
        "Summary" {
            $Query | View-FileDeleteSummary
            break
        }
        "InteractiveTable" {
            $Query | View-FileDeleteInteractiveTable
            break
        }
        "Timeline" {
            $Query | View-FileDeleteTimeline
            break
        }
        "TimelineList" {
            $Query | View-FileDeleteTimelineList
            break
        }
    }
}

Export-ModuleMember -Function View-FileDeleteSummary, View-FileDeleteInteractiveTable, 
                             View-FileDeleteTimeline, View-FileDeleteTimelineList,
                             Investigate-FileDeleteInfo 