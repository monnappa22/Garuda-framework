function View-FileStreamHashSummary {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $FileStreamEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 15) {
            $FileStreamEvents += $Event
        }
    }
    end {
        $FileStreamEvents | Select-Object @{
                Name = "ProcessInfo"
                Expression = { "{0} (PID: {1}) GUID: {2}" -f $_.Image, $_.ProcessId, $_.ProcessGuid }
            }, UTCtime, @{
                Name = "Event"
                Expression = { "FileStreamHash (15)" }
            }, @{
                Name = "EventDetails"
                Expression = { "$($_.TargetFilename) [$($_.Contents)] [MD5: $($_.MD5)]" }
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

function View-FileStreamHashInteractiveTable {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $FileStreamEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 15) {
            $FileStreamEvents += $Event
        }
    }
    end {
        $FileStreamEvents | Select-Object UTCtime,
            @{Name="GUID"; Expression={ $_.ProcessGuid }},
            @{Name="Process"; Expression={ $_.Image }},
            @{Name="Event"; Expression={ "FileStreamHash (15)" }},
            @{Name="EventDetails"; Expression={ "$($_.TargetFilename) [$($_.Contents)] [MD5: $($_.MD5)]" }},
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
            # File fields
            TargetFilename, 
            CreationUtcTime,
            # FileStreamHash specific fields
            Contents, 
            Hash,
            # Hash fields
            MD5, 
            SHA256, 
            SHA1, 
            IMPHASH,
            # Time-related fields
            TimeCreated | 
            Out-GridView -Title "File Stream Hash Information"
    }
}

function View-FileStreamHashTimeline {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $FileStreamEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 15) {
            $FileStreamEvents += $Event
        }
    }
    End {
        $FileStreamEvents | Select-Object `
            UTCtime,
            @{Name="GUID"; Expression={ $_.ProcessGuid }},
            @{Name="Process"; Expression={ $_.ProcessName }},
            @{Name="Event"; Expression={ "FileStreamHash (15)" }},
            @{Name="EventDetails"; Expression={ "$($_.TargetFilename) [$($_.Contents)] [MD5: $($_.MD5)]" }} | 
            Sort-Object UTCtime | Format-Table -AutoSize -Wrap
    }
}

function View-FileStreamHashTimelineList {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $FileStreamEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 15) {
            $FileStreamEvents += $Event
        }
    }
    End {
        $FileStreamEvents | Select-Object `
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
            @{Name="Event"; Expression={ "FileStreamHash (15)" }},
            @{Name="EventDetails"; Expression={ "$($_.TargetFilename) [$($_.Contents)] [MD5: $($_.MD5)]" }} | 
            Sort-Object UTCtime
    }
}

function Investigate-FileStreamHashInfo {
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
        [string] $TargetFilename = $false,

        [parameter(Mandatory = $false)]
        [string] $CreationUtcTime = $false,

        [parameter(Mandatory = $false)]
        [string] $Hash = $false,

        [parameter(Mandatory = $false)]
        [string] $Contents = $false,

        [parameter(Mandatory = $false)]
        [string] $User = $false,

        [parameter(Mandatory = $false)]
        [string] $UtcTime = $false,

        [parameter(Mandatory = $false)]
        [string] $HostName = $false,

        [parameter(Mandatory = $false)]
        [string] $MD5 = $false,

        [parameter(Mandatory = $false)]
        [string] $SHA256 = $false,

        [parameter(Mandatory = $false)]
        [string] $SHA1 = $false,

        [parameter(Mandatory = $false)]
        [string] $IMPHASH = $false,

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

    if ($null -eq $LogFile) {
        $Parameters = @{
            EventId = 15
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
            EventId = 15
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

    if ($TargetFilename -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.TargetFilename -like $TargetFilename}
    }

    if ($CreationUtcTime -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.CreationUtcTime -like $CreationUtcTime}
    }

    if ($Hash -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Hash -like $Hash}
    }

    if ($Contents -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Contents -like $Contents}
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
        $BaseQuery = $BaseQuery | Where-Object {$_.MD5 -like $MD5}
    }

    if ($SHA256 -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.SHA256 -like $SHA256}
    }

    if ($SHA1 -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.SHA1 -like $SHA1}
    }

    if ($IMPHASH -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.IMPHASH -like $IMPHASH}
    }

    $Query = $BaseQuery
    
    switch ($View) {
        "Detailed" { 
            $Query
            break
        }
        "Summary" {
            $Query | View-FileStreamHashSummary
            break
        }
        "InteractiveTable" {
            $Query | View-FileStreamHashInteractiveTable
            break
        }
        "Timeline" {
            $Query | View-FileStreamHashTimeline
            break
        }
        "TimelineList" {
            $Query | View-FileStreamHashTimelineList
            break
        }
    }
}

Export-ModuleMember -Function View-FileStreamHashSummary, 
                             View-FileStreamHashInteractiveTable, View-FileStreamHashTimeline,
                             View-FileStreamHashTimelineList, Investigate-FileStreamHashInfo 