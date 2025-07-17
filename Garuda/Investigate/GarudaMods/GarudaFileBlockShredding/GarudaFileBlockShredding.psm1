function View-FileBlockShreddingSummary {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $FileBlockShreddingEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 28) {
            $FileBlockShreddingEvents += $Event
        }
    }
    end {
        $FileBlockShreddingEvents | select-object UTCtime, TargetFilename, MD5, IsExecutable, `
            @{Name = "Process"; Expression = { "Image: $($_.Image) | ProcessId: $($_.ProcessId) | ProcessGuid: $($_.ProcessGuid)" } } `
        | sort-object Process | Format-Table UTCtime, TargetFilename, MD5, IsExecutable -GroupBy Process -Autosize -Wrap `
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

function View-FileBlockShreddingInteractiveTable {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $FileBlockShreddingEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 28) {
            $FileBlockShreddingEvents += $Event
        }
    }
    end {
        $FileBlockShreddingEvents | Select-Object UTCtime,
            @{Name="GUID"; Expression={ $_.ProcessGuid }},
            @{Name="Process"; Expression={ "Image: $($_.Image) | ProcessId: $($_.ProcessId) | ProcessGuid: $($_.ProcessGuid)" }},
            @{Name="Event"; Expression={ "File Block Shredding (28)" }},
            @{Name="EventDetails"; Expression={ "TargetFilename: $($_.TargetFilename) | Executable: $($_.IsExecutable)" }},
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
            # File Block Shredding specific fields
            RuleName,
            TargetFilename,
            IsExecutable,
            # Hash fields
            Hashes,
            MD5,
            SHA256,
            SHA1,
            IMPHASH,
            # Time-related fields
            TimeCreated |
            Out-GridView -Title "File Block Shredding Information"
    }
}

function View-FileBlockShreddingTimeline {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $FileBlockShreddingEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 28) {
            $FileBlockShreddingEvents += $Event
        }
    }
    End {
        $FileBlockShreddingEvents | Select-Object `
            UTCtime,
            @{Name="GUID"; Expression={ $_.ProcessGuid }},
            @{Name="Process"; Expression={ "$($_.ProcessName)($($_.ProcessId))" }},
            @{Name="Event"; Expression={ "File Block Shredding (28)" }},
            @{Name="EventDetails"; Expression={ "TargetFilename: $($_.TargetFilename) | Executable: $($_.IsExecutable)" }} | 
            Sort-Object UTCtime | Format-Table -AutoSize -Wrap
    }
}

function View-FileBlockShreddingTimelineList {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $FileBlockShreddingEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 28) {
            $FileBlockShreddingEvents += $Event
        }
    }
    End {
        $FileBlockShreddingEvents | Select-Object `
            UTCtime,
            HostName,
            User,
            @{Name="Process"; Expression={ "Image: $($_.Image) | ProcessId: $($_.ProcessId) | ProcessGuid: $($_.ProcessGuid)" }},
            @{Name="Event"; Expression={ "File Block Shredding (28)" }},
            @{Name="EventDetails"; Expression={ "TargetFilename: $($_.TargetFilename) | Executable: $($_.IsExecutable)" }},
            Hashes | 
            Sort-Object UTCtime
    }
}

function Investigate-FileBlockShreddingInfo {
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
        [string] $IsExecutable = "",

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
            EventId = 28
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
            EventId = 28
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

    if ($IsExecutable -ne "") {
        $BaseQuery = $BaseQuery | Where-Object {$_.IsExecutable -like $IsExecutable}
    }

    $Query = $BaseQuery
    
    switch ($View) {
        "Detailed" { 
            $Query
            break
        }
        "Summary" {
            $Query | View-FileBlockShreddingSummary
            break
        }
        "InteractiveTable" {
            $Query | View-FileBlockShreddingInteractiveTable
            break
        }
        "Timeline" {
            $Query | View-FileBlockShreddingTimeline
            break
        }
        "TimelineList" {
            $Query | View-FileBlockShreddingTimelineList
            break
        }
    }
}

Export-ModuleMember -Function View-FileBlockShreddingSummary, View-FileBlockShreddingInteractiveTable, 
                             View-FileBlockShreddingTimeline, View-FileBlockShreddingTimelineList,
                             Investigate-FileBlockShreddingInfo 