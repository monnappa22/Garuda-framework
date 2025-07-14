# Module: GarudaProcessTampering
# Description: Module for investigating process tampering events (Event ID 25)
# Author: Garuda Team

#region View Functions

Function View-ProcessTamperingInfo {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Process {
        If ($Event.EventId -eq 25) {
            $Event | Select-Object EventId, EventType, HostName, UTCtime, `
            ProcessGuid, ProcessId, Image, Type, User, `
            @{Name="ProcessInfo"; Expression={"Process: {0} ({1}) - Tampering Type: {2}" `
             -f $_.HollowedProcessName, $_.ProcessId, $_.Type}}
        }
    }
}

function View-ProcessTamperingSummary {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ProcessTamperingEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 25) {
            $ProcessTamperingEvents += $Event
        }
    }
    end {
        $ProcessTamperingEvents | select-object UTCtime, User, Type, Image, `
            @{Name = "Process"; Expression = { "PID: $($_.ProcessId) [$($_.ProcessGuid)]" } } `
        | sort-object Process | Format-Table UTCtime, User, Type, Image -GroupBy Process -Autosize -Wrap `
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

function View-ProcessTamperingInteractiveTable {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ProcessTamperingEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 25) {
            $ProcessTamperingEvents += $Event
        }
    }
    end {
        $ProcessTamperingEvents | Select-Object UTCtime,
            @{Name="GUID"; Expression={ $_.ProcessGuid }},
            @{Name="Process"; Expression={ $_.Image }},
            @{Name="Event"; Expression={ "Process Tampering (25)" }},
            @{Name="EventDetails"; Expression={ "$($_.Image) - [$($_.Type)]" }},
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
            # Process Tampering specific fields
            Type,
            HollowedProcessName,
            HollowedProcessDir,
            # Time-related fields
            TimeCreated |
            Out-GridView -Title "Process Tampering Information"
    }
}

function View-ProcessTamperingTimeline {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ProcessTamperingEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 25) {
            $ProcessTamperingEvents += $Event
        }
    }
    end {
        $ProcessTamperingEvents | Select-Object `
            UTCtime,
            ProcessGuid,
            ProcessId,
            @{Name="Event"; Expression={ "Process Tampering (25)" }},
            @{Name="EventDetails"; Expression={ "$($_.Image) - [$($_.Type)]" }} | 
            Sort-Object UTCtime | Format-Table -AutoSize -Wrap
    }
}

function View-ProcessTamperingTimelineList {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ProcessTamperingEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 25) {
            $ProcessTamperingEvents += $Event
        }
    }
    end {
        $ProcessTamperingEvents | Select-Object `
            UTCtime,
            HostName,
            User,
            ProcessId,
            ProcessGuid,
            @{Name="Event"; Expression={ "Process Tampering (25)" }},
            @{Name="EventDetails"; Expression={ "$($_.Image) - [$($_.Type)]" }} | 
            Sort-Object UTCtime | Format-List
    }
}

#endregion View Functions

#region Investigation Functions

function Investigate-ProcessTamperingInfo {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [parameter(Mandatory = $false)]
        [string] $HollowedProcessName = $false,

        [parameter(Mandatory = $false)]
        [string] $HollowedProcessDir = $false,

        [parameter(Mandatory = $false)]
        [string] $ProcessId = $false,

        [parameter(Mandatory = $false)]
        [string] $ProcessGuid = $false,

        [parameter(Mandatory = $false)]
        [string] $Image = $false,

        [parameter(Mandatory = $false)]
        [string] $Type = $false,

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
            EventId = 25
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
            EventId = 25
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

    # Apply filters based on parameters
    if ($ProcessGuid -ne $false) {
        $TrimProcessGuid = $ProcessGuid.tostring().trimstart("{").trimend("}")
        $ProcessGuid = "{0}{1}{2}" -f '{', $TrimProcessGuid, '}'
        $BaseQuery = $BaseQuery | Where-Object {$_.ProcessGuid -eq $ProcessGuid.ToString()}
    }

    if ($HollowedProcessName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.HollowedProcessName -like $HollowedProcessName}
    }

    if ($HollowedProcessDir -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.HollowedProcessDir -like $HollowedProcessDir}
    }

    if ($ProcessId -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.ProcessId -eq $ProcessId}
    }

    if ($Image -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Image -like $Image}
    }

    if ($Type -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Type -like $Type}
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
    
    # Displaying results based on the chosen views
    switch ($View) {
        "Detailed" { 
            $Query
            break
        }
        "Summary" {
            $Query | View-ProcessTamperingSummary
            break
        }
        "InteractiveTable" {
             $Query | View-ProcessTamperingInteractiveTable
            break
        }
        "Timeline" {
             $Query | View-ProcessTamperingTimeline
            break
        }
        "TimelineList" {
             $Query | View-ProcessTamperingTimelineList
            break
        }
    }
}

#endregion Investigation Functions

# Export functions
Export-ModuleMember -Function @(
    'View-ProcessTamperingInfo',
    'View-ProcessTamperingSummary',
    'View-ProcessTamperingInteractiveTable',
    'View-ProcessTamperingTimeline',
    'View-ProcessTamperingTimelineList',
    'Investigate-ProcessTamperingInfo'
) 