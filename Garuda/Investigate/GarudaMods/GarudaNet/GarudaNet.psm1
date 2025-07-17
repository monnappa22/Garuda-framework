Function View-NetTimeline {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $NetEvents = @() 
    }
    Process {
        if ($Event.EventId -eq 3) {
            $NetEvents += $Event
        }
    }
    End {
        $NetEvents | Select-Object `
            UTCtime,
            @{Name="GUID"; Expression={$_.ProcessGuid}},
            @{Name="Process"; Expression={"$($_.ProcessName)($($_.ProcessId))"}},
            @{Name="Event"; Expression={"Network Connect (3)"}},
            @{Name="EventDetails"; Expression={ 
                "SourceHostname: $($_.SourceHostname) | SourceIp: $($_.SourceIp) | SourcePort: $($_.SourcePort) | DestinationIp: $($_.DestinationIp) | DestinationPort: $($_.DestinationPort) | DestinationHostname: $($_.DestinationHostname) | Protocol: $($_.Protocol) | Initiated: $($_.Initiated)"
            }} | 
            Sort-Object UTCtime | Format-Table -AutoSize -Wrap
    }
}

Function View-NetTimelineList {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $NetEvents = @() 
    }
    Process {
        if ($Event.EventId -eq 3) {
            $NetEvents += $Event
        }
    }
    End {
        $NetEvents | Select-Object `
            'UTCtime',
            'HostName',
            @{Name="User"; Expression={$_.User}},
            @{Name="Process"; Expression={
                "Image: $($_.Image) | ProcessId: $($_.ProcessId) | ProcessGuid: $($_.ProcessGuid)"
            }},
            @{Name="Event"; Expression={"Network Connect (3)"}},
            @{Name="EventDetails"; Expression={ 
                "SourceHostname: $($_.SourceHostname) | SourceIp: $($_.SourceIp) | SourcePort: $($_.SourcePort) | DestinationIp: $($_.DestinationIp) | DestinationPort: $($_.DestinationPort) | DestinationHostname: $($_.DestinationHostname) | Protocol: $($_.Protocol) | Initiated: $($_.Initiated)"
            }} |
            Sort-Object UTCtime
    }
}

function View-NetSummary {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $NetEvents = @() 
    }
    Process {
        if ($Event.EventId -eq 3) {
            $NetEvents += $Event
        }
    }
    End {
        if ($NetEvents.Count -gt 0) {
            $NetEvents | Select-Object @{
                Name = "ProcessInfo"
                Expression = { "Image: $($_.Image) | ProcessId: $($_.ProcessId) | ProcessGuid: $($_.ProcessGuid)" }
            }, UTCtime, @{
                Name = "Event"
                Expression = { "Network Connect (3)" }
            }, @{
                Name = "EventDetails"
                Expression = { "SourceHostname: $($_.SourceHostname) | SourceIp: $($_.SourceIp) | SourcePort: $($_.SourcePort) | DestinationIp: $($_.DestinationIp) | DestinationPort: $($_.DestinationPort) | DestinationHostname: $($_.DestinationHostname) | Protocol: $($_.Protocol) | Initiated: $($_.Initiated)" }
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

function View-NetInteractivetable {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $NetEvents = @() 
    }
    Process {
        if ($Event.EventId -eq 3) {
            $NetEvents += $Event
        }
    }
    end {
        # Create a view with the standard first 5 fields, then Event ID 3 specific fields
        $NetEvents | Select-Object UTCtime,
            @{Name="GUID"; Expression={ $_.ProcessGuid }},
            @{Name="Process"; Expression={ "Image: $($_.Image) | ProcessId: $($_.ProcessId) | ProcessGuid: $($_.ProcessGuid)" }},
            @{Name="Event"; Expression={ "Network Connect (3)" }},
            @{Name="EventDetails"; Expression={ 
                "SourceHostname: $($_.SourceHostname) | SourceIp: $($_.SourceIp) | SourcePort: $($_.SourcePort) | DestinationIp: $($_.DestinationIp) | DestinationPort: $($_.DestinationPort) | DestinationHostname: $($_.DestinationHostname) | Protocol: $($_.Protocol) | Initiated: $($_.Initiated)"
            }},
            # Event ID 3 specific fields
            HostName,
            ProcessGuid,
            ProcessId,
            Image,
            User,
            Protocol,
            Initiated,
            SourceIsIpv6,
            SourceIp,
            SourceHostname,
            SourcePort,
            SourcePortName,
            DestinationIsIpv6,
            DestinationIp,
            DestinationHostname,
            DestinationPort,
            DestinationPortName,
            EventId,
            EventType,
            TimeCreated,
            ProcessName,
            ProcessDir |
            Out-GridView -Title "Network Connections"
    }
}

# Below is the investigation function
function Investigate-NetworkConnections {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [parameter(Mandatory = $false, Position = 0)]
        [string] $ProcessGuid = $false,

        [parameter(Mandatory = $false)]
        [string] $ProcessName = $false,

        [parameter(Mandatory = $false)]
        [string] $Image= $false,

        [parameter(Mandatory = $false)]
        [string] $User = $false,

        [parameter(Mandatory = $false)]
        [string] $Protocol = $false,

        [parameter(Mandatory = $false)]
        [string] $SourceIp = $false,

        [parameter(Mandatory = $false)]
        [string] $SourcePort = $false,

        [parameter(Mandatory = $false)]
        [string] $DestinationIp = $false,

        [parameter(Mandatory = $false)]
        [string] $DestinationPort = $false,

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
        [ValidateSet("Detailed","Timeline","TimelineList","Summary","InteractiveTable")]
        [string] $view = "Detailed",

        [parameter(Mandatory = $false)]
        [int] $ProcessId = $false,

        [parameter(Mandatory = $false)]
        [string] $Initiated = $false,

        [parameter(Mandatory = $false)]
        [string] $SourceIsIpv6 = $false,

        [parameter(Mandatory = $false)]
        [string] $SourceHostname = $false,

        [parameter(Mandatory = $false)]
        [string] $SourcePortName = $false,

        [parameter(Mandatory = $false)]
        [string] $DestinationIsIpv6 = $false,

        [parameter(Mandatory = $false)]
        [string] $DestinationHostname = $false,

        [parameter(Mandatory = $false)]
        [string] $DestinationPortName = $false,

        [parameter(Mandatory = $false)]
        [string] $ProcessDir = $false
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
            EventId = 3
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
            $Parameters.ToLocalTime = $ToLocalTime
        }
        elseif ($FromUtcTime) {
            $Parameters.FromUtcTime = $FromUtcTime
            $Parameters.ToUtcTime = $ToUtcTime
        }
    }
    else {
        $Parameters = @{
            EventId = 3
            LogFile = $LogFile
            PastSeconds = $PastSeconds
            PastMinutes = $PastMinutes
            PastHours = $PastHours
            PastDays = $PastDays
        }

        # Add LocalTime/UTCTime parameters if specified
        if ($FromLocalTime) {
            $Parameters.FromLocalTime = $FromLocalTime
            $Parameters.ToLocalTime = $ToLocalTime
        }
        elseif ($FromUtcTime) {
            $Parameters.FromUtcTime = $FromUtcTime
            $Parameters.ToUtcTime = $ToUtcTime
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

    if ($User -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.User -like $User}
    }

    if ($Protocol -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Protocol -like $Protocol}
    }

    if ($SourceIp -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.SourceIp -like $SourceIp}
    }

    if ($SourcePort -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.SourcePort -like $SourcePort}
    }

    if ($DestinationIp -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.DestinationIp -like $DestinationIp}
    }

    if ($DestinationPort -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.DestinationPort -like $DestinationPort}
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

    if ($Initiated -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Initiated -like $Initiated}
    }

    if ($SourceIsIpv6 -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.SourceIsIpv6 -like $SourceIsIpv6}
    }

    if ($SourceHostname -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.SourceHostname -like $SourceHostname}
    }

    if ($SourcePortName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.SourcePortName -like $SourcePortName}
    }

    if ($DestinationIsIpv6 -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.DestinationIsIpv6 -like $DestinationIsIpv6}
    }

    if ($DestinationHostname -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.DestinationHostname -like $DestinationHostname}
    }

    if ($DestinationPortName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.DestinationPortName -like $DestinationPortName}
    }

    if ($ProcessDir -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.ProcessDir -like $ProcessDir}
    }

    $Query = $BaseQuery
    
    # Displaying results based on the chosen views
    switch ($view) {
        "Detailed" { 
            $Query
            break
        }
        "Timeline" {
            $Query | View-NetTimeline
            break
        }
        "TimelineList" {
            $Query | View-NetTimelineList
            break
        }
        "Summary" {
            $Query | View-NetSummary
            break
        }
        "InteractiveTable" {
             $Query | View-NetInteractivetable
            break
        }
    }
}

# Export module members
Export-ModuleMember -Function @(
    'Investigate-NetworkConnections',
    'View-NetTimeline',
    'View-NetTimelineList',
    'View-NetSummary',
    'View-NetInteractivetable'
)
