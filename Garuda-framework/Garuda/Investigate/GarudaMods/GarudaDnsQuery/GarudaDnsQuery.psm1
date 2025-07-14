#
# Module: GarudaDnsQuery
# Description: Module for investigating DNS query events (Event ID 22)
#

#region View Functions

function View-DnsQuerySummary {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    
    Begin {
        $DnsEvents = @()
    }
    
    Process {
        If ($Event.EventId -eq 22) {
            $DnsEvents += $Event
        }
    }
    
    End {
        $DnsEvents | select-object UtcTime, User, QueryName, QueryResults, QueryStatus,
            @{Name = "Process"; Expression = { "{0} (PID: {1}) - {2}" -f $_.ProcessName, $_.ProcessId, $_.ProcessGuid } } |
        sort-object Process | Format-Table UtcTime, User, QueryName, QueryResults, QueryStatus -GroupBy Process -Autosize -Wrap |
        Out-String -stream | ForEach-Object {
            if ($_ -match "Process:.*") {
                write-host $_ -ForegroundColor green
            }
            else {
                write-host $_
            }
        }
    }
}

function View-DnsQueryInteractiveTable {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    
    Begin {
        $DnsEvents = @()
    }
    
    Process {
        If ($Event.EventId -eq 22) {
            $DnsEvents += $Event
        }
    }
    
    End {
        $DnsEvents | Select-Object UTCtime,
            @{Name="GUID"; Expression={ $_.ProcessGuid }},
            @{Name="Process"; Expression={ $_.Image }},
            @{Name="Event"; Expression={ "DNS Query (22)" }},
            @{Name="EventDetails"; Expression={ "$($_.QueryName) [$($_.QueryResults)] [Status: $($_.QueryStatus)]" }},
            # Event identification
            EventId,
            EventType,
            # Host and user information
            HostName,
            User,
            # Process-related fields
            ProcessGuid,
            ProcessId,
            Image,
            ProcessName,
            ProcessDir,
            # DNS Query specific fields
            QueryName,
            QueryStatus,
            QueryResults,
            # Time-related fields
            TimeCreated |
            Out-GridView -Title "DNS Query Events"
    }
}

function View-DnsQueryTimeline {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    
    Begin {
        $DnsEvents = @()
    }
    
    Process {
        If ($Event.EventId -eq 22) {
            $DnsEvents += $Event
        }
    }
    
    End {
        $DnsEvents | Select-Object `
            UTCtime,
            ProcessGuid,
            @{Name="Process"; Expression={ $_.ProcessName }},
            @{Name="Event"; Expression={ "DNS Query (22)" }},
            @{Name="EventDetails"; Expression={ "$($_.QueryName) [$($_.QueryResults)] [Status: $($_.QueryStatus)]" }} | 
            Sort-Object UTCtime | Format-Table -AutoSize -Wrap
    }
}

function View-DnsQueryTimelineList {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    
    Begin {
        $DnsEvents = @()
    }
    
    Process {
        If ($Event.EventId -eq 22) {
            $DnsEvents += $Event
        }
    }
    
    End {
        $DnsEvents | Select-Object `
            UTCtime,
            HostName,
            User,
            @{Name="ProcessId"; Expression={ $_.ProcessId }},
            @{Name="Process"; Expression={ "$($_.Image) [$($_.ProcessGuid)]" }},
            @{Name="Event"; Expression={ "DNS Query (22)" }},
            @{Name="EventDetails"; Expression={ "$($_.QueryName) [$($_.QueryResults)] [Status: $($_.QueryStatus)]" }} | 
            Sort-Object UTCtime | Format-List
    }
}

#endregion View Functions

#region Investigation Functions

function Investigate-DnsQueryInfo {
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
        [string] $QueryName = $false,
        
        [parameter(Mandatory = $false)]
        [string] $QueryStatus = $false,
        
        [parameter(Mandatory = $false)]
        [string] $QueryResults = $false,
        
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
    if (($FromLocalTime -and $FromUtcTime) -or ($ToLocalTime -and $ToUtcTime)) {
        Write-Error "Cannot mix LocalTime and UtcTime parameters"
        return
    }
    
    # Set default ToLocalTime if FromLocalTime is provided but ToLocalTime is not
    if ($FromLocalTime -and -not $ToLocalTime) {
        $ToLocalTime = Get-Date
    }
    
    # Set default ToUtcTime if FromUtcTime is provided but ToUtcTime is not
    if ($FromUtcTime -and -not $ToUtcTime) {
        $ToUtcTime = (Get-Date).ToUniversalTime()
    }
    
    # Calculate time range from PastSeconds, PastMinutes, PastHours, PastDays
    if ($PastSeconds -or $PastMinutes -or $PastHours -or $PastDays) {
        $ToLocalTime = Get-Date
        $timespan = New-TimeSpan -Seconds $PastSeconds -Minutes $PastMinutes -Hours $PastHours -Days $PastDays
        $FromLocalTime = $ToLocalTime - $timespan
    }
    
    # Common parameters for event source
    $BaseParams = @{
        ID = 22
    }
    
    # Parameters for querying logs
    if ($PSCmdlet.ParameterSetName -eq "EventLogs") {
        $BaseParams['LogName'] = "Microsoft-Windows-Sysmon/Operational"
        if ($ComputerName -and $ComputerName -ne $Env:COMPUTERNAME) {
            $BaseParams['ComputerName'] = $ComputerName
        }
        if ($Credential) {
            $BaseParams['Credential'] = $Credential
        }
    }
    else {
        # Reading from log file
        $BaseParams['Path'] = $LogFile
    }
    
    # Filter by time if specified
    if ($FromLocalTime -and $ToLocalTime) {
        $BaseParams['StartTime'] = $FromLocalTime
        $BaseParams['EndTime'] = $ToLocalTime
    }
    
    # Query for events
    try {
        if ($PSCmdlet.ParameterSetName -eq "EventLogs") {
            $BaseQuery = Get-WinEvent -FilterHashtable $BaseParams -ErrorAction Stop | ConvertTo-GarudaObjects
        }
        else {
            $BaseQuery = Get-WinEvent -FilterHashtable $BaseParams -ErrorAction Stop | ConvertTo-GarudaObjects
        }
    }
    catch {
        Write-Error "Failed to retrieve events: $_"
        return
    }
    
    # Apply filters
    if ($ProcessName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object { $_.ProcessName -like "*$ProcessName*" }
    }
    
    if ($ProcessId -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object { $_.ProcessId -eq $ProcessId }
    }
    
    if ($ProcessGuid -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object { $_.ProcessGuid -like "*$ProcessGuid*" }
    }
    
    if ($Image -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object { $_.Image -like "*$Image*" }
    }
    
    if ($ProcessDir -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object { $_.ProcessDir -like "*$ProcessDir*" }
    }
    
    if ($QueryName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object { $_.QueryName -like "*$QueryName*" }
    }
    
    if ($QueryStatus -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object { $_.QueryStatus -eq $QueryStatus }
    }
    
    if ($QueryResults -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object { $_.QueryResults -like "*$QueryResults*" }
    }
    
    if ($User -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object { $_.User -like "*$User*" }
    }
    
    if ($UtcTime -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object { $_.UtcTime -like "*$UtcTime*" }
    }
    
    if ($HostName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object { $_.HostName -like "*$HostName*" }
    }
    
    $Query = $BaseQuery
    
    # Return results in the specified view
    switch ($View) {
        "Detailed" { 
            $Query
            break
        }
        "Summary" {
            $Query | View-DnsQuerySummary
            break
        }
        "InteractiveTable" {
            $Query | View-DnsQueryInteractiveTable
            break
        }
        "Timeline" {
            $Query | View-DnsQueryTimeline
            break
        }
        "TimelineList" {
            $Query | View-DnsQueryTimelineList
            break
        }
    }
}

#endregion Investigation Functions

# Export module members
Export-ModuleMember -Function View-DnsQuerySummary, View-DnsQueryInteractiveTable, 
                             View-DnsQueryTimeline, View-DnsQueryTimelineList,
                             Investigate-DnsQueryInfo 