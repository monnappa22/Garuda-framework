#
# Module: GarudaClipboardChange
# Description: Module for investigating Clipboard Change events (Event ID 24)
#

#region View Functions

function View-ClipboardChangeSummary {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    
    Begin {
        $ClipboardEvents = @()
    }
    
    Process {
        If ($Event.EventId -eq 24) {
            $ClipboardEvents += $Event
        }
    }
    
    End {
        $ClipboardEvents | select-object UtcTime, User, ClientInfo, Archived,
            @{Name = "Process"; Expression = { "{0} (PID: {1}) - {2}" -f $_.ProcessName, $_.ProcessId, $_.ProcessGuid } } |
        sort-object Process | Format-Table UtcTime, User, ClientInfo, Archived -GroupBy Process -Autosize -Wrap |
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

function View-ClipboardChangeInteractiveTable {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    
    Begin {
        $ClipboardEvents = @()
    }
    
    Process {
        If ($Event.EventId -eq 24) {
            $ClipboardEvents += $Event
        }
    }
    
    End {
        $ClipboardEvents | Select-Object UTCtime,
            @{Name="GUID"; Expression={ $_.ProcessGuid }},
            @{Name="Process"; Expression={ $_.Image }},
            @{Name="Event"; Expression={ "Clipboard Change (24)" }},
            @{Name="EventDetails"; Expression={ "$($_.ClientInfo) [Archived: $($_.Archived)]" }},
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
            # Clipboard Change specific fields
            Session,
            ClientInfo,
            Archived,
            # Hash fields
            Hashes,
            MD5,
            SHA256,
            IMPHASH,
            # Time-related fields
            TimeCreated |
            Out-GridView -Title "Clipboard Change Events"
    }
}

function View-ClipboardChangeTimeline {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    
    Begin {
        $ClipboardEvents = @()
    }
    
    Process {
        If ($Event.EventId -eq 24) {
            $ClipboardEvents += $Event
        }
    }
    
    End {
        $ClipboardEvents | Select-Object `
            UTCtime,
            @{Name="GUID"; Expression={ $_.ProcessGuid }},
            @{Name="Process"; Expression={ $_.ProcessName }},
            @{Name="Event"; Expression={ "Clipboard Change (24)" }},
            @{Name="EventDetails"; Expression={ "$($_.ClientInfo) [Archived: $($_.Archived)]" }} | 
            Sort-Object UTCtime | Format-Table -AutoSize -Wrap
    }
}

function View-ClipboardChangeTimelineList {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    
    Begin {
        $ClipboardEvents = @()
    }
    
    Process {
        If ($Event.EventId -eq 24) {
            $ClipboardEvents += $Event
        }
    }
    
    End {
        $ClipboardEvents | Select-Object `
            UTCtime,
            HostName,
            User,
            ProcessId,
            @{Name="Process"; Expression={ "$($_.Image) [$($_.ProcessGuid)]" }},
            @{Name="Event"; Expression={ "Clipboard Change (24)" }},
            @{Name="EventDetails"; Expression={ "$($_.ClientInfo) [Archived: $($_.Archived)]" }},
            Hashes | 
            Sort-Object UTCtime
    }
}

#endregion View Functions

#region Investigation Functions

function Investigate-ClipboardChangeInfo {
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
        [string] $Session = $false,
        
        [parameter(Mandatory = $false)]
        [string] $ClientInfo = $false,
        
        [parameter(Mandatory = $false)]
        [string] $Archived = "",
        
        [parameter(Mandatory = $false)]
        [string] $User = $false,
        
        [parameter(Mandatory = $false)]
        [string] $UtcTime = $false,
        
        [parameter(Mandatory = $false)]
        [string] $HostName = $false,
        
        [parameter(Mandatory = $false)]
        [string] $Hashes = $false,
        
        [parameter(Mandatory = $false)]
        [string] $MD5 = $false,
        
        [parameter(Mandatory = $false)]
        [string] $SHA256 = $false,
        
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

    # Build parameters for Get-SysmonRawEvents
    $Parameters = @{
        EventId = 24
        PastSeconds = $PastSeconds
        PastMinutes = $PastMinutes
        PastHours = $PastHours
        PastDays = $PastDays
    }

    # Add time range parameters if specified
    if ($FromLocalTime) { $Parameters.FromLocalTime = $FromLocalTime }
    if ($ToLocalTime) { $Parameters.ToLocalTime = $ToLocalTime }
    if ($FromUtcTime) { $Parameters.FromUtcTime = $FromUtcTime }
    if ($ToUtcTime) { $Parameters.ToUtcTime = $ToUtcTime }

    # Add computer name and credential if specified
    if ($ComputerName) { $Parameters.ComputerName = $ComputerName }
    if ($Credential) { $Parameters.Credential = $Credential }

    # Add log file if specified
    if ($LogFile) { $Parameters.LogFile = $LogFile }

    try {
        $BaseQuery = Get-SysmonRawEvents @Parameters | ConvertTo-GarudaObjects
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
    
    if ($Session -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object { $_.Session -like "*$Session*" }
    }
    
    if ($ClientInfo -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object { $_.ClientInfo -like "*$ClientInfo*" }
    }
    
    if ($Archived -ne "") {
        $BaseQuery = $BaseQuery | Where-Object { $_.Archived -like $Archived }
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
    
    if ($Hashes -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object { $_.Hashes -like "*$Hashes*" }
    }
    
    if ($MD5 -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object { $_.MD5 -like "*$MD5*" }
    }
    
    if ($SHA256 -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object { $_.SHA256 -like "*$SHA256*" }
    }
    
    if ($IMPHASH -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object { $_.IMPHASH -like "*$IMPHASH*" }
    }
    
    $Query = $BaseQuery
    
    # Return results in the specified view
    switch ($View) {
        "Detailed" { 
            $Query
            break
        }
        "Summary" {
            $Query | View-ClipboardChangeSummary
            break
        }
        "InteractiveTable" {
            $Query | View-ClipboardChangeInteractiveTable
            break
        }
        "Timeline" {
            $Query | View-ClipboardChangeTimeline
            break
        }
        "TimelineList" {
            $Query | View-ClipboardChangeTimelineList
            break
        }
    }
}

#endregion Investigation Functions

# Export module members
Export-ModuleMember -Function View-ClipboardChangeSummary, View-ClipboardChangeInteractiveTable, 
                             View-ClipboardChangeTimeline, View-ClipboardChangeTimelineList,
                             Investigate-ClipboardChangeInfo 