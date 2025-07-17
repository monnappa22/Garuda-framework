function View-ProcSummary {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ProcEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 1) {
            $ProcEvents += $Event
        }
    }
    End {
        if ($ProcEvents.Count -gt 0) {
            $ProcEvents | Select-Object @{
                Name = "ProcessInfo"
                Expression = { 
                    "ParentImage: $($_.ParentImage) | ParentProcessId: $($_.ParentProcessId) | ParentProcessGuid: $($_.ParentProcessGuid)"
                }
            }, UTCtime, @{
                Name = "Event"
                Expression = { "Process Create (1)" }
            }, @{
                Name = "EventDetails"
                Expression = { 
                    if ($_.CommandLine) {
                        "Image: $($_.Image) | ProcessId: $($_.ProcessId) | ProcessGuid: $($_.ProcessGuid) | CommandLine: $($_.CommandLine)"
                    } else {
                        "Image: $($_.Image) | ProcessId: $($_.ProcessId) | ProcessGuid: $($_.ProcessGuid)"
                    }
                }
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

function View-ProcInteractivetable {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ProcEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 1) {
            $ProcEvents += $Event
        }
    }
    end {
        # Create a custom view with the standard first 5 fields, then Process Create (Event ID 1) relevant fields
        $ProcEvents | Select-Object UTCtime,
            @{Name="GUID"; Expression={ $_.ParentProcessGuid }},
            @{Name="Process"; Expression={ 
                if ($_.ParentCommandLine) {
                    "ParentImage: $($_.ParentImage) | ParentProcessId: $($_.ParentProcessId) | ParentProcessGuid: $($_.ParentProcessGuid) | ParentCommandLine: $($_.ParentCommandLine)"
                } else {
                    "ParentImage: $($_.ParentImage) | ParentProcessId: $($_.ParentProcessId) | ParentProcessGuid: $($_.ParentProcessGuid)"
                }
            }},
            @{Name="Event"; Expression={ "Process Create (1)" }},
            @{Name="EventDetails"; Expression={ 
                "Image: $($_.Image) | ProcessId: $($_.ProcessId) | ProcessGuid: $($_.ProcessGuid) | CommandLine: $($_.CommandLine) | IntegrityLevel: $($_.IntegrityLevel)"
            }},
            # Event ID 1 specific fields
            HostName,
            EventId,
            EventType,
            ProcessGuid,
            ProcessId,
            Image,
            FileVersion,
            Description, 
            Product,
            Company,
            OriginalFileName,
            CommandLine,
            CurrentDirectory,
            User,
            LogonGuid,
            LogonId,
            TerminalSessionId,
            IntegrityLevel,
            Hashes,
            ParentProcessGuid,
            ParentProcessId,
            ParentImage,
            ParentCommandLine,
            MD5,
            SHA256,
            SHA1,
            IMPHASH,
            TimeCreated,
            ProcessName,
            ProcessDir,
            ParentProcessName,
            ParentProcessDir |
            Out-GridView -Title "Process Creation Information"
    }
}

    
function View-ProcMetaData {

    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event,

        [parameter(Mandatory = $false, Position = 0)]
        [string] $ProcGuid = $false
    )

    Begin {

        $ProcEvents = @()
    }

    process {

        if ($Event.EventId -eq 1) {

            if ($ProcGuid -eq $false) {

                $ProcEvents += $Event

            }
            else {
                $TrimProcGuid = $ProcGuid.tostring().trimstart("{").trimend("}")
                $ProcGuid = "{0}{1}{2}" -f '{', $TrimProcGuid, '}'
                $ProcEvents += $Event | where-object { $_.ProcessGuid -eq $ProcGuid.ToString()}
            }
            
        }
    }
    
    end {
            $ProcEvents | Select-Object FileVersion,Description,Company, OriginalFileName, `
            @{Name="Process";Expression = {"{0} {1}"-f $_.ProcessName, $_.ProcessGuid}},Image | sort-object Process `
            | format-list FileVersion,Description,Company,OriginalFileName,Image -GroupBy Process | Out-String -stream `
            | ForEach-Object {

                if ($_ -match "Process:.*") {
                    write-host $_ -ForegroundColor Cyan
                }
                else {
                    write-host $_
                }
            
            }

    }
    
} 

Function View-ProcToken {

    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event,

        [parameter(Mandatory = $false, Position = 0)]
        [string] $ProcGuid = $false
    )

    Begin {

        $ProcEvents = @()
    }


    process {

        if ($Event.EventId -eq 1) {

            if ($ProcGuid -eq $false) {

                $ProcEvents += $Event
            }

            else {
                $TrimProcGuid = $ProcGuid.tostring().trimstart("{").trimend("}")
                $ProcGuid = "{0}{1}{2}" -f '{', $TrimProcGuid, '}'
                $ProcEvents += $Event | where-object { $_.ProcessGuid -eq $ProcGuid.ToString()}
            }
        }
    }

    end {

        $ProcEvents | select-object User,LogonId,LogonGuid,TerminalSessionId,IntegrityLevel,Image, `
        @{Name="Process"; Expression = {"{0} {1}" -f $_.ProcessName,$_.ProcessGuid}} | Sort-Object Process `
        | Format-List User,LogonId,LogonGuid,TerminalSessionId,IntegrityLevel,Image -GroupBy Process | Out-String -stream `
        | ForEach-Object {

            if ($_ -match "Process:.*") {
                write-host $_ -ForegroundColor Cyan
            }
            else {
                write-host $_
            }
        
        }
    }
}

Function View-ProcHashes {

    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event,

        [parameter(Mandatory = $false)]
        [string] $MD5 = $false,

        [parameter(Mandatory = $false)]
        [string] $SHA256 = $false,

        [parameter(Mandatory = $false)]
        [string] $SHA1 = $false
    )

    Begin {

        $ProcEvents = @()
    }

    Process {
        If ($Event.EventId -eq 1) {

            if ($MD5 -ne $false) {
                $ProcEvents += $Event | where-object { $_.MD5 -eq $MD5 }
            }
            elseif ($SHA256 -ne $false) {
                $ProcEvents += $Event | where-object { $_.SHA256 -eq $SHA256 }
            }
            elseif ($SHA1 -ne $false) {
                $ProcEvents += $Event | where-object { $_.SHA1 -eq $SHA1 }
            }
            else {
                $ProcEvents += $Event
            }
        }
        
    }
    end {

        $ProcEvents | Select-Object MD5,SHA256,SHA1,Hashes,Image, `
        @{Name="Process"; Expression = {"{0} {1}" -f $_.ProcessName,$_.ProcessGuid}} | Sort-Object Process `
        | Format-List MD5,SHA256,SHA1,Hashes,Image -GroupBy Process | Out-String -stream `
        |  ForEach-Object {

            if ($_ -match "Process:.*") {
                write-host $_ -ForegroundColor Cyan
            }
            else {
                write-host $_
            }
        
        }

    }
}


function View-ProcTimeline {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ProcEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 1) {
            $ProcEvents += $Event
        }
    }
    End {
        $ProcEvents | Select-Object `
            UTCtime,
            @{Name="GUID"; Expression={ $_.ParentProcessGuid }},
            @{Name="Process"; Expression={ "$($_.ParentProcessName)($($_.ParentProcessId))" }},
            @{Name="Event"; Expression={ "Process Creation (1)" }},
            @{Name="EventDetails"; Expression={ 
                "Image: $($_.Image) | ProcessId: $($_.ProcessId) | ProcessGuid: $($_.ProcessGuid) | CommandLine: $($_.CommandLine)" 
            }} | 
            Sort-Object UTCtime | Format-Table -AutoSize -Wrap
    }
}

function View-ProcTimelineList {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ProcEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 1) {
            $ProcEvents += $Event
        }
    }
    End {
        $ProcEvents | Select-Object `
            UTCtime,
            HostName,
            User,
            @{Name="Process"; Expression={ 
                if ($_.ParentCommandLine) {
                    "ParentImage: $($_.ParentImage) | ParentProcessId: $($_.ParentProcessId) | ParentProcessGuid: $($_.ParentProcessGuid) | ParentCommandLine: $($_.ParentCommandLine)"
                } else {
                    "ParentImage: $($_.ParentImage) | ParentProcessId: $($_.ParentProcessId) | ParentProcessGuid: $($_.ParentProcessGuid)"
                }
            }},
            @{Name="Event"; Expression={ "Process Creation (1)" }},
            @{Name="EventDetails"; Expression={ 
                "Image: $($_.Image) | ProcessId: $($_.ProcessId) | ProcessGuid: $($_.ProcessGuid) | CommandLine: $($_.CommandLine) | IntegrityLevel: $($_.IntegrityLevel)"
            }},
            Hashes | 
            Sort-Object UTCtime | Format-List
    }
}

# Below is the investigation function
function Investigate-ProcInfo {

    [CmdletBinding(PositionalBinding = $false)]
    param (
        [parameter(Mandatory = $false, Position = 0)]
        [string] $ProcessGuid = $false,

        [parameter(Mandatory = $false)]
        [string] $ParentProcessGuid = $false,

        [parameter(Mandatory = $false)]
        [string] $LogonGuid = $false,

        [parameter(Mandatory = $false)]
        [string] $ProcessName = $false,

        [parameter(Mandatory = $false)]
        [string] $ParentProcessName= $false,

        [parameter(Mandatory = $false)]
        [string] $CommandLine = $false,

        [parameter(Mandatory = $false)]
        [string] $Image= $false,

        [parameter(Mandatory = $false)]
        [string] $ParentImage = $false,

        [parameter(Mandatory = $false)]
        [string] $User = $false,

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
        [string] $IMPHASH = $false,

        [parameter(Mandatory = $false)]
        [string] $FileVersion = $false,

        [parameter(Mandatory = $false)]
        [string] $Description = $false,

        [parameter(Mandatory = $false)]
        [string] $Product = $false,

        [parameter(Mandatory = $false)]
        [string] $Company = $false,

        [parameter(Mandatory = $false)]
        [string] $OriginalFileName = $false,

        [parameter(Mandatory = $false)]
        [string] $CurrentDirectory = $false,

        [parameter(Mandatory = $false)]
        [string] $LogonId = $false,

        [parameter(Mandatory = $false)]
        [int] $TerminalSessionId = $false,

        [parameter(Mandatory = $false)]
        [string] $IntegrityLevel = $false,

        [parameter(Mandatory = $false)]
        [string] $ParentUser = $false,

        [parameter(Mandatory = $false)]
        [int] $ProcessId = $false,

        [parameter(Mandatory = $false)]
        [int] $ParentProcessId = $false,

        [parameter(Mandatory = $false)]
        [string] $ParentCommandLine = $false,

        [parameter(Mandatory = $false)]
        [string] $MD5 = $false,

        [parameter(Mandatory = $false)]
        [string] $SHA256 = $false,

        [parameter(Mandatory = $false)]
        [string] $SHA1 = $false,

        [parameter(Mandatory = $false)]
        [string] $ProcessDir = $false,

        [parameter(Mandatory = $false)]
        [string] $ParentProcessDir = $false,

        [parameter(Mandatory = $false)]
        [string] $Hashes = $false,

        [parameter(Mandatory = $false)]
        [ValidateSet("Detailed","Summary","InteractiveTable", "Metadata", "Token", "Hashes", "Timeline", "TimelineList")]
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
            EventId = 1
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
            EventId = 1
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
    
    if ($ProcessGuid -ne $false) {
        $TrimProcessGuid = $ProcessGuid.tostring().trimstart("{").trimend("}")
        $ProcessGuid = "{0}{1}{2}" -f '{', $TrimProcessGuid, '}'
        $BaseQuery = $BaseQuery | Where-Object {$_.ProcessGuid -eq $ProcessGuid.ToString()}
    }

    if ($LogonGuid -ne $false) {
        
        $TrimLogonGuid = $LogonGuid.tostring().trimstart("{").trimend("}")
        $LogonGuid = "{0}{1}{2}" -f '{', $TrimLogonGuid, '}'
        $BaseQuery = $BaseQuery | Where-Object {$_.LogonGuid -eq $LogonGuid.ToString()}
    }

    if ($ParentProcessGuid -ne $false) {
        
        $TrimParentProcessGuid = $ParentProcessGuid.tostring().trimstart("{").trimend("}")
        $ParentProcessGuid = "{0}{1}{2}" -f '{', $TrimParentProcessGuid, '}'
        $BaseQuery = $BaseQuery | Where-Object {$_.ParentProcessGuid -eq $ParentProcessGuid.ToString()}
    }

    if ($ProcessName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.ProcessName -like $ProcessName}
    }

    if ($ParentProcessName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.ParentProcessName -like $ParentProcessName}
    }

    if ($CommandLine -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.CommandLine -like $CommandLine}
    }

    if ($Image -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Image -like $Image}
    }

    if ($ParentImage -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.ParentImage -like $ParentImage}
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

    if ($IMPHASH -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.IMPHASH -like $IMPHASH}
    }

    if ($FileVersion -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.FileVersion -like $FileVersion}
    }

    if ($Description -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Description -like $Description}
    }

    if ($Product -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Product -like $Product}
    }

    if ($Company -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Company -like $Company}
    }

    if ($OriginalFileName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.OriginalFileName -like $OriginalFileName}
    }

    if ($CurrentDirectory -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.CurrentDirectory -like $CurrentDirectory}
    }

    if ($LogonId -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.LogonId -like $LogonId}
    }

    if ($TerminalSessionId -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.TerminalSessionId -eq $TerminalSessionId}
    }

    if ($IntegrityLevel -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.IntegrityLevel -like $IntegrityLevel}
    }

    if ($ParentUser -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.ParentUser -like $ParentUser}
    }

    if ($ProcessId -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.ProcessId -eq $ProcessId}
    }

    if ($ParentProcessId -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.ParentProcessId -eq $ParentProcessId}
    }

    if ($ParentCommandLine -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.ParentCommandLine -like $ParentCommandLine}
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

    if ($ProcessDir -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.ProcessDir -like $ProcessDir}
    }

    if ($ParentProcessDir -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.ParentProcessDir -like $ParentProcessDir}
    }

    if ($Hashes -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Hashes -like $Hashes}
    }

    $Query = $BaseQuery
    
    # Displaying results based on the chosen views

    switch ($View) {

        "Detailed" { 
            $Query
            break
        }

        "Summary" {
            $Query | View-ProcSummary
            break
        }
        
        "InteractiveTable" {
             $Query | View-ProcInteractivetable
            break
        }

        "Metadata" {
            $Query | View-ProcMetaData
            break
        }

        "Token" {
            $Query | View-ProcToken
            break
        }

        "Hashes" {
            $Query | View-ProcHashes
            break
        }

        "Timeline" {
            $Query | View-ProcTimeline
            break
        }

        "TimelineList" {
            $Query | View-ProcTimelineList
            break
        }
    }
}
