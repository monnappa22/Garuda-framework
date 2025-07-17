function View-ImageLoadTimeline {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ImageLoadEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 7) {
            $ImageLoadEvents += $Event
        }
    }
    End {
        $ImageLoadEvents | Select-Object `
            UTCtime,
            @{Name="GUID"; Expression={$_.ProcessGuid}},
            @{Name="Process"; Expression={"$($_.ProcessName)($($_.ProcessId))"}},
            @{Name="Event"; Expression={ "Image Load (7)" }},
            @{Name="EventDetails"; Expression={ 
                if ($_.Signed) {
                    "ImageLoaded: $($_.ImageLoaded) | Signed: $($_.Signed) | Status: $($_.SignatureStatus) | Signature: $($_.Signature)"
                } else {
                    "ImageLoaded: $($_.ImageLoaded)"
                }
            }} | 
            Sort-Object UTCtime | Format-Table -AutoSize -Wrap
    }
}

function View-ImageLoadTimelineList {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ImageLoadEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 7) {
            $ImageLoadEvents += $Event
        }
    }
    End {
        $ImageLoadEvents | Select-Object `
            UTCtime,
            HostName,
            User,
            @{Name="Process"; Expression={ "Image: $($_.Image) | ProcessId: $($_.ProcessId) | ProcessGuid: $($_.ProcessGuid)" }},
            @{Name="Event"; Expression={ "Image Load (7)" }},
            @{Name="EventDetails"; Expression={ 
                if ($_.Signed) {
                    "ImageLoaded: $($_.ImageLoaded) | Signed: $($_.Signed) | Status: $($_.SignatureStatus) | Signature: $($_.Signature)"
                } else {
                    "ImageLoaded: $($_.ImageLoaded)"
                }
            }},
            Hashes | 
            Sort-Object UTCtime
    }
}

function View-ImageLoadSummary {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ImageLoadEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 7) {
            $ImageLoadEvents += $Event
        }
    }
    end {
        $ImageLoadEvents | Select-Object `
            @{Name = "ProcessInfo"; Expression = { "Image: $($_.Image) | ProcessId: $($_.ProcessId) | ProcessGuid: $($_.ProcessGuid)" }},
            UTCtime,
            @{Name = "Event"; Expression = { "Image Load (7)" }},
            @{Name = "EventDetails"; Expression = { 
                if ($_.Signed) {
                    "ImageLoaded: $($_.ImageLoaded) | Signed: $($_.Signed) | Status: $($_.SignatureStatus) | Signature: $($_.Signature)"
                } else {
                    "ImageLoaded: $($_.ImageLoaded)"
                }
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

function View-ImageLoadInteractiveTable {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event
    )
    Begin { 
        $ImageLoadEvents = @() 
    }
    Process {
        If ($Event.EventId -eq 7) {
            $ImageLoadEvents += $Event
        }
    }
    end {
        # Create a view with the standard first 5 fields, then Event ID 7 specific fields
        $ImageLoadEvents | Select-Object UTCtime,
            @{Name="GUID"; Expression={ $_.ProcessGuid }},
            @{Name="Process"; Expression={ "Image: $($_.Image) | ProcessId: $($_.ProcessId) | ProcessGuid: $($_.ProcessGuid)" }},
            @{Name="Event"; Expression={ "Image Load (7)" }},
            @{Name="EventDetails"; Expression={ 
                if ($_.Signed) {
                    "ImageLoaded: $($_.ImageLoaded) | Signed: $($_.Signed) | Status: $($_.SignatureStatus) | Signature: $($_.Signature)"
                } else {
                    "ImageLoaded: $($_.ImageLoaded)"
                }
            }},
            HostName,
            EventId,
            EventType,
            ProcessGuid,
            ProcessId,
            Image,
            ImageLoaded,
            FileVersion,
            Description,
            Product,
            Company,
            OriginalFileName,
            Hashes,
            Signed,
            Signature,
            SignatureStatus,
            User,
            MD5,
            SHA256,
            SHA1,
            IMPHASH,
            ProcessName,
            ProcessDir,
            ModuleName,
            ModuleLoadDir,
            TimeCreated |
            Out-GridView -Title "Image Load Information"
    }
}

function View-ImageLoadMetadata {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event,
        [parameter(Mandatory = $false, Position = 0)]
        [string] $ModulePath = $false
    )
    Begin {
        $ImageLoadEvents = @()
    }
    process {
        if ($Event.EventId -eq 7) {
            if ($ModulePath -eq $false) {
                $ImageLoadEvents += $Event
            }
            else {
                $ImageLoadEvents += $Event | where-object { $_.ImageLoaded -eq $ModulePath }
            }
        }
    }
    end {
        $ImageLoadEvents | Select-Object FileVersion, Description, Product, Company, OriginalFileName, ImageLoaded, `
        @{Name="Module"; Expression = {"{0} - Loaded by {1} - {2}"-f $_.ModuleName, $_.ProcessName, $_.ProcessGuid}} | sort-object Module `
        | format-list FileVersion, Description, Product, Company, OriginalFileName, ImageLoaded -GroupBy Module | Out-String -stream `
        | ForEach-Object {
            if ($_ -match "Module:.*") {
                write-host $_ -ForegroundColor Cyan
            }
            else {
                write-host $_
            }
        }
    }
}

function View-ImageLoadSignature {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event,
        [parameter(Mandatory = $false, Position = 0)]
        [string] $ModulePath = $false
    )
    Begin {
        $ImageLoadEvents = @()
    }
    process {
        if ($Event.EventId -eq 7) {
            if ($ModulePath -eq $false) {
                $ImageLoadEvents += $Event
            }
            else {
                $ImageLoadEvents += $Event | where-object { $_.ImageLoaded -eq $ModulePath }
            }
        }
    }
    end {
        $ImageLoadEvents | Select-Object Signed, Signature, SignatureStatus, ImageLoaded, `
        @{Name="Module"; Expression = {"{0} - Loaded by {1} - {2}"-f $_.ModuleName, $_.ProcessName, $_.ProcessGuid}} | sort-object Module `
        | format-list Signed, Signature, SignatureStatus, ImageLoaded -GroupBy Module | Out-String -stream `
        | ForEach-Object {
            if ($_ -match "Module:.*") {
                write-host $_ -ForegroundColor Cyan
            }
            else {
                write-host $_
            }
        }
    }
}

Function View-ImageLoadHashes {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [psobject] $Event,
        [parameter(Mandatory = $false)]
        [string] $MD5 = $false,
        [parameter(Mandatory = $false)]
        [string] $SHA256 = $false,
        [parameter(Mandatory = $false)]
        [string] $IMPHASH = $false
    )
    Begin {
        $ImageLoadEvents = @()
    }
    Process {
        If ($Event.EventId -eq 7) {
            if ($MD5 -ne $false) {
                $ImageLoadEvents += $Event | where-object { $_.MD5 -eq $MD5 }
            }
            elseif ($SHA256 -ne $false) {
                $ImageLoadEvents += $Event | where-object { $_.SHA256 -eq $SHA256 }
            }
            elseif ($IMPHASH -ne $false) {
                $ImageLoadEvents += $Event | where-object { $_.IMPHASH -eq $IMPHASH }
            }
            else {
                $ImageLoadEvents += $Event
            }
        }
    }
    end {
        $ImageLoadEvents | Select-Object MD5, SHA256, IMPHASH, Hashes, ImageLoaded, `
        @{Name="Module"; Expression = {"{0} - Loaded by {1} - {2}"-f $_.ModuleName, $_.ProcessName, $_.ProcessGuid}} | Sort-Object Module `
        | Format-List MD5, SHA256, IMPHASH, Hashes, ImageLoaded -GroupBy Module | Out-String -stream `
        | ForEach-Object {
            if ($_ -match "Module:.*") {
                write-host $_ -ForegroundColor Cyan
            }
            else {
                write-host $_
            }
        }
    }
}

function Investigate-ImageLoadInfo {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [parameter(Mandatory = $false)]
        [string] $ProcessName = $false,

        [parameter(Mandatory = $false)]
        [string] $ProcessId = $false,

        [parameter(Mandatory = $false)]
        [string] $ProcessGuid = $false,

        [parameter(Mandatory = $false)]
        [string] $ModuleName = $false,

        [parameter(Mandatory = $false)]
        [string] $ImageLoaded = $false,

        [parameter(Mandatory = $false)]
        [string] $FileVersion = $false,

        [parameter(Mandatory = $false)]
        [string] $Company = $false,

        [parameter(Mandatory = $false)]
        [string] $Product = $false,

        [parameter(Mandatory = $false)]
        [string] $OriginalFileName = $false,

        [parameter(Mandatory = $false)]
        [string] $Signature = $false,

        [parameter(Mandatory = $false)]
        [string] $SignatureStatus = $false,

        [parameter(Mandatory = $false)]
        [string] $Signed = $false,

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
        [ValidateSet("Detailed", "Timeline", "TimelineList", "Summary", "InteractiveTable", "Metadata", "Signature", "Hashes")]
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
            EventId = 7
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
            EventId = 7
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

    if ($ModuleName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.ModuleName -like $ModuleName}
    }

    if ($ImageLoaded -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.ImageLoaded -like $ImageLoaded}
    }

    if ($FileVersion -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.FileVersion -like $FileVersion}
    }

    if ($Company -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Company -like $Company}
    }

    if ($Product -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Product -like $Product}
    }

    if ($OriginalFileName -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.OriginalFileName -like $OriginalFileName}
    }

    if ($Signature -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Signature -like $Signature}
    }

    if ($SignatureStatus -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.SignatureStatus -like $SignatureStatus}
    }

    if ($Signed -ne $false) {
        $BaseQuery = $BaseQuery | Where-Object {$_.Signed -like $Signed}
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
        "Timeline" {
            $Query | View-ImageLoadTimeline
            break
        }
        "TimelineList" {
            $Query | View-ImageLoadTimelineList
            break
        }
        "Summary" {
            $Query | View-ImageLoadSummary
            break
        }
        "InteractiveTable" {
            $Query | View-ImageLoadInteractiveTable
            break
        }
        "Metadata" {
            $Query | View-ImageLoadMetadata
            break
        }
        "Signature" {
            $Query | View-ImageLoadSignature
            break
        }
        "Hashes" {
            $Query | View-ImageLoadHashes
            break
        }
    }
}

# Export the functions
Export-ModuleMember -Function View-ImageLoadTimeline, View-ImageLoadTimelineList, View-ImageLoadSummary, 
                             View-ImageLoadInteractiveTable, View-ImageLoadMetadata, View-ImageLoadSignature,
                             View-ImageLoadHashes, Investigate-ImageLoadInfo
