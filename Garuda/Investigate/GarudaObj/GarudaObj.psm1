# Class Definition for all different Garuda objects
class ProcessCreate {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $ProcessGuid
    [int] $ProcessId
    [string] $Image
    [string] $FileVersion
    [string] $Description
    [string] $Product
    [string] $Company
    [string] $OriginalFileName
    [string] $CommandLine
    [string] $CurrentDirectory
    [string] $User
    [string] $LogonGuid
    [string] $LogonId
    [int] $TerminalSessionId
    [string] $IntegrityLevel
    [string] $Hashes
    [string] $ParentProcessGuid
    [int] $ParentProcessId
    [string] $ParentImage
    [string] $ParentCommandLine

    # additional properties
    [string] $MD5
    [string] $SHA256
    [string] $SHA1
    [string] $IMPHASH
    [string] $ProcessName
    [string] $ProcessDir
    [string] $ParentProcessName
    [string] $ParentProcessDir
}

Class FileCreateTime {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $ProcessGuid
    [int] $ProcessId
    [string] $Image
    [string] $TargetFilename
    [string] $CreationUtcTime
    [string] $PreviousCreationUtcTime
    [string] $User

    # additional properties
    [string] $ProcessName
    [string] $ProcessDir
}

Class NetworkConnection {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $ProcessGuid
    [int] $ProcessId
    [string] $Image
    [string] $User
    [string] $Protocol
    [string] $Initiated
    [string] $SourceIsIpv6
    [string] $SourceIp
    [string] $SourceHostname
    [int] $SourcePort
    [string] $SourcePortName
    [string] $DestinationIsIpv6
    [string] $DestinationIp
    [string] $DestinationHostname
    [int] $DestinationPort
    [string] $DestinationPortName

    # additional properties
    [string] $ProcessName
    [string] $ProcessDir

}

Class ServiceStateChange {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $State
    [string] $Version
    [string] $SchemaVersion

}

Class ProcessTerminate {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $ProcessGuid
    [int] $ProcessId
    [string] $Image
    [string] $User

    # additional properties
    [string] $ProcessName
    [string] $ProcessDir
}

Class DriverLoad {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $ImageLoaded
    [string] $Hashes
    [string] $Signed
    [string] $Signature
    [string] $SignatureStatus

    # additional properties
    [string] $MD5
    [string] $SHA256
    [string] $SHA1
    [string] $IMPHASH
    [string] $DriverName
    [string] $DriverDir

}

Class ModuleLoad {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $ProcessGuid
    [int] $ProcessId
    [string] $Image
    [string] $ImageLoaded
    [string] $FileVersion
    [string] $Description
    [string] $Product
    [string] $Company
    [string] $OriginalFileName
    [string] $Hashes
    [string] $Signed
    [string] $Signature
    [string] $SignatureStatus
    [string] $User

    # additional properties
    [string] $MD5
    [string] $SHA256
    [string] $SHA1
    [string] $IMPHASH
    [string] $ProcessName
    [string] $ProcessDir
    [string] $ModuleName
    [string] $ModuleLoadDir

}

Class RemoteThread {
    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $SourceProcessGuid
    [int] $SourceProcessId
    [string] $SourceImage
    [string] $TargetProcessGuid
    [int] $TargetProcessId
    [string] $TargetImage
    [int] $NewThreadId
    [string] $StartAddress
    [string] $StartModule
    [string] $StartFunction
    [string] $SourceUser
    [string] $TargetUser

    # additional properties
    [string] $SourceProcessName
    [string] $SourceProcessDir
    [string] $TargetProcessName
    [string] $TargetProcessDir
}

Class RawAccessRead {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $ProcessGuid
    [int] $ProcessId
    [string] $Image
    [string] $Device
    [string] $User

    # additional properties
    [string] $ProcessName
    [string] $ProcessDir
}

Class ProcessAccess {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $SourceProcessGuid
    [int] $SourceProcessId
    [int] $SourceThreadId
    [string] $SourceImage
    [string] $TargetProcessGuid
    [int] $TargetProcessId
    [string] $TargetImage
    [string] $GrantedAccess
    [string] $CallTrace
    [string] $SourceUser
    [string] $TargetUser

    # additional properties
    [string] $SourceProcessName
    [string] $SourceProcessDir
    [string] $TargetProcessName
    [string] $TargetProcessDir
}

Class FileCreate {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $ProcessGuid
    [int] $ProcessId
    [string] $Image
    [string] $TargetFilename
    [string] $CreationUtcTime
    [string] $User

    # additional properties
    [string] $ProcessName
    [string] $ProcessDir
}
Class RegObjCreateDelete {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $ProcessGuid
    [int] $ProcessId
    [string] $Image
    [string] $TargetObject
    [string] $User

    # additional properties
    [string] $ProcessName
    [string] $ProcessDir
    [string] $RegKey
    [string] $RegKeyValue

}

Class RegSetValue {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $ProcessGuid
    [int] $ProcessId
    [string] $Image
    [string] $TargetObject
    [string] $Details
    [string] $User

    # additional properties
    [string] $ProcessName
    [string] $ProcessDir
    [string] $RegKey
    [string] $RegValueName
    [string] $RegValueData

}

Class RegObjRename {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $ProcessGuid
    [int] $ProcessId
    [string] $Image
    [string] $TargetObject
    [string] $NewName
    [string] $User

    # additional properties
    [string] $ProcessName
    [string] $ProcessDir
    [string] $RegKey        # Extracted from TargetObject
    [string] $RegKeyValue   # Extracted from TargetObject
    [string] $RenamedRegKeyValue

}

Class FileStream {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $ProcessGuid
    [int] $ProcessId
    [string] $Image
    [string] $TargetFilename
    [string] $CreationUtcTime
    [string] $Hash
    [string] $Contents
    [string] $User

    # additional properties
    [string] $ProcessName
    [string] $ProcessDir
    [string] $MD5
    [string] $SHA256
    [string] $SHA1
    [string] $IMPHASH
}

Class ServiceConfigurationChange {
    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $Configuration
    [string] $ConfigurationFileHash
}

Class CreatePipe {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $ProcessGuid
    [int] $ProcessId
    [string] $Image
    [string] $PipeName
    [string] $User

    # additional properties
    [string] $ProcessName
    [string] $ProcessDir
}

Class ConnectPipe {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $ProcessGuid
    [int] $ProcessId
    [string] $Image
    [string] $PipeName
    [string] $User

    # additional properties
    [string] $ProcessName
    [string] $ProcessDir
}

Class WmiFilter {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $Operation
    [string] $User
    [string] $EventNamespace
    [string] $Name
    [string] $Query
}

Class WmiConsumer {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $Operation
    [string] $User
    [string] $Name
    [string] $Type
    [string] $Destination
}

Class WmiBinding {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $Operation
    [string] $User
    [string] $Consumer
    [string] $Filter
}

Class DnsQuery {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $ProcessGuid
    [int] $ProcessId
    [string] $Image
    [string] $QueryName
    [string] $QueryStatus
    [string] $QueryResults
    [string] $User

    # additional properties
    [string] $ProcessName
    [string] $ProcessDir
}

Class FileDelete {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $ProcessGuid
    [int] $ProcessId
    [string] $User
    [string] $Image
    [string] $TargetFilename
    [string] $Hashes
    [string] $IsExecutable
    [string] $Archived

    # additional properties
    [string] $MD5
    [string] $SHA256
    [string] $SHA1
    [string] $IMPHASH
    [string] $ProcessName
    [string] $ProcessDir
}


Class ClipboardChange {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $ProcessGuid
    [int] $ProcessId
    [string] $Image
    [string] $Session
    [string] $ClientInfo
    [string] $Hashes
    [string] $Archived
    [string] $User

    # additional properties
    [string] $MD5
    [string] $SHA256
    [string] $IMPHASH
    [string] $ProcessName
    [string] $ProcessDir
}

Class ProcessTampering {
    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $ProcessGuid
    [int] $ProcessId
    [string] $Image
    [string] $Type          # Tampering type (e.g., "Image is locked for access")
    [string] $User
    
    # Additional derived properties
    [string] $HollowedProcessName   # Extracted from Image path
    [string] $HollowedProcessDir    # Directory containing the process
}


Class FileDeleteDetected {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $ProcessGuid
    [int] $ProcessId
    [string] $User
    [string] $Image
    [string] $TargetFilename
    [string] $Hashes
    [string] $IsExecutable

    # additional properties
    [string] $MD5
    [string] $SHA256
    [string] $SHA1
    [string] $IMPHASH
    [string] $ProcessName
    [string] $ProcessDir
}

Class FileBlockExecutable {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $RuleName
    [string] $ProcessGuid
    [int] $ProcessId
    [string] $User
    [string] $Image
    [string] $TargetFilename
    [string] $Hashes

    # additional properties
    [string] $MD5
    [string] $SHA256
    [string] $SHA1
    [string] $IMPHASH
    [string] $ProcessName
    [string] $ProcessDir
}

Class FileBlockShredding {

    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $RuleName
    [string] $ProcessGuid
    [int] $ProcessId
    [string] $User
    [string] $Image
    [string] $TargetFilename
    [string] $Hashes
    [string] $IsExecutable

    # additional properties
    [string] $MD5
    [string] $SHA256
    [string] $SHA1
    [string] $IMPHASH
    [string] $ProcessName
    [string] $ProcessDir
}

Class FileExecutableDetected {
    [int] $EventId
    [string] $HostName
    [datetime] $TimeCreated
    [string] $EventType
    [string] $UtcTime
    [string] $RuleName
    [string] $ProcessGuid
    [int] $ProcessId
    [string] $User
    [string] $Image
    [string] $TargetFilename
    [string] $Hashes

    # additional properties
    [string] $MD5
    [string] $SHA256
    [string] $SHA1
    [string] $IMPHASH
    [string] $ProcessName
    [string] $ProcessDir
}

# Gets process name,process dir and takes care of process with no full path (Ex: System)
function Get-ProcFromImagePath($Image) {

    [regex] $proc_rx = "(?<ProcDir>.*)\\(?<ProcName>.*)"
    
    if ($proc_rx.IsMatch($Image)) {
        $ProcName = $proc_rx.match($Image).Groups["ProcName"].Value.trim()
        $ProcDir = $proc_rx.match($Image).Groups["ProcDir"].Value.trim()
    }
    
    else {
    
        $ProcName = $Image
        $ProcDir = "-"
    }
    return $ProcName, $ProcDir
}


function ConvertTo-GarudaObjects {

    [CmdletBinding()]
    param (
        [parameter(ValueFromPipeline)]
        [System.Diagnostics.Eventing.Reader.EventLogRecord] $Event
    )

    Begin {
        
        [regex] $rx = "^\w+:\s+(?<capture>.*)"  # regex for capturing field values
        [regex] $proc_rx = "(?<ProcDir>.*)\\(?<ProcName>.*)"  # regex for capturing process name and process dir
        [regex] $reg_rx = "(?<RegPath>.*)\\(?<RegName>.*)"  # regex for capturing registry path and object name
    }

    process {
        # Creates objects for Process Create Events
        if ($Event.Id -eq 1) {

            $Message = $Event.Message.split("`n")
            $Hashes = $rx.match($Message[18]).Groups["capture"].Value.trim()
            foreach ($Hash in $Hashes.split(",")) {
                $HashType, $HashValue = $Hash.split("=")
                if ($HashType -eq "MD5") {
                    $MD5Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "SHA256") {
                    $SHA256Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "SHA1") {
                    $SHA1Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "IMPHASH") {
                    $IMPHash = $HashValue.trim()
                }
            }
            $ProcImage = $rx.match($message[5]).Groups["capture"].Value.trim()
            $ProcName, $ProcDir = Get-ProcFromImagePath $ProcImage
            $ParentProcImage = $rx.match($message[21]).Groups["capture"].Value.trim()
            $ParentProcName, $ParentProcDir = Get-ProcFromImagePath $ParentProcImage

            $Properties = @{
                EventId           = $Event.Id
                HostName          = $Event.MachineName
                TimeCreated       = $Event.TimeCreated
                EventType         = "ProcessCreate"
                UtcTime           = $rx.match($message[2]).Groups["capture"].Value.trim()
                ProcessGuid       = $rx.match($message[3]).Groups["capture"].Value.trim()
                ProcessId         = $rx.match($message[4]).Groups["capture"].Value.trim()
                Image             = $ProcImage
                FileVersion       = $rx.match($message[6]).Groups["capture"].Value.trim()
                Description       = $rx.match($message[7]).Groups["capture"].Value.trim()
                Product           = $rx.match($message[8]).Groups["capture"].Value.trim()
                Company           = $rx.match($message[9]).Groups["capture"].Value.trim()
                OriginalFileName  = $rx.match($message[10]).Groups["capture"].Value.trim()
                CommandLine       = $rx.match($message[11]).Groups["capture"].Value.trim()
                CurrentDirectory  = $rx.match($message[12]).Groups["capture"].Value.trim()
                User              = $rx.match($message[13]).Groups["capture"].Value.trim()
                LogonGuid         = $rx.match($message[14]).Groups["capture"].Value.trim()
                LogonId           = $rx.match($message[15]).Groups["capture"].Value.trim()
                TerminalSessionId = $rx.match($message[16]).Groups["capture"].Value.trim()
                IntegrityLevel    = $rx.match($message[17]).Groups["capture"].Value.trim()
                Hashes            = $Hashes
                ParentProcessGuid = $rx.match($message[19]).Groups["capture"].Value.trim()
                ParentProcessId   = $rx.match($message[20]).Groups["capture"].Value.trim()
                ParentImage       = $ParentProcImage
                ParentCommandLine = $rx.match($message[22]).Groups["capture"].Value.trim()
                
                # Creating additional properties
                MD5               = $MD5Hash
                SHA256            = $SHA256Hash
                SHA1              = $SHA1Hash
                IMPHASH           = $IMPHash
                ProcessName       = $ProcName
                ProcessDir        = $ProcDir
                ParentProcessName = $ParentProcName
                ParentProcessDir  = $ParentProcDir
            }

            $ProcObject = New-Object -TypeName ProcessCreate -Property $Properties
            Write-Output $ProcObject
        }
        # Creates Objects for File Creation Time Change Events
        elseif ($Event.Id -eq 2) {

            $Message = $Event.Message.split("`n")
            $ProcImage = $rx.match($message[5]).Groups["capture"].Value.trim()
            $ProcName, $ProcDir = Get-ProcFromImagePath $ProcImage
            $Properties = @{
                EventId                 = $Event.Id
                HostName                = $Event.MachineName
                TimeCreated             = $Event.TimeCreated
                EventType               = "FileCreateTime"
                UtcTime                 = $rx.match($message[2]).Groups["capture"].Value.trim()
                ProcessGuid             = $rx.match($message[3]).Groups["capture"].Value.trim()
                ProcessId               = $rx.match($message[4]).Groups["capture"].Value.trim()
                Image                   = $ProcImage
                TargetFilename          = $rx.match($message[6]).Groups["capture"].Value.trim()
                CreationUtcTime         = $rx.match($message[7]).Groups["capture"].Value.trim()
                PreviousCreationUtcTime = $rx.match($message[8]).Groups["capture"].Value.trim()
                User                    = $rx.match($message[9]).Groups["capture"].Value.trim()

                # Creating additional properties
                ProcessName             = $ProcName
                ProcessDir              = $ProcDir
            }

            $FileCreateTimeObject = New-Object -TypeName FileCreateTime -Property $Properties
            Write-Output $FileCreateTimeObject
        }
        # Creates Objects for Network Connection Events
        elseif ($Event.Id -eq 3) {
            
            $Message = $Event.Message.split("`n")
            $ProcImage = $rx.match($message[5]).Groups["capture"].Value.trim()
            $ProcName, $ProcDir = Get-ProcFromImagePath $ProcImage
            $Properties = @{
                
                EventId             = $Event.Id
                HostName            = $Event.MachineName
                TimeCreated         = $Event.TimeCreated
                EventType           = "NetworkConnection"
                #UtcTime             = $rx.match($message[2]).Groups["capture"].Value.trim()
                UtcTime             = $Event.TimeCreated.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff")
                ProcessGuid         = $rx.match($message[3]).Groups["capture"].Value.trim()
                ProcessId           = $rx.match($message[4]).Groups["capture"].Value.trim()
                Image               = $ProcImage
                User                = $rx.match($message[6]).Groups["capture"].Value.trim()
                Protocol            = $rx.match($message[7]).Groups["capture"].Value.trim()
                Initiated           = $rx.match($message[8]).Groups["capture"].Value.trim()
                SourceIsIpv6        = $rx.match($message[9]).Groups["capture"].Value.trim()
                SourceIp            = $rx.match($message[10]).Groups["capture"].Value.trim()
                SourceHostname      = $rx.match($message[11]).Groups["capture"].Value.trim()
                SourcePort          = $rx.match($message[12]).Groups["capture"].Value.trim()
                SourcePortName      = $rx.match($message[13]).Groups["capture"].Value.trim()
                DestinationIsIpv6   = $rx.match($message[14]).Groups["capture"].Value.trim()
                DestinationIp       = $rx.match($message[15]).Groups["capture"].Value.trim()
                DestinationHostname = $rx.match($message[16]).Groups["capture"].Value.trim()
                DestinationPort     = $rx.match($message[17]).Groups["capture"].Value.trim()
                DestinationPortName = $rx.match($message[18]).Groups["capture"].Value.trim()
                
                # Creating additional properties
                ProcessName         = $ProcName
                ProcessDir          = $ProcDir
            }
            $NetworkObject = New-Object -TypeName NetworkConnection -Property $Properties
            Write-Output $NetworkObject

        }
        # Creates Objects for Service State Change Events
        elseif ($Event.Id -eq 4) {

            $Message = $Event.Message.split("`n")
            $Properties = @{

                EventId       = $Event.Id
                HostName      = $Event.MachineName
                TimeCreated   = $Event.TimeCreated
                EventType     = "SysmonServiceStateChange"
                UtcTime       = $rx.match($message[1]).Groups["capture"].Value.trim()
                State         = $rx.match($message[2]).Groups["capture"].Value.trim()
                Version       = $rx.match($message[3]).Groups["capture"].Value.trim()
                SchemaVersion = $rx.match($message[4]).Groups["capture"].Value.trim()
            }

            $SysmonStateChangeObject = New-Object -TypeName ServiceStateChange -Property $Properties
            Write-Output $SysmonStateChangeObject
        }
        # Creates Objects for Process Termination Events
        elseif ($Event.Id -eq 5) {
            $Message = $Event.Message.split("`n")
            $ProcImage = $rx.match($message[5]).Groups["capture"].Value.trim()
            $ProcName, $ProcDir = Get-ProcFromImagePath $ProcImage
            $Properties = @{
                EventId     = $Event.Id
                HostName    = $Event.MachineName
                TimeCreated = $Event.TimeCreated
                EventType   = $Message[0].split(":")[0].trim()
                UtcTime     = $rx.match($message[2]).Groups["capture"].Value.trim()
                ProcessGuid = $rx.match($message[3]).Groups["capture"].Value.trim()
                ProcessId   = $rx.match($message[4]).Groups["capture"].Value.trim()
                Image       = $ProcImage
                User        = $rx.match($message[6]).Groups["capture"].Value.trim()

                # Creating additional properties
                ProcessName = $ProcName
                ProcessDir  = $ProcDir
            }

            $ProcessTerminateObject = New-Object -TypeName ProcessTerminate -Property $Properties
            Write-Output $ProcessTerminateObject
        }
        # Creates Objects for Driver Load Events
        elseif ($Event.Id -eq 6) {

            $Message = $Event.Message.split("`n")
            $Hashes = $rx.match($Message[4]).Groups["capture"].Value.trim()
            foreach ($Hash in $Hashes.split(",")) {
                $HashType, $HashValue = $Hash.split("=")
                if ($HashType -eq "MD5") {
                    $MD5Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "SHA256") {
                    $SHA256Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "SHA1") {
                    $SHA1Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "IMPHASH") {
                    $IMPHash = $HashValue.trim()
                }
            }
            $DriverPath = $rx.match($message[3]).Groups["capture"].Value.trim()
            $Properties = @{

                EventId         = $Event.Id
                HostName        = $Event.MachineName
                TimeCreated     = $Event.TimeCreated
                EventType       = $Message[0].split(":")[0].trim()
                UtcTime         = $rx.match($message[2]).Groups["capture"].Value.trim()
                ImageLoaded     = $DriverPath
                Hashes          = $Hashes
                Signed          = $rx.match($message[5]).Groups["capture"].Value.trim()
                Signature       = $rx.match($message[6]).Groups["capture"].Value.trim()
                SignatureStatus = $rx.match($message[7]).Groups["capture"].Value.trim()

                # Creating additional properties
                MD5             = $MD5Hash
                SHA256          = $SHA256Hash
                SHA1            = $SHA1Hash
                IMPHASH         = $IMPHash
                DriverName      = $proc_rx.match($DriverPath).Groups["ProcName"].Value.trim()
                DriverDir       = $proc_rx.match($DriverPath).Groups["ProcDir"].Value.trim()

            }

            $DriverLoadObject = New-Object -TypeName DriverLoad -Property $Properties
            Write-Output $DriverLoadObject

        }
        # Creates Objects for Module Load (Image Load) Events
        elseif ($Event.Id -eq 7) {
            $Message = $Event.Message.split("`n")
            $Hashes = $rx.match($Message[12]).Groups["capture"].Value.trim()
            foreach ($Hash in $Hashes.split(",")) {
                $HashType, $HashValue = $Hash.split("=")
                if ($HashType -eq "MD5") {
                    $MD5Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "SHA256") {
                    $SHA256Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "SHA1") {
                    $SHA1Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "IMPHASH") {
                    $IMPHash = $HashValue.trim()
                }
            }
            $ProcImage = $rx.match($message[5]).Groups["capture"].Value.trim()
            $ProcName, $ProcDir = Get-ProcFromImagePath $ProcImage
            $ModulePath = $rx.match($message[6]).Groups["capture"].Value.trim()
            $Properties = @{

                EventId          = $Event.Id
                HostName         = $Event.MachineName
                TimeCreated      = $Event.TimeCreated
                EventType        = $Message[0].split(":")[0].trim()
                UtcTime          = $rx.match($message[2]).Groups["capture"].Value.trim()
                ProcessGuid      = $rx.match($message[3]).Groups["capture"].Value.trim()
                ProcessId        = $rx.match($message[4]).Groups["capture"].Value.trim()
                Image            = $ProcImage
                ImageLoaded      = $ModulePath
                FileVersion      = $rx.match($message[7]).Groups["capture"].Value.trim()
                Description      = $rx.match($message[8]).Groups["capture"].Value.trim()
                Product          = $rx.match($message[9]).Groups["capture"].Value.trim()
                Company          = $rx.match($message[10]).Groups["capture"].Value.trim()
                OriginalFileName = $rx.match($message[11]).Groups["capture"].Value.trim()
                Hashes           = $Hashes
                Signed           = $rx.match($message[13]).Groups["capture"].Value.trim()
                Signature        = $rx.match($message[14]).Groups["capture"].Value.trim()
                SignatureStatus  = $rx.match($message[15]).Groups["capture"].Value.trim()
                User             = $rx.match($message[16]).Groups["capture"].Value.trim()

                # Creating additional properties
                MD5              = $MD5Hash
                SHA256           = $SHA256Hash
                SHA1             = $SHA1Hash
                IMPHASH          = $IMPHash
                ProcessName      = $ProcName
                ProcessDir       = $ProcDir
                ModuleName       = $proc_rx.match($ModulePath).Groups["ProcName"].Value.trim()
                ModuleLoadDir    = $proc_rx.match($ModulePath).Groups["ProcDir"].Value.trim()

            }
            $ModuleLoadObject = New-Object -TypeName ModuleLoad -Property $Properties
            Write-Output $ModuleLoadObject
        }
        # Creates Object for CreateRemoteThread Events
        elseif ($Event.Id -eq 8) {
            $Message = $Event.Message.split("`n")
            $SourceImage = $rx.match($message[5]).Groups["capture"].Value.trim()
            $TargetImage = $rx.match($message[8]).Groups["capture"].Value.trim()
            $SourceProcName, $SourceProcDir = Get-ProcFromImagePath $SourceImage
            $TargetProcName, $TargetProcDir = Get-ProcFromImagePath $TargetImage
            $Properties = @{
                EventId           = $Event.Id
                HostName          = $Event.MachineName
                TimeCreated       = $Event.TimeCreated
                EventType         = "CreateRemoteThread"
                UtcTime           = $rx.match($message[2]).Groups["capture"].Value.trim()
                SourceProcessGuid = $rx.match($message[3]).Groups["capture"].Value.trim()
                SourceProcessId   = $rx.match($message[4]).Groups["capture"].Value.trim()
                SourceImage       = $SourceImage
                TargetProcessGuid = $rx.match($message[6]).Groups["capture"].Value.trim()
                TargetProcessId   = $rx.match($message[7]).Groups["capture"].Value.trim()
                TargetImage       = $TargetImage
                NewThreadId       = $rx.match($message[9]).Groups["capture"].Value.trim()
                StartAddress      = $rx.match($message[10]).Groups["capture"].Value.trim()
                StartModule       = $rx.match($message[11]).Groups["capture"].Value.trim()
                StartFunction     = $rx.match($message[12]).Groups["capture"].Value.trim()
                SourceUser        = $rx.match($message[13]).Groups["capture"].Value.trim()
                TargetUser        = $rx.match($message[14]).Groups["capture"].Value.trim()

                # Creating additional properties
                SourceProcessName = $SourceProcName
                SourceProcessDir  = $SourceProcDir
                TargetProcessName = $TargetProcName
                TargetProcessDir  = $TargetProcDir
            }
            $RemoteThreadObject = New-Object -TypeName RemoteThread -Property $Properties
            Write-Output $RemoteThreadObject
        }
        # Creates Object for RawAccessRead Events
        elseif ($Event.Id -eq 9) {
            $Message = $Event.Message.split("`n")
            $ProcImage = $rx.match($message[5]).Groups["capture"].Value.trim()
            $ProcName, $ProcDir = Get-ProcFromImagePath $ProcImage
            $Properties = @{

                EventId     = $Event.Id
                HostName    = $Event.MachineName
                TimeCreated = $Event.TimeCreated
                EventType   = "RawAccessRead"
                UtcTime     = $rx.match($message[2]).Groups["capture"].Value.trim()
                ProcessGuid = $rx.match($message[3]).Groups["capture"].Value.trim()
                ProcessId   = $rx.match($message[4]).Groups["capture"].Value.trim()
                Image       = $ProcImage
                Device      = $rx.match($message[6]).Groups["capture"].Value.trim()
                User        = $rx.match($message[7]).Groups["capture"].Value.trim()

                # Creating additional properties
                ProcessName = $ProcName
                ProcessDir  = $ProcDir
            }
            
            $RawAccessReadObject = New-Object -TypeName RawAccessRead -Property $Properties
            Write-Output $RawAccessReadObject
        }
        # Creates Object for ProcessAccess Events
        elseif ($Event.Id -eq 10) {
            $Message = $Event.Message.split("`n")
            $SourceProcImage = $rx.match($message[6]).Groups["capture"].Value.trim()
            $SourceProcName, $SourceProcDir = Get-ProcFromImagePath $SourceProcImage
            $TargetProcImage = $rx.match($message[9]).Groups["capture"].Value.trim()
            $TargetProcName, $TargetProcDir = Get-ProcFromImagePath $TargetProcImage
            $Properties = @{
                EventId           = $Event.Id
                HostName          = $Event.MachineName
                TimeCreated       = $Event.TimeCreated
                EventType         = "ProcessAccess"
                UtcTime           = $rx.match($message[2]).Groups["capture"].Value.trim()
                SourceProcessGuid = $rx.match($message[3]).Groups["capture"].Value.trim()
                SourceProcessId   = $rx.match($message[4]).Groups["capture"].Value.trim()
                SourceThreadId    = $rx.match($message[5]).Groups["capture"].Value.trim()
                SourceImage       = $SourceProcImage
                TargetProcessGuid = $rx.match($message[7]).Groups["capture"].Value.trim()
                TargetProcessId   = $rx.match($message[8]).Groups["capture"].Value.trim()
                TargetImage       = $TargetProcImage
                GrantedAccess     = $rx.match($message[10]).Groups["capture"].Value.trim()
                CallTrace         = $rx.match($message[11]).Groups["capture"].Value.trim()
                SourceUser        = $rx.match($message[12]).Groups["capture"].Value.trim()
                TargetUser        = $rx.match($message[13]).Groups["capture"].Value.trim()

                # Creating additional properties
                SourceProcessName = $SourceProcName
                SourceProcessDir  = $SourceProcDir
                TargetProcessName = $TargetProcName
                TargetProcessDir  = $TargetProcDir
            }
            $ProcessAccessObject = New-Object -TypeName ProcessAccess -Property $Properties
            Write-Output $ProcessAccessObject
        }
        # Creates Object for FileCreate Events
        elseif ($Event.Id -eq 11) {
            $Message = $Event.Message.split("`n")
            $ProcImage = $rx.match($message[5]).Groups["capture"].Value.trim()
            $ProcName, $ProcDir = Get-ProcFromImagePath $ProcImage
            $Properties = @{

                EventId         = $Event.Id
                HostName        = $Event.MachineName
                TimeCreated     = $Event.TimeCreated
                EventType       = "FileCreate"
                UtcTime         = $rx.match($message[2]).Groups["capture"].Value.trim()
                ProcessGuid     = $rx.match($message[3]).Groups["capture"].Value.trim()
                ProcessId       = $rx.match($message[4]).Groups["capture"].Value.trim()
                Image           = $ProcImage
                TargetFilename  = $rx.match($message[6]).Groups["capture"].Value.trim()
                CreationUtcTime = $rx.match($message[7]).Groups["capture"].Value.trim()
                User            = $rx.match($message[8]).Groups["capture"].Value.trim()

                # Creating additional properties
                ProcessName     = $ProcName
                ProcessDir      = $ProcDir
            }

            $FileCreateObject = New-Object -TypeName FileCreate -Property $Properties
            Write-Output $FileCreateObject

        }
        # Creates Object for Registry Object Create/Delete Events
        elseif ($Event.Id -eq 12) {
            $Message = $Event.Message.split("`n")
            $ProcImage = $rx.match($message[6]).Groups["capture"].Value.trim()
            $ProcName, $ProcDir = Get-ProcFromImagePath $ProcImage
            $TargetObj = $rx.match($message[7]).Groups["capture"].Value.trim()
            $Properties = @{

                EventId      = $Event.Id
                HostName     = $Event.MachineName
                TimeCreated  = $Event.TimeCreated
                EventType    = $rx.match($message[2]).Groups["capture"].Value.trim()
                UtcTime      = $rx.match($message[3]).Groups["capture"].Value.trim()
                ProcessGuid  = $rx.match($message[4]).Groups["capture"].Value.trim()
                ProcessId    = $rx.match($message[5]).Groups["capture"].Value.trim()
                Image        = $ProcImage
                TargetObject = $TargetObj
                User         = $rx.match($message[8]).Groups["capture"].Value.trim()

                # Creating additional properties
                ProcessName  = $ProcName
                ProcessDir   = $ProcDir
                RegKey       = $reg_rx.match($TargetObj).Groups["RegPath"].value.trim()
                RegKeyValue  = $reg_rx.match($TargetObj).Groups["RegName"].value.trim()

            }
            $RegCreateDeleteObject = New-Object -TypeName RegObjCreateDelete -Property $Properties
            Write-Output $RegCreateDeleteObject
        }
        # Creates Object for Registry SetValue Events
        elseif ($Event.Id -eq 13) {
            $Message = $Event.Message.split("`n")
            $ProcImage = $rx.match($message[6]).Groups["capture"].Value.trim()
            $ProcName, $ProcDir = Get-ProcFromImagePath $ProcImage
            $TargetObj = $rx.match($message[7]).Groups["capture"].Value.trim()
            $ValueData = $rx.match($message[8]).Groups["capture"].Value.trim()
            $Properties = @{
                EventId = $Event.Id
                HostName = $Event.MachineName
                TimeCreated = $Event.TimeCreated
                EventType = $rx.match($message[2]).Groups["capture"].Value.trim()
                UtcTime = $rx.match($message[3]).Groups["capture"].Value.trim()
                ProcessGuid = $rx.match($message[4]).Groups["capture"].Value.trim()
                ProcessId = $rx.match($message[5]).Groups["capture"].Value.trim()
                Image = $ProcImage
                TargetObject = $TargetObj
                Details = $ValueData
                User = $rx.match($message[9]).Groups["capture"].Value.trim()

                # Creating additional properties
                ProcessName = $ProcName
                ProcessDir = $ProcDir
                RegKey = $reg_rx.match($TargetObj).Groups["RegPath"].value.trim()
                RegValueName = $reg_rx.match($TargetObj).Groups["RegName"].value.trim()
                RegValueData = $ValueData
            }

            $RegSetValueObject = New-Object -TypeName RegSetValue -Property $Properties
            Write-Output $RegSetValueObject
        }
        # Creates Object for Registry Object Rename Events
        elseif ($Event.Id -eq 14) {
            $Message = $Event.Message.split("`n")
            $ProcImage = $rx.match($message[6]).Groups["capture"].Value.trim()
            $ProcName, $ProcDir = Get-ProcFromImagePath $ProcImage
            $TargetObj = $rx.match($message[7]).Groups["capture"].Value.trim()
            $NewNameObj = $rx.match($message[8]).Groups["capture"].Value.trim()
            
            $Properties = @{
                EventId = $Event.Id
                HostName = $Event.MachineName
                TimeCreated = $Event.TimeCreated
                EventType = $rx.match($message[2]).Groups["capture"].Value.trim()
                UtcTime = $rx.match($message[3]).Groups["capture"].Value.trim()
                ProcessGuid = $rx.match($message[4]).Groups["capture"].Value.trim()
                ProcessId = $rx.match($message[5]).Groups["capture"].Value.trim()
                Image = $ProcImage
                TargetObject = $TargetObj
                NewName = $NewNameObj
                User = $rx.match($message[9]).Groups["capture"].Value.trim()

                # Creating additional properties
                ProcessName = $ProcName
                ProcessDir = $ProcDir
                RegKey = $reg_rx.match($TargetObj).Groups["RegPath"].value.trim()
                RegKeyValue = $reg_rx.match($TargetObj).Groups["RegName"].value.trim()
                RenamedRegKeyValue = $reg_rx.match($NewNameObj).Groups["RegName"].value.trim()
            }

            $RegRenameObject = New-Object -TypeName RegObjRename -Property $Properties
            Write-Output $RegRenameObject
        }
        # Creates Object for File Stream Events
        elseif ($Event.Id -eq 15) {
            $Message = $Event.Message.split("`n")
            $ProcImage = $rx.match($message[5]).Groups["capture"].Value.trim()
            $ProcName, $ProcDir = Get-ProcFromImagePath $ProcImage
            $Hash = $rx.match($message[8]).Groups["capture"].Value.trim()
            
            # Parse hash values
            foreach ($HashValue in $Hash.split(",")) {
                $HashType, $HashVal = $HashValue.split("=")
                if ($HashType -eq "MD5") {
                    $MD5Hash = $HashVal.trim()
                }
                elseif ($HashType -eq "SHA256") {
                    $SHA256Hash = $HashVal.trim()
                }
                elseif ($HashType -eq "SHA1") {
                    $SHA1Hash = $HashVal.trim()
                }
                elseif ($HashType -eq "IMPHASH") {
                    $IMPHash = $HashVal.trim()
                }
            }
            
            $Properties = @{
                EventId = $Event.Id
                HostName = $Event.MachineName
                TimeCreated = $Event.TimeCreated
                EventType = "FileStreamHash"
                UtcTime = $rx.match($message[2]).Groups["capture"].Value.trim()
                ProcessGuid = $rx.match($message[3]).Groups["capture"].Value.trim()
                ProcessId = $rx.match($message[4]).Groups["capture"].Value.trim()
                Image = $ProcImage
                TargetFilename = $rx.match($message[6]).Groups["capture"].Value.trim()
                CreationUtcTime = $rx.match($message[7]).Groups["capture"].Value.trim()
                Hash = $rx.match($message[8]).Groups["capture"].Value.trim()
                Contents = $rx.match($message[9]).Groups["capture"].Value.trim()
                User = $rx.match($message[10]).Groups["capture"].Value.trim()

                # Creating additional properties
                ProcessName = $ProcName
                ProcessDir = $ProcDir
                MD5 = $MD5Hash
                SHA256 = $SHA256Hash
                SHA1 = $SHA1Hash
                IMPHASH = $IMPHash
            }

            $FileStreamHashObject = New-Object -TypeName FileStream -Property $Properties
            Write-Output $FileStreamHashObject
        }
        # Creates Object for Sysmon Service Configuration Change Events
        elseif ($Event.Id -eq 16) {
            $Message = $Event.Message.split("`n")
            $Configuration = $rx.match($message[2]).Groups["capture"].Value.trim()
            $HashValue = $rx.match($message[3]).Groups["capture"].Value.trim()
            
            $Properties = @{
                EventId = $Event.Id
                HostName = $Event.MachineName
                TimeCreated = $Event.TimeCreated
                EventType = "ServiceConfigurationChange"
                UtcTime = $rx.match($message[1]).Groups["capture"].Value.trim()
                Configuration = $Configuration
                ConfigurationFileHash = $HashValue
            }

            $ServiceConfigObject = New-Object -TypeName ServiceConfigurationChange -Property $Properties
            Write-Output $ServiceConfigObject
        }        
        # Creates Object for Create Pipe Events
        elseif ($Event.Id -eq 17) {
            $Message = $Event.Message.split("`n")
            $ProcImage = $rx.match($message[7]).Groups["capture"].Value.trim()
            $ProcName, $ProcDir = Get-ProcFromImagePath $ProcImage
            $Properties = @{
                EventId     = $Event.Id
                HostName    = $Event.MachineName
                TimeCreated = $Event.TimeCreated
                EventType   = $rx.match($message[2]).Groups["capture"].Value.trim()
                UtcTime     = $rx.match($message[3]).Groups["capture"].Value.trim()
                ProcessGuid = $rx.match($message[4]).Groups["capture"].Value.trim()
                ProcessId   = $rx.match($message[5]).Groups["capture"].Value.trim()
                PipeName    = $rx.match($message[6]).Groups["capture"].Value.trim()
                Image       = $ProcImage
                User        = $rx.match($message[8]).Groups["capture"].Value.trim()

                # Creating additional properties
                ProcessName = $ProcName
                ProcessDir  = $ProcDir
            }

            $CreatePipeObject = New-Object -TypeName CreatePipe -Property $Properties
            Write-Output $CreatePipeObject
        }
        # Creates Object for Connect Pipe Events
        elseif ($Event.Id -eq 18) {
            $Message = $Event.Message.split("`n")
            $ProcImage = $rx.match($message[7]).Groups["capture"].Value.trim()
            $ProcName, $ProcDir = Get-ProcFromImagePath $ProcImage
            $Properties = @{
                EventId     = $Event.Id
                HostName    = $Event.MachineName
                TimeCreated = $Event.TimeCreated
                EventType   = $rx.match($message[2]).Groups["capture"].Value.trim()
                UtcTime     = $rx.match($message[3]).Groups["capture"].Value.trim()
                ProcessGuid = $rx.match($message[4]).Groups["capture"].Value.trim()
                ProcessId   = $rx.match($message[5]).Groups["capture"].Value.trim()
                PipeName    = $rx.match($message[6]).Groups["capture"].Value.trim()
                Image       = $ProcImage
                User        = $rx.match($message[8]).Groups["capture"].Value.trim()

                # Creating additional properties
                ProcessName = $ProcName
                ProcessDir  = $ProcDir
            }

            $ConnectPipeObject = New-Object -TypeName ConnectPipe -Property $Properties
            Write-Output $ConnectPipeObject
        }
        # Creates Object for WMI filter Events
        elseif ($Event.Id -eq 19) {

            $Message = $Event.Message.split("`n")
            $Properties = @{
                
                EventId        = $Event.Id
                HostName       = $Event.MachineName
                TimeCreated    = $Event.TimeCreated
                EventType      = $rx.match($message[2]).Groups["capture"].Value.trim()
                UtcTime        = $rx.match($message[3]).Groups["capture"].Value.trim()
                Operation      = $rx.match($message[4]).Groups["capture"].Value.trim()
                User           = $rx.match($message[5]).Groups["capture"].Value.trim()
                EventNamespace = $rx.match($message[6]).Groups["capture"].Value.trim()
                Name           = $rx.match($message[7]).Groups["capture"].Value.trim()
                Query          = $rx.match($message[8]).Groups["capture"].Value.trim()

            }
            $WmiFilterObject = New-Object -TypeName WmiFilter -Property $Properties
            Write-Output $WmiFilterObject
        }
        # Creates Object for WMI Consumer Events
        elseif ($Event.Id -eq 20) {

            $Message = $Event.Message.split("`n")
            $Properties = @{
                
                EventId     = $Event.Id
                HostName    = $Event.MachineName
                TimeCreated = $Event.TimeCreated
                EventType   = $rx.match($message[2]).Groups["capture"].Value.trim()
                UtcTime     = $rx.match($message[3]).Groups["capture"].Value.trim()
                Operation   = $rx.match($message[4]).Groups["capture"].Value.trim()
                User        = $rx.match($message[5]).Groups["capture"].Value.trim()
                Name        = $rx.match($message[6]).Groups["capture"].Value.trim()
                Type        = $rx.match($message[7]).Groups["capture"].Value.trim()
                Destination = $rx.match($message[8]).Groups["capture"].Value.trim()
            }
            $WmiConsumerObject = New-Object -TypeName WmiConsumer -Property $Properties
            Write-Output $WmiConsumerObject
        }
        # Creates Object for WMI Consumer Events
        elseif ($Event.Id -eq 21) {

            $Message = $Event.Message.split("`n")
            $Properties = @{
                
                EventId     = $Event.Id
                HostName    = $Event.MachineName
                TimeCreated = $Event.TimeCreated
                EventType   = $rx.match($message[2]).Groups["capture"].Value.trim()
                UtcTime     = $rx.match($message[3]).Groups["capture"].Value.trim()
                Operation   = $rx.match($message[4]).Groups["capture"].Value.trim()
                User        = $rx.match($message[5]).Groups["capture"].Value.trim()
                Consumer    = $rx.match($message[6]).Groups["capture"].Value.trim()
                Filter      = $rx.match($message[7]).Groups["capture"].Value.trim()
            }
            $WmiBindingObject = New-Object -TypeName WmiBinding -Property $Properties
            Write-Output $WmiBindingObject
        }
        # Creates Object for DNS Query Events
        elseif ($Event.Id -eq 22) {

            $Message = $Event.Message.split("`n")
            $ProcImage = $rx.match($message[8]).Groups["capture"].Value.trim()
            $ProcName, $ProcDir = Get-ProcFromImagePath $ProcImage
            $Properties = @{

                EventId      = $Event.Id
                HostName     = $Event.MachineName
                TimeCreated  = $Event.TimeCreated
                EventType    = "DnsQuery"
                UtcTime      = $Event.TimeCreated.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff")
                ProcessGuid  = $rx.match($message[3]).Groups["capture"].Value.trim()
                ProcessId    = $rx.match($message[4]).Groups["capture"].Value.trim()
                Image        = $ProcImage
                QueryName    = $rx.match($message[5]).Groups["capture"].Value.trim()
                QueryStatus  = $rx.match($message[6]).Groups["capture"].Value.trim()
                QueryResults = $rx.match($message[7]).Groups["capture"].Value.trim()
                User         = $rx.match($message[9]).Groups["capture"].Value.trim()

                # Creating additional properties
                ProcessName  = $ProcName
                ProcessDir   = $ProcDir
            }

            $DnsQueryObject = New-Object -TypeName DnsQuery -Property $Properties
            Write-Output $DnsQueryObject
        }
        # Creates Object for File Delete Events
        elseif ($Event.Id -eq 23) {
            
            $Message = $Event.Message.split("`n")
            $Hashes = $rx.match($Message[8]).Groups["capture"].Value.trim()
            foreach ($Hash in $Hashes.split(",")) {
                $HashType, $HashValue = $Hash.split("=")
                if ($HashType -eq "MD5") {
                    $MD5Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "SHA256") {
                    $SHA256Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "SHA1") {
                    $SHA1Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "IMPHASH") {
                    $IMPHash = $HashValue.trim()
                }
            }
            $ProcImage = $rx.match($message[6]).Groups["capture"].Value.trim()
            $ProcName, $ProcDir = Get-ProcFromImagePath $ProcImage
            $Properties = @{
                
                EventId        = $Event.Id
                HostName       = $Event.MachineName
                TimeCreated    = $Event.TimeCreated
                EventType      = "FileDelete"
                UtcTime        = $rx.match($message[2]).Groups["capture"].Value.trim()
                ProcessGuid    = $rx.match($message[3]).Groups["capture"].Value.trim()
                ProcessId      = $rx.match($message[4]).Groups["capture"].Value.trim()
                User           = $rx.match($message[5]).Groups["capture"].Value.trim()
                Image          = $ProcImage
                TargetFilename = $rx.match($message[7]).Groups["capture"].Value.trim()
                Hashes         = $rx.match($message[8]).Groups["capture"].Value.trim()
                IsExecutable   = $rx.match($message[9]).Groups["capture"].Value.trim()
                Archived       = $rx.match($message[10]).Groups["capture"].Value.trim()

                # Creating additional properties
                MD5            = $MD5Hash
                SHA256         = $SHA256Hash
                SHA1           = $SHA1Hash
                IMPHASH        = $IMPHash
                ProcessName    = $ProcName
                ProcessDir     = $ProcDir
            }

            $FileDeleteObject = New-Object -TypeName FileDelete -Property $Properties
            Write-Output $FileDeleteObject
        }
        # Creates Object for Clipboard Change Events
        elseif ($Event.Id -eq 24) {
            
            $Message = $Event.Message.split("`n")
            $Hashes = $rx.match($Message[8]).Groups["capture"].Value.trim()
            foreach ($Hash in $Hashes.split(",")) {
                $HashType, $HashValue = $Hash.split("=")
                if ($HashType -eq "MD5") {
                    $MD5Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "SHA256") {
                    $SHA256Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "IMPHASH") {
                    $IMPHash = $HashValue.trim()
                }
            }
            $ProcImage = $rx.match($message[5]).Groups["capture"].Value.trim()
            $ProcName, $ProcDir = Get-ProcFromImagePath $ProcImage
            $Properties = @{
                
                EventId        = $Event.Id
                HostName       = $Event.MachineName
                TimeCreated    = $Event.TimeCreated
                EventType      = "ClipboardChange"
                UtcTime        = $rx.match($message[2]).Groups["capture"].Value.trim()
                ProcessGuid    = $rx.match($message[3]).Groups["capture"].Value.trim()
                ProcessId      = $rx.match($message[4]).Groups["capture"].Value.trim()
                Image          = $ProcImage
                Session        = $rx.match($message[6]).Groups["capture"].Value.trim()
                ClientInfo     = $rx.match($message[7]).Groups["capture"].Value.trim()
                Hashes         = $Hashes
                Archived       = $rx.match($message[9]).Groups["capture"].Value.trim()
                User           = $rx.match($message[10]).Groups["capture"].Value.trim()

                # Creating additional properties
                MD5            = $MD5Hash
                SHA256         = $SHA256Hash
                IMPHASH        = $IMPHash
                ProcessName    = $ProcName
                ProcessDir     = $ProcDir
            }

            $ClipboardChangeObject = New-Object -TypeName ClipboardChange -Property $Properties
            Write-Output $ClipboardChangeObject
        }
        # Creates Object for ProcessTampering Events
        elseif ($Event.Id -eq 25) {
            
            $Message = $Event.Message.split("`n")
            $ProcImage = $rx.match($message[5]).Groups["capture"].Value.trim()
            $ProcName, $ProcDir = Get-ProcFromImagePath $ProcImage
            $Properties = @{
                
                EventId        = $Event.Id
                HostName       = $Event.MachineName
                TimeCreated    = $Event.TimeCreated
                EventType      = "ProcessTampering"
                UtcTime        = $rx.match($message[2]).Groups["capture"].Value.trim()
                ProcessGuid    = $rx.match($message[3]).Groups["capture"].Value.trim()
                ProcessId      = $rx.match($message[4]).Groups["capture"].Value.trim()
                Image          = $ProcImage
                Type           = $rx.match($message[6]).Groups["capture"].Value.trim()
                User           = $rx.match($message[7]).Groups["capture"].Value.trim()

                # Creating additional properties
                HollowedProcessName    = $ProcName
                HollowedProcessDir     = $ProcDir
            }

            $ProcessTamperingObject = New-Object -TypeName ProcessTampering -Property $Properties
            Write-Output $ProcessTamperingObject
        }
        # Creates Object for FileDeleteDetected Events
        elseif ($Event.Id -eq 26) {
            
            $Message = $Event.Message.split("`n")
            $Hashes = $rx.match($Message[8]).Groups["capture"].Value.trim()
            foreach ($Hash in $Hashes.split(",")) {
                $HashType, $HashValue = $Hash.split("=")
                if ($HashType -eq "MD5") {
                    $MD5Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "SHA256") {
                    $SHA256Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "SHA1") {
                    $SHA1Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "IMPHASH") {
                    $IMPHash = $HashValue.trim()
                }
            }
            $ProcImage = $rx.match($message[6]).Groups["capture"].Value.trim()
            $ProcName, $ProcDir = Get-ProcFromImagePath $ProcImage
            $Properties = @{
                
                EventId        = $Event.Id
                HostName       = $Event.MachineName
                TimeCreated    = $Event.TimeCreated
                EventType      = "FileDeleteDetected"
                UtcTime        = $rx.match($message[2]).Groups["capture"].Value.trim()
                ProcessGuid    = $rx.match($message[3]).Groups["capture"].Value.trim()
                ProcessId      = $rx.match($message[4]).Groups["capture"].Value.trim()
                User           = $rx.match($message[5]).Groups["capture"].Value.trim()
                Image          = $ProcImage
                TargetFilename = $rx.match($message[7]).Groups["capture"].Value.trim()
                Hashes         = $rx.match($message[8]).Groups["capture"].Value.trim()
                IsExecutable   = $rx.match($message[9]).Groups["capture"].Value.trim()

                # Creating additional properties
                MD5            = $MD5Hash
                SHA256         = $SHA256Hash
                SHA1           = $SHA1Hash
                IMPHASH        = $IMPHash
                ProcessName    = $ProcName
                ProcessDir     = $ProcDir
            }

            $FileDeleteDetectedObject = New-Object -TypeName FileDeleteDetected -Property $Properties
            Write-Output $FileDeleteDetectedObject
        }
        # Creates Object for FileBlockExecutable Events
        elseif ($Event.Id -eq 27) {
            
            $Message = $Event.Message.split("`n")
            $Hashes = $rx.match($Message[8]).Groups["capture"].Value.trim()
            foreach ($Hash in $Hashes.split(",")) {
                $HashType, $HashValue = $Hash.split("=")
                if ($HashType -eq "MD5") {
                    $MD5Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "SHA256") {
                    $SHA256Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "SHA1") {
                    $SHA1Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "IMPHASH") {
                    $IMPHash = $HashValue.trim()
                }
            }
            $ProcImage = $rx.match($message[6]).Groups["capture"].Value.trim()
            $ProcName, $ProcDir = Get-ProcFromImagePath $ProcImage
            $Properties = @{
                
                EventId        = $Event.Id
                HostName       = $Event.MachineName
                TimeCreated    = $Event.TimeCreated
                EventType      = "FileBlockExecutable"
                UtcTime        = $rx.match($message[2]).Groups["capture"].Value.trim()
                RuleName       = $rx.match($message[1]).Groups["capture"].Value.trim()
                ProcessGuid    = $rx.match($message[3]).Groups["capture"].Value.trim()
                ProcessId      = $rx.match($message[4]).Groups["capture"].Value.trim()
                User           = $rx.match($message[5]).Groups["capture"].Value.trim()
                Image          = $ProcImage
                TargetFilename = $rx.match($message[7]).Groups["capture"].Value.trim()
                Hashes         = $Hashes

                # Creating additional properties
                MD5            = $MD5Hash
                SHA256         = $SHA256Hash
                SHA1           = $SHA1Hash
                IMPHASH        = $IMPHash
                ProcessName    = $ProcName
                ProcessDir     = $ProcDir
            }

            $FileBlockExecutableObject = New-Object -TypeName FileBlockExecutable -Property $Properties
            Write-Output $FileBlockExecutableObject
        }
        # Creates Object for FileBlockShredding Events
        elseif ($Event.Id -eq 28) {
            
            $Message = $Event.Message.split("`n")
            $Hashes = $rx.match($Message[8]).Groups["capture"].Value.trim()
            foreach ($Hash in $Hashes.split(",")) {
                $HashType, $HashValue = $Hash.split("=")
                if ($HashType -eq "MD5") {
                    $MD5Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "SHA256") {
                    $SHA256Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "SHA1") {
                    $SHA1Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "IMPHASH") {
                    $IMPHash = $HashValue.trim()
                }
            }
            $ProcImage = $rx.match($message[6]).Groups["capture"].Value.trim()
            $ProcName, $ProcDir = Get-ProcFromImagePath $ProcImage
            $Properties = @{
                
                EventId        = $Event.Id
                HostName       = $Event.MachineName
                TimeCreated    = $Event.TimeCreated
                EventType      = "FileBlockShredding"
                UtcTime        = $rx.match($message[2]).Groups["capture"].Value.trim()
                RuleName       = $rx.match($message[1]).Groups["capture"].Value.trim()
                ProcessGuid    = $rx.match($message[3]).Groups["capture"].Value.trim()
                ProcessId      = $rx.match($message[4]).Groups["capture"].Value.trim()
                User           = $rx.match($message[5]).Groups["capture"].Value.trim()
                Image          = $ProcImage
                TargetFilename = $rx.match($message[7]).Groups["capture"].Value.trim()
                Hashes         = $Hashes
                IsExecutable   = $rx.match($message[9]).Groups["capture"].Value.trim()

                # Creating additional properties
                MD5            = $MD5Hash
                SHA256         = $SHA256Hash
                SHA1           = $SHA1Hash
                IMPHASH        = $IMPHash
                ProcessName    = $ProcName
                ProcessDir     = $ProcDir
            }

            $FileBlockShreddingObject = New-Object -TypeName FileBlockShredding -Property $Properties
            Write-Output $FileBlockShreddingObject
        }
        # Creates Object for FileExecutableDetected Events
        elseif ($Event.Id -eq 29) {
            $Message = $Event.Message.split("`n")
            $Hashes = $rx.match($Message[8]).Groups["capture"].Value.trim()
            foreach ($Hash in $Hashes.split(",")) {
                $HashType, $HashValue = $Hash.split("=")
                if ($HashType -eq "MD5") {
                    $MD5Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "SHA256") {
                    $SHA256Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "SHA1") {
                    $SHA1Hash = $HashValue.trim()
                }
                elseif ($HashType -eq "IMPHASH") {
                    $IMPHash = $HashValue.trim()
                }
            }
            $ProcImage = $rx.match($message[6]).Groups["capture"].Value.trim()
            $ProcName, $ProcDir = Get-ProcFromImagePath $ProcImage
            $Properties = @{
                EventId = $Event.Id
                HostName = $Event.MachineName
                TimeCreated = $Event.TimeCreated
                EventType = "FileExecutableDetected"
                UtcTime = $rx.match($message[2]).Groups["capture"].Value.trim()
                RuleName = $rx.match($message[1]).Groups["capture"].Value.trim()
                ProcessGuid = $rx.match($message[3]).Groups["capture"].Value.trim()
                ProcessId = $rx.match($message[4]).Groups["capture"].Value.trim()
                User = $rx.match($message[5]).Groups["capture"].Value.trim()
                Image = $ProcImage
                TargetFilename = $rx.match($message[7]).Groups["capture"].Value.trim()
                Hashes = $Hashes

                # Creating additional properties
                MD5 = $MD5Hash
                SHA256 = $SHA256Hash
                SHA1 = $SHA1Hash
                IMPHASH = $IMPHash
                ProcessName = $ProcName
                ProcessDir = $ProcDir
            }

            $FileExecutableDetectedObject = New-Object -TypeName FileExecutableDetected -Property $Properties
            Write-Output $FileExecutableDetectedObject
        }
    }
}

# Exporting only the required cmdlets
Export-ModuleMember ConvertTo-GarudaObjects