# Gets the raw events for the specified time and you can also filter the events based on the event id
function Get-SysmonRawEvents {

    [CmdletBinding(PositionalBinding = $false)]
    param (

        [parameter(Mandatory = $false, Position = 0)]
        [int[]] $EventId,

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
        [string[]] $LogFile
    )

    # Setting the start and the end time based on the specified parameter
    $CurrentDateTime = Get-Date
    $CurrentUtcDateTime = [System.DateTime]::UtcNow

    # Check if mixing Local and UTC time parameters
    if (($FromLocalTime -ne $null -and $FromUtcTime -ne $null) -or
        ($ToLocalTime -ne $null -and $ToUtcTime -ne $null) -or
        ($FromLocalTime -ne $null -and $ToUtcTime -ne $null) -or
        ($FromUtcTime -ne $null -and $ToLocalTime -ne $null)) {
        Write-Error "Cannot mix LocalTime and UtcTime parameters. Please use either LocalTime or UtcTime format consistently."
        return
    }
   
    if ($FromLocalTime -ne $null) {
        $Start = $FromLocalTime
        if ($ToLocalTime -eq $null){
            $End = $CurrentDateTime
        }
        else {
            $End = $ToLocalTime
        }
    }
    elseif ($FromUtcTime -ne $null) {
        # Convert UTC times to local time for Windows Event filtering
        $Start = $FromUtcTime.ToLocalTime()
        if ($ToUtcTime -eq $null){
            $End = $CurrentUtcDateTime.ToLocalTime()
        }
        else {
            $End = $ToUtcTime.ToLocalTime()
        }
    }
    else {
        # If no time parameters specified, default to last 15 minutes
        if (($PastMinutes -eq 0) -and ($PastSeconds -eq 0) -and ($PastHours -eq 0) -and ($PastDays -eq 0)) {
            $Start = $CurrentDateTime.AddMinutes(-15)
        }
        else {
            # Calculate total timespan using all components
            $Start = $CurrentDateTime.AddDays(-$PastDays).
                                    AddHours(-$PastHours).
                                    AddMinutes(-$PastMinutes).
                                    AddSeconds(-$PastSeconds)
        }
        $End = $CurrentDateTime
    }


    $FilterHashtable = @{

        logname = 'Microsoft-Windows-Sysmon/Operational'
        id = $EventId
        StartTime = $Start
        EndTime = $End
    }

    if ($EventId.Count -eq 0) {
        
        $FilterHashtable.Remove("id")
    }


    if ($LogFile.count -ne 0) {

        $FilterHashtable.remove("logname")
        $FilterHashtable.add("Path", $LogFile)
        if(($FromLocalTime -eq $null) -and ($FromUtcTime -eq $null) -and 
           (($PastMinutes -eq 0) -and ($PastSeconds -eq 0) -and ($PastHours -eq 0) -and ($PastDays -eq 0))){
            $FilterHashtable.remove("StartTime")
            $FilterHashtable.remove("EndTime")
        }
    }


    # Gets events from the logfile (offline analysis)
    If ($FilterHashtable.contains("Path")) {

        Get-WinEvent -FilterHashtable $FilterHashtable
    }

    # Get Events from the sysmon event logs
    else {

        if ($null -eq $Credential) {

            Get-WinEvent -FilterHashtable $FilterHashtable -ComputerName $ComputerName
        }
        else {
    
            Get-WinEvent -FilterHashtable $FilterHashtable -ComputerName $ComputerName -Credential $Credential
        }
    }
}
