# Garuda - Threat Hunting and Investigation Framework

**Garuda** is a PowerShell-based threat hunting and investigation framework that transforms raw Sysmon events into structured, actionable intelligence for Windows environments.

Garuda serves as both an investigation/hunting tool for security analysts and an educational platform for learning threat hunting methodologies. With 28+ investigation commands covering all Sysmon event types, it's suitable for individual analysts, security teams, researchers, and students developing cybersecurity skills.

## Garuda Key Capabilities

### 🎓 **Learn Threat Hunting Methodologies**
- Master process execution analysis and parent-child relationships
- Understand file system monitoring and suspicious behaviors
- Study network connection patterns and DNS query analysis
- Learn registry analysis and persistence detection techniques

### 🔬 **Practice and Research Security Analysis**
- Experiment with detection logic across all Sysmon event types (1-29)
- Develop and test threat hunting hypotheses with real data
- Research attack patterns for code injection and lateral movement
- Study advanced malware behaviors and evasion techniques

### 🛡️ **Conduct Investigations**
- Analyze security incidents with comprehensive Sysmon coverage
- Hunt for threats using advanced correlation and filtering
- Investigate suspicious activities across multiple view formats
- Perform remote and offline analysis for incident response (still in testing phase)

### ⚡ **Platform Capabilities**
- **28+ Investigation Commands** covering all Sysmon event types
- **Multiple Analysis Views** (Timeline, Interactive Tables, Detailed, Summary)
- **Advanced Filtering** by any event attribute with wildcard support
- **Remote & Offline Analysis (still in testing phase)** for flexible investigation workflows
- **PowerShell 7.0 Integration** with automatic module loading

Whether you're learning security analysis, researching detection methods, developing investigation skills, or conducting threat hunting on systems running Sysmon, Garuda provides a comprehensive platform to explore and analyze Sysmon telemetry.

## Requirements

- **Windows 10** or **Windows Server 2016** or later
- **PowerShell 7.0** or later ([Download here](https://github.com/PowerShell/PowerShell/releases))
- **Sysmon must be installed and configured** before using Garuda
  - Download and install from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
  - Version 10.0 or later recommended (current: v15.15)
  - **Important**: Use a filtered Sysmon configuration file that enables logging for required events
  - Verify Sysmon is generating events: `Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5`
- **Administrative privileges** for full functionality
- **PowerShell Execution Policy** set to allow script execution

**Garuda** leverages PowerShell 7.0's autoload functionality - simply install to your module path and start investigating!

## Installation

1. **Download the Repository**
   
   **Option A: Using Git**
   ```powershell
   git clone https://github.com/monnappa22/Garuda-framework.git
   ```
   
   **Option B: Direct Download**
   - Download ZIP from [GitHub repository](https://github.com/monnappa22/Garuda-framework)
   - Extract to a folder (e.g., `C:\Garuda-framework`)

2. **Install Garuda Module**

   **Choose your installation scope:** You can install Garuda either for the current user only or system-wide for all users.

   #### **Option A: Current User Installation (Recommended)**
   *Installs only for your user account, no admin privileges required for installation*
   
   **Note**: While installation doesn't require admin privileges, running Garuda commands will require administrator privileges to access Sysmon logs.

   **Method 1: Using PowerShell Commands**
   1. Open PowerShell in the downloaded/extracted Garuda-framework folder
   2. Run the following command:
   ```powershell
   # Current user installation
   $UserModulePath = [Environment]::GetFolderPath('MyDocuments') + '\PowerShell\Modules'
   Copy-Item -Path ".\Garuda" -Destination "$UserModulePath\Garuda" -Recurse -Force
   ```

   **Method 2: Manual Copy Using File Explorer**
   1. **Locate or create your PowerShell Modules directory:**
      - Path: `C:\Users\{YourUsername}\Documents\PowerShell\Modules`
      - **If the folder doesn't exist**: Create the folder structure manually:
        1. Navigate to `C:\Users\{YourUsername}\Documents`
        2. Create a `PowerShell` folder (if it doesn't exist)
        3. Inside PowerShell folder, create a `Modules` folder
   
   2. **Copy the Garuda folder:**
      - From: `C:\Garuda-framework\Garuda` (your extracted folder)
      - To: `C:\Users\{YourUsername}\Documents\PowerShell\Modules\Garuda`
      - Use Ctrl+C and Ctrl+V or right-click → Copy/Paste
   
   3. **Verify the structure:**
      ```
      C:\Users\{YourUsername}\Documents\PowerShell\Modules\
      └── Garuda\
          └── Investigate\
              ├── GarudaMods\
              ├── GarudaObj\
              └── GarudaRaw\
      ```

   #### **Option B: System-wide Installation**
   *Installs for all users on the system, requires administrator privileges*

   **Method 1: Using PowerShell Commands (Run as Administrator)**
   1. Open PowerShell **as Administrator** in the downloaded/extracted Garuda-framework folder
   2. Run the following command:
   ```powershell
   # System-wide installation (requires admin)
   $SystemModulePath = "$env:ProgramFiles\PowerShell\Modules"
   Copy-Item -Path ".\Garuda" -Destination "$SystemModulePath\Garuda" -Recurse -Force
   ```

   **Method 2: Manual Copy Using File Explorer (Run as Administrator)**
   1. **Open File Explorer as Administrator**
   2. **Navigate to system modules directory:**
      - Path: `C:\Program Files\PowerShell\Modules`
   3. **Copy the Garuda folder:**
      - From: `C:\Garuda-framework\Garuda` (your extracted folder)
      - To: `C:\Program Files\PowerShell\Modules\Garuda`
   4. **Verify the structure:**
      ```
      C:\Program Files\PowerShell\Modules\
      └── Garuda\
          └── Investigate\
              ├── GarudaMods\
              ├── GarudaObj\
              └── GarudaRaw\
      ```

3. **Set PowerShell Execution Policy** (if needed)
   ```powershell
   # Check current execution policy
   Get-ExecutionPolicy
   
   # Set execution policy to bypass restrictions (recommended for Garuda)
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser
   ```

4. **Verify Installation**
   ```powershell
   # Test with a simple command (should show all available investigation cmdlets)
   Get-Command -Name "Investigate-*" -Module Garuda*
   ```

**Note**: PowerShell 7.0+ will automatically load modules when you use their commands, so no manual importing is needed.

## Getting Started

### Prerequisites for Garuda Commands

⚠️ **Important**: Launch **PowerShell 7 as Administrator** to execute Garuda commands (required for accessing Sysmon logs).

**Quick launch**: Search "PowerShell 7" → Right-click → "Run as administrator"

### Command Discovery

Learn how to explore Garuda's capabilities:

```powershell
# List all Investigation commands
Get-Command -Name "Investigate-*"
```

### Investigation Cmdlets Reference

Garuda provides comprehensive investigation commands for all Sysmon event types:

| Garuda Command | Sysmon Event | Event ID | Description |
|--------|--------------|----------|-------------|
| `Investigate-ProcInfo` | Process Creation | 1 | Investigate process creation events with command lines, hashes, and parent processes |
| `Investigate-FileCreateTimeChange` | File Create Time Change | 2 | Investigate file timestamp modification events |
| `Investigate-NetworkConnections` | Network Connection | 3 | Investigate network connections with source/destination analysis |
| `Investigate-SysmonServiceStateChange` | Sysmon State Change | 4 | Investigate Sysmon configuration changes |
| `Investigate-ProcTerminated` | Process Termination | 5 | Investigate process termination events |
| `Investigate-DriverInfo` | Driver Load | 6 | Investigate driver loading with signature verification |
| `Investigate-ImageLoadInfo` | Image/DLL Load | 7 | Investigate module/DLL loading events |
| `Investigate-RemoteThreadInfo` | Remote Thread Creation | 8 | Investigate remote thread injection attempts |
| `Investigate-RawAccessInfo` | Raw Access Read | 9 | Investigate raw disk access events |
| `Investigate-ProcessAccessInfo` | Process Access | 10 | Investigate inter-process access attempts |
| `Investigate-FileCreateInfo` | File Create | 11 | Investigate file creation events |
| `Investigate-RegCreateDeleteInfo` | Registry Key Create/Delete | 12 | Investigate registry key creation and deletion |
| `Investigate-RegSetValueInfo` | Registry Value Set | 13 | Investigate registry value modifications |
| `Investigate-RegRenameInfo` | Registry Key Rename | 14 | Investigate registry key renaming |
| `Investigate-FileStreamHashInfo` | File Stream Creation | 15 | Investigate alternate data stream creation |
| `Investigate-ServiceConfigInfo` | Service Configuration Change | 16 | Investigate Windows service configuration changes |
| `Investigate-PipeCreateInfo` | Named Pipe Creation | 17 | Investigate named pipe creation |
| `Investigate-PipeConnectInfo` | Named Pipe Connection | 18 | Investigate named pipe connections |
| `Investigate-WmiFilterInfo` | WMI Event Filter | 19 | Investigate WMI event filter activity |
| `Investigate-WmiConsumerInfo` | WMI Event Consumer | 20 | Investigate WMI event consumer activity |
| `Investigate-WmiBindingInfo` | WMI Event Consumer To Filter Binding | 21 | Investigate WMI consumer/filter bindings |
| `Investigate-DnsQueryInfo` | DNS Query | 22 | Investigate DNS resolution requests |
| `Investigate-FileDeleteInfo` | File Delete | 23 | Investigate file deletion events |
| `Investigate-ClipboardChangeInfo` | Clipboard Change | 24 | Investigate clipboard content changes |
| `Investigate-ProcessTamperingInfo` | Process Tampering | 25 | Investigate process image tampering |
| `Investigate-FileDeleteDetectedInfo` | File Delete Detected | 26 | Investigate detected file deletions |
| `Investigate-FileBlockExecutableInfo` | File Block Executable | 27 | Investigate blocked executable files |
| `Investigate-FileBlockShreddingInfo` | File Block Shredding | 28 | Investigate blocked file shredding attempts |
| `Investigate-FileExecutableDetectedInfo` | File Executable Detected | 29 | Investigate detected executable files |

### Your First Command

Start with this simple command to see recent process activity:

```powershell
Investigate-ProcInfo
```

This will display process creation events for the last 15 minutes (default timeframe).

**Expected Result**: You should see detailed process creation events. If you see:
- **No events returned**: Sysmon might not be generating Process Creation (Event ID 1) events
- **Error messages**: Check the [Troubleshooting](#troubleshooting) section
- **Events displayed**: Success! You're ready to explore more

### Getting Information on Command Parameters

Learn how to get detailed help for any investigation command:

```powershell
# Get basic parameter information for commands
Get-Help Investigate-ProcInfo
Get-Help Investigate-NetworkConnections
```

This shows you all available parameters for each command.

### Common Parameters

Most `Investigate-*` cmdlets share these useful parameters:

**Time Filtering** - Control the time range of events to analyze:
- `-PastSeconds`, `-PastMinutes`, `-PastHours`, `-PastDays` - Look back from now
- `-FromLocalTime` and `-ToLocalTime` - Specific time range  
- `-FromUtcTime` and `-ToUtcTime` - UTC time range

**Analysis Location** - Choose where to investigate events:
- `-ComputerName` - Investigate remote systems
- `-Credential` - Credentials for remote access
- `-LogFile` - Analyze offline .evtx files

**Event Specific Filters** - Filter by attributes specific to each event type:
- `-ProcessName`, `-DestinationIp`, `-TargetFilename`, `-RegKey`, etc.

### Understanding Output Views

All `Investigate-*` cmdlets support different output formats via the `-View` parameter:

| View Option | Description | Best For |
|-------------|-------------|----------|
| `Detailed` | Full event details (default) | Deep analysis of specific events |
| `Summary` | Condensed overview | Quick assessment of activity patterns |
| `InteractiveTable` | Sortable, filterable table | Exploring and correlating events |
| `Timeline` | Chronological event list | Understanding sequence of events |
| `TimelineList` | Detailed timeline format | Forensic timeline analysis |



## Command Examples

### Process Investigation
```powershell
# Process creation in the last 2 hours with detailed view
Investigate-ProcInfo -PastHours 2 -View "Detailed"

# Focus on specific process - show only cmd.exe launches in the last hour
Investigate-ProcInfo -ProcessName "cmd.exe" -PastHours 1

# Use wildcards to find processes - show all svchost processes in the last 20 minutes
Investigate-ProcInfo -ProcessName "*svchost*" -PastMinutes 20

# Specify exact time range using PowerShell's flexible datetime formats
Investigate-ProcInfo -FromUtcTime "2024-01-15 09:00" -ToUtcTime "2024-01-15 17:00"
```

### Network Investigation
```powershell
# Show network connections in chronological order over the last 4 hours
Investigate-NetworkConnections -PastHours 4 -View "Timeline"

# Find all connections to Google DNS server in the last day
Investigate-NetworkConnections -DestinationIp "8.8.8.8" -PastDays 1
```

### File System Investigation
```powershell
# View all file creation events in chronological order for the last 2 hours
Investigate-FileCreateInfo -PastHours 2 -View "Timeline"

# Monitor suspicious activity - find files created in any Temp folder in the last 6 hours
Investigate-FileCreateInfo -TargetFilename "*\Temp\*" -PastHours 6
```

### Registry Investigation
```powershell
# View registry value changes with sortable/filterable table for the last hour
Investigate-RegSetValueInfo -PastHours 1 -View "InteractiveTable"

# Watch for persistence - monitor changes to Windows startup registry key
Investigate-RegSetValueInfo -RegKey "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

### Remote Analysis (Testing Phase)
```powershell
# Note: Remote analysis is in testing phase - use with caution
# Requires: PowerShell remoting must be enabled on the target system
# Investigate process activity on a remote computer with authentication
$Credential = Get-Credential
Investigate-ProcInfo -ComputerName "RemotePC" -Credential $Credential -PastHours 24
```

### Offline Analysis (Testing Phase)
```powershell
# Note: Offline analysis is in testing phase - use with caution
# Requires: Sysmon and Garuda to be installed on the analysis system
# Analyze pre-collected Sysmon logs in timeline format for forensic analysis
Investigate-ProcInfo -LogFile "C:\Logs\sysmon.evtx" -View "Timeline"
```

## Troubleshooting

### Check PowerShell Version
```powershell
$PSVersionTable.PSVersion  # Should be 7.0 or higher
```

### Verify Sysmon is Running and Generating Events
```powershell
# Check Sysmon service status
Get-Service sysmon

# Verify Sysmon is generating events (should show recent events)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5

# Check if Process Creation events (ID 1) are being generated
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterHashtable @{ID=1} -MaxEvents 3
```

**If no events**: Your Sysmon configuration may not be enabling the required events. Consider using a comprehensive Sysmon configuration file.

### Module Loading Issues
```powershell
# Check modules are available
Get-Module -ListAvailable Garuda*

# Force reload if needed
Remove-Module Garuda* -Force
```

## Frequently Asked Questions

### Q: What if my investigation returns no results?
**A:** Check that Sysmon is generating events for the time period you're investigating. Start with `-PastMinutes 30` for recent activity.

### Q: How do I know which cmdlet to use for my investigation?
**A:** Start with `Investigate-ProcInfo` for process activity, `Investigate-NetworkConnections` for network activity, or use the reference table to find cmdlets by Event ID.

### Q: How far back can I search?
**A:** This depends on your Sysmon log retention settings. Windows Event Log has size limits that will affect how far back events are available.

### Q: Which installation method should I choose (user vs system)?
**A:** Use **user installation** if you don't have admin privileges or want to keep Garuda for your account only. Use **system installation** if you want all users to access Garuda.

### Q: How do I configure Sysmon properly for Garuda?
**A:** Use a filtered Sysmon configuration that enables logging for required events. Popular configurations available from the community:
- **SwiftOnSecurity's sysmon-config**: [https://github.com/SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
- **Olaf Hartong's Sysmon-Modular**: [https://github.com/olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)

### Q: What if I get "execution policy" errors?
**A:** Run `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser` to allow PowerShell script execution for your user account.

## Support & Resources

### Featured Content
- **AI-Powered Threat Hunting**: Watch how LLMs can perform autonomous threat hunting with Garuda - [Watch Video](https://youtu.be/Sk_c5w1CEiY)

### Getting Help
- **Issues**: Report bugs or request features on [GitHub Issues](https://github.com/monnappa22/Garuda-framework/issues)
- **Documentation**: Check cmdlet help with `Get-Help <cmdlet-name>` 
- **Community**: Engage with other users and developers

### Stay Updated
- **Twitter**: Follow [@monnappa22](https://x.com/monnappa22) for updates and detailed documentation (coming soon!)
- **YouTube**: Subscribe to [MonnappaKA](https://www.youtube.com/c/MonnappaKA) for video tutorials (more videos coming soon!)

### Contributing
Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest enhancements.

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed contribution guidelines.

## License

Garuda uses a **dual license model** to support both open source use and commercial applications:

### 🆓 Open Source Use (GPL v3)
**For personal, educational, research, and open source projects:**
- ✅ **Free to use, modify, and distribute**
- ✅ **Full source code access**
- ✅ **Community contributions welcome**
- 📋 **Requirements**: Derivative works must be GPL v3, source code must be shared

### 💼 Commercial Use (Commercial License)
**For commercial products and proprietary applications:**
- ✅ **No GPL v3 restrictions** - keep your modifications private
- ✅ **Embed in closed-source products**
- 💡 **Contact**: [monnappa22@gmail.com](mailto:monnappa22@gmail.com?subject=Garuda%20Commercial%20License%20Inquiry)

### Which License Do I Need?

**Choose GPL v3 if:**
- You can share your source code modifications
- You're building open source applications
- You want to contribute to the community

**Choose Commercial License if:**
- You need to keep modifications proprietary
- You're embedding in commercial products
- You can't comply with GPL v3 requirements

See [LICENSE](LICENSE) for complete terms and commercial licensing options.

### Copyright
© 2025 Monnappa K A. All rights reserved.

**For Inquiries**: [monnappa22@gmail.com](mailto:monnappa22@gmail.com)

---