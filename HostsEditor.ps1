# region GlobalVariables
$banner = @"
 _   _           _       
| | | | ___  ___| |_ ___ 
| |_| |/ _ \/ __| __/ __|
|  _  | (_) \__ \ |_\__ \
|_| |_|\___/|___/\__|___/                        
 _____    _ _ _             
| ____|__| (_) |_ ___  _ __ 
|  _| / _` | | __/ _ \| '__|
| |__| (_| | | || (_) | |   
|_____\__,_|_|\__\___/|_|   
"@


# Define constants for paths
$hostsPath = "$env:windir\system32\drivers\etc\hosts"
$backupPath = "$env:LOCALAPPDATA\CBB\hosts.bak"

$disabledComment = "DISABLED BY APPLICATION"

$defaultHostsContent = @"
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should 
# be placed in the first column followed by the corresponding host name. 
# The IP address and the host name should be separated by at least one 
# space. 
# 
# Additionally, comments (such as these) may be inserted on individual 
# lines or following the machine name denoted by a '#' symbol. 
# 
# For example: 
# 
#      102.54.94.97     rhino.acme.com          # source server 
#       38.25.63.10     x.acme.com              # x client host 
# 
# localhost name resolution is handled within DNS itself. 
#	127.0.0.1       localhost 
#	::1             localhost 
"@

enum AppModes {
    Main
    Edit
}

[AppModes]$currentMode = [AppModes]::Main

enum MainMenuOptions {
    Edit
    View
    Backup
    Restore
    Help
    Quit
}

enum EditMenuOptions {
    Add
    Remove
    Enable
    Disable
    View
    Backup
    Restore
    Help
    Quit
}
# endregion GlobalVariables

function Show-Banner {
    Clear-Host
    Write-Host $banner -ForegroundColor Green
    Write-Host "-cantbebroken@protonmail.com-" -ForegroundColor Cyan
    Write-Host ""
}

function Show-Prompt {
    [boolean]$isAdmin = Get-IsAdmin

    if (-not $isAdmin) {
        Write-Host "You need to run as an Administrator." -ForegroundColor Red
    }

    Write-Host "┍─╼[$env:USERNAME@$env:COMPUTERNAME]"
    Write-Host "┝─╼[$(Get-Date)]"

    if ($currentMode -eq [AppModes]::Edit) {
        Write-Host -NoNewLine "┝─╼["
        Write-Host -NoNewLine "✎ EDIT MODE" -ForegroundColor Green
        Write-Host "]"
    }
    
    Write-Host -NoNewLine "┕─► "
}

function Get-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)

    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        # Write-Host "You have administrative privileges."
        return $true
    }
    else {
        # Write-Host "You do not have administrative privileges."
        return $false
    }
}

function Sanitize-Input([string]$data) {
    return $data -replace "([\.\^\$\*\+\?\{\}\[\]\\\|\(\)])", '`$1'
}

function FlushDNSCache {
    Write-Host "Flushing DNS cache..."
    ipconfig /flushdns | Out-Null
    Write-Host "DNS cache has been flushed."
}

function Show-MainModeHelp {
    Write-Host "edit - editing mode" -ForegroundColor Green
    Write-Host "view - display the hosts file" -ForegroundColor Green
    Write-Host "backup - backup the hosts file" -ForegroundColor Green
    Write-Host "restore - restore the hosts file" -ForegroundColor Green
    Write-Host "help - show this help message" -ForegroundColor Green
    Write-Host "quit - quit the program" -ForegroundColor Green
}

function Show-EditModeHelp {
    Write-Host "add <ip> <hostname> - add an entry to the hosts file" -ForegroundColor Green
    Write-Host "remove <ip> <hostname> - remove an entry" -ForegroundColor Green
    Write-Host "enable <ip> <hostname> - enable an entry" -ForegroundColor Green
    Write-Host "disable <ip> <hostname> - disable an entry" -ForegroundColor Green
    Write-Host "view - display the hosts file" -ForegroundColor Green
    Write-Host "backup - backup the hosts file" -ForegroundColor Green
    Write-Host "restore - restore the hosts file" -ForegroundColor Green
    Write-Host "help - show this help message" -ForegroundColor Green
    Write-Host "quit - back to Main Menu" -ForegroundColor Green
}

function Show-HostsAsTable {
    # Read the hosts file and split each line into an array
    $hostsLines = Get-Content $hostsPath

    # Process each line to extract the IP and hostname, and determine if it's enabled or disabled
    $hostsEntries = foreach ($line in $hostsLines) {
        if ($line -match '^\s*([\d.]+)\s+(.*)$') {
            $enabled = $false
            if ($line -notmatch "^#\s*$disabledComment") {
                $enabled = $true
            }
            New-Object PSObject -Property @{
                IPAddress = $matches[1]
                HostName  = $matches[2]
                Enabled   = $enabled
            }
        }
    }

    # Display the entries in a table format
    $hostsEntries | Format-Table -Property IPAddress, HostName, Enabled -AutoSize
}

function Backup-HostsFile {
    if (-not (Test-Path -Path $backupPath)) {
        New-Item -Path $backupPath -Force | Out-Null
    }

    Get-Content -Path $hostsPath | Set-Content -Path $backupPath
    Write-Host "Backup complete."
}

function Restore-HostsBackup {
    if (Test-Path -Path $backupPath) {
        Get-Content -Path $backupPath | Set-Content -Path $hostsPath
    }
    else {
        Set-Content -Path $hostsPath -Value $defaultHostsContent
    }
}

function Enable-Entry([string]$address, [string]$hostName) {
    # Construct the disabled entry pattern with the special comment
    $disabledEntryPattern = "^#\s*$disabledComment\s*$address\s+$hostName$"

    # Read the hosts file
    $fileContent = Get-Content -Path $hostsPath

    # Find the disabled entry and replace it with the enabled version
    $enabledContent = $fileContent -creplace $disabledEntryPattern, "$address`t$hostName"

    # Write the updated content back to the hosts file
    $enabledContent | Set-Content -Path $hostsPath

    FlushDNSCache
}

function Disable-Entry([string]$address, [string]$hostName) {
    # Construct the entry with a special comment
    
    $entry = "$address`t$hostName"
    $disabledEntry = "# $disabledComment`t$entry"

    # Read the hosts file
    $fileContent = Get-Content -Path $hostsPath

    # Replace the active entry with the disabled entry
    $updatedContent = $fileContent -replace "^$address\s+$hostName$", $disabledEntry

    # Write the updated content back to the hosts file
    $updatedContent | Out-File -FilePath $hostsPath

    FlushDNSCache
}

function Add-Entry([string]$address, [string]$hostName) {
    
    # Construct the entry with at least one space between IP and hostname
    $entry = "$address`t$hostName"

    # Regular expression pattern to match the entry in the hosts file
    $pattern = "^$address\s+$hostName$"

    # Check if the entry already exists in the hosts file
    $existingEntry = Get-Content -Path $hostsPath | Where-Object { $_ -cmatch $pattern }


    if ($existingEntry) {
        Write-Host ""
        Write-Host "URL $entry is already in the hosts file."
    }
    else {
        # Add the entry to the hosts file if it does not exist
        Add-Content -Path $hostsPath -Value $entry
        Write-Host ""
        Write-Host "URL $entry successfully added to the hosts file."
    }

    FlushDNSCache
}

function Remove-Entry([string]$address, [string]$hostName) {
    # Construct the entry pattern
    $entryPattern = "^$address\s+$hostName$"

    # Read the hosts file
    $fileContent = Get-Content -Path $hostsPath

    # Filter out the line to remove
    $filteredContent = $fileContent | Where-Object { $_ -notmatch $entryPattern }

    # Write the filtered content back to the hosts file
    $filteredContent | Set-Content -Path $hostsPath -Force

    FlushDNSCache
}

function CheckAndSanitizeEntry([string]$address, [string]$hostName) {
    if (-not $address) {
        $address = "127.0.0.1"
    }

    if ($address -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        Write-Host "Invalid IP address format. Please enter a valid IP address."
        return
    }

    if (-not $hostName) {
        Write-Host "Hostname cannot be empty."
        return
    }

    # Sanitize input to escape special characters
    $sanitizedAddress = Sanitize-Input $address
    $sanitizedHostName = Sanitize-Input $hostName

    return $sanitizedAddress, $sanitizedHostName
}



function Invoke-MainMode($command) {

    # if (-not ([System.Enum]::IsDefined([MainMenuOptions], $command))) {
    #     Write-Host "Invalid option specified. Please use one of the following: " -ForegroundColor Red
    #     Show-MainModeHelp
    # }
    
    if ($command -eq [MainMenuOptions]::Edit) {
        $Global:currentMode = [AppModes]::Edit
    }

    if ($command -eq [MainMenuOptions]::Help) {
        Show-MainModeHelp
    }

    if ($command -eq [MainMenuOptions]::View) {
        Show-HostsAsTable
    }

    if ($command -eq [MainMenuOptions]::Backup) {
        Backup-HostsFile
    }

    if ($command -eq [MainMenuOptions]::Restore) {
        Restore-HostsBackup
    }

    if ($command -eq [MainMenuOptions]::Quit) {
        exit 0
    }

    if ($command -eq "exit") {
        exit 0
    }
    
}

function Invoke-EditMode([string]$userInput) {

    # Split the input string into parts
    $parts = $userInput -split '\s+'

    $command = $parts[0]

    # if (-not ([System.Enum]::IsDefined([EditMenuOptions], $command))) {
    #     Write-Host "Invalid option specified. Please use one of the following: " -ForegroundColor Red
    #     Show-EditModeHelp
    # }

    if ($command -eq [EditMenuOptions]::Quit) {
        $Global:currentMode = [AppModes]::Main
    }

    if ($command -eq "exit") {
        $Global:currentMode = [AppModes]::Main
    }

    if ($command -eq [EditMenuOptions]::Help) {
        Show-EditModeHelp
    }

    if ($command -eq [EditMenuOptions]::View) {
        Show-HostsAsTable
    }

    if ($command -eq [EditMenuOptions]::Backup) {
        Backup-HostsFile
    }

    if ($command -eq [EditMenuOptions]::Restore) {
        Restore-HostsBackup
    }

    $ipAddress = $parts[1]
    $hostName = $parts[2]
    
    if ($command -eq [EditMenuOptions]::Add) {
        $ipAddress, $hostName = CheckAndSanitizeEntry $ipAddress $hostName
        Add-Entry $ipAddress $hostName
    }

    if ($command -eq [EditMenuOptions]::Remove) {
        $ipAddress, $hostName = CheckAndSanitizeEntry $ipAddress $hostName
        Remove-Entry $ipAddress $hostName
    }

    if ($command -eq [EditMenuOptions]::Enable) {
        $ipAddress, $hostName = CheckAndSanitizeEntry $ipAddress $hostName
        Enable-Entry $ipAddress $hostName
    }

    if ($command -eq [EditMenuOptions]::Disable) {
        $ipAddress, $hostName = CheckAndSanitizeEntry $ipAddress $hostName
        Disable-Entry $ipAddress $hostName
    }

}

# Main loop
Show-Banner
while ($true) {
    Show-Prompt

    $userInput = Read-Host

    if ($currentMode -eq [AppModes]::Main) {
        Invoke-MainMode $userInput
    }
    else {
        Invoke-EditMode $userInput
    }
}
