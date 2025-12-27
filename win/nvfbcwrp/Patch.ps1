# NVFBC DLL patch script
# Requires administrator privileges to run
param(
    [switch]$Force
)

Function Test-Administrator {
    [OutputType([bool])]
    param()
    process {
        [Security.Principal.WindowsPrincipal]$user = [Security.Principal.WindowsIdentity]::GetCurrent();
        return $user.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);
    }
} #end function Test-Administrator
Function Test-CommandExist {
    Param ($Command)
    $OldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    try { if (Get-Command $Command) { RETURN $true } }
    Catch { RETURN $false }
    Finally { $ErrorActionPreference = $OldPreference }
} #end function Test-CommandExist
If (Test-CommandExist pwsh.exe) {
    $pwsh = "pwsh.exe"
}
Else {
    $pwsh = "powershell.exe"
}
If (-Not (Test-Administrator)) {
    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force
    $forceParam = if ($Force) { " -Force" } else { "" }
    $Proc = Start-Process -PassThru -Verb RunAs $pwsh -Args "-ExecutionPolicy Bypass -Command Set-Location '$PSScriptRoot'; &'$PSCommandPath' EVAL$forceParam"
    If ($null -Ne $Proc) {
        $Proc.WaitForExit()
    }
    If ($null -Eq $Proc -Or $Proc.ExitCode -Ne 0) {
        Write-Warning "Failed to launch start as Administrator`r`nPress any key to exit"
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
    }
    exit
}
ElseIf (($args.Count -Ge 1) -And ($args[0] -Eq "EVAL")) {
    $forceParam = if ($Force) { " -Force" } else { "" }
    Start-Process $pwsh -NoNewWindow -Args "-ExecutionPolicy Bypass -Command Set-Location '$PSScriptRoot'; &'$PSCommandPath'$forceParam"
    exit
}
Function Unlock-DLL {
    param (
        [string]$filePath
    )

    # Check if the file exists
    if (-Not (Test-Path -Path $filePath)) {
        Write-Error "The specified file does not exist."
        exit
    }

    Write-Host "Unlocking file: $filePath"

    # Get the file security object
    $fileSecurity = Get-Acl -Path $filePath

    # Set the owner to "Administrators"
    $administrators = [System.Security.Principal.NTAccount]"Administrators"
    $fileSecurity.SetOwner($administrators)

    # Apply the new owner to the file
    Set-Acl -Path $filePath -AclObject $fileSecurity

    # Define a new access rule for "Administrators" with full control
    $administratorsRights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($administrators, $administratorsRights, [System.Security.AccessControl.InheritanceFlags]::None, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)

    # Add the new access rule to the file security object
    $fileSecurity.AddAccessRule($accessRule)

    # Apply the updated security settings to the file
    Set-Acl -Path $filePath -AclObject $fileSecurity

    Write-Host "Owner changed to 'Administrators' and full control permissions granted to 'Administrators' for file: $filePath"
} #end function Unlock-DLL
Write-Host "Starting NVFBC DLL patch..."

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$system32Path = "$env:WINDIR\system32"
$sysWOW64Path = "$env:WINDIR\SysWOW64"

$originalNvFBC64 = "$system32Path\NvFBC64.dll"
$originalNvFBC32 = "$sysWOW64Path\NvFBC.dll"

$backupNvFBC64 = "$system32Path\NvFBC64_.dll"
$backupNvFBC32 = "$sysWOW64Path\NvFBC_.dll"

$wrapperNvFBC64 = "$scriptDir\nvfbcwrp64.dll"
$wrapperNvFBC32 = "$scriptDir\nvfbcwrp32.dll"

# Download wrapper DLLs if not found locally
$nvfbcwrp64Url = "https://gist.github.com/Snawoot/17b14e7ce0f7412b91587c2723719eff/raw/e8e9658fd20751ad875477f37b49ea158ece896d/nvfbcwrp64.dll"
$nvfbcwrp32Url = "https://gist.github.com/Snawoot/17b14e7ce0f7412b91587c2723719eff/raw/e8e9658fd20751ad875477f37b49ea158ece896d/nvfbcwrp32.dll"

if (-Not (Test-Path $wrapperNvFBC64)) {
    Write-Host "nvfbcwrp64.dll not found locally. Downloading from GitHub..."
    try {
        Invoke-WebRequest -Uri $nvfbcwrp64Url -OutFile $wrapperNvFBC64 -UseBasicParsing
        Write-Host "[OK] nvfbcwrp64.dll downloaded successfully"
    }
    catch {
        throw "Failed to download nvfbcwrp64.dll: $($_.Exception.Message)"
    }
}

if (-Not (Test-Path $wrapperNvFBC32)) {
    Write-Host "nvfbcwrp32.dll not found locally. Downloading from GitHub..."
    try {
        Invoke-WebRequest -Uri $nvfbcwrp32Url -OutFile $wrapperNvFBC32 -UseBasicParsing
        Write-Host "[OK] nvfbcwrp32.dll downloaded successfully"
    }
    catch {
        throw "Failed to download nvfbcwrp32.dll: $($_.Exception.Message)"
    }
}

try {
    # Helper function to check if file sizes are similar (within 10% tolerance)
    function Test-SimilarFileSize {
        param (
            [string]$file1,
            [string]$file2,
            [double]$tolerance = 0.10
        )

        if (-Not (Test-Path $file1) -or -Not (Test-Path $file2)) {
            return $false
        }

        $size1 = (Get-Item $file1).Length
        $size2 = (Get-Item $file2).Length

        $diff = [Math]::Abs($size1 - $size2)
        $avgSize = ($size1 + $size2) / 2

        return ($diff / $avgSize) -le $tolerance
    }

    # Step 1: Backup NvFBC64.dll
    if (Test-Path $originalNvFBC64) {
        # Check if the current file is already the wrapper (similar size) unless -Force is used
        if (-Not $Force -and (Test-SimilarFileSize $originalNvFBC64 $wrapperNvFBC64)) {
            Write-Host "NvFBC64.dll appears to already be patched (similar size to wrapper), skipping backup"
        }
        else {
            if ($Force) {
                Write-Host "Force flag set, backing up current file regardless of size"
            }
            Write-Host "Rename $originalNvFBC64 to $backupNvFBC64"
            Unlock-DLL $originalNvFBC64
            Move-Item -Path $originalNvFBC64 -Destination $backupNvFBC64 -Force
            Write-Host "[OK] NvFBC64.dll backup completed"
        }
    }
    else {
        Write-Warning "NvFBC64.dll not found"
    }

    # Step 2: Backup NvFBC.dll
    if (Test-Path $originalNvFBC32) {
        # Check if the current file is already the wrapper (similar size) unless -Force is used
        if (-Not $Force -and (Test-SimilarFileSize $originalNvFBC32 $wrapperNvFBC32)) {
            Write-Host "NvFBC.dll appears to already be patched (similar size to wrapper), skipping backup"
        }
        else {
            if ($Force) {
                Write-Host "Force flag set, backing up current file regardless of size"
            }
            Write-Host "Rename $originalNvFBC32 to $backupNvFBC32"
            Unlock-DLL $originalNvFBC32
            Move-Item -Path $originalNvFBC32 -Destination $backupNvFBC32 -Force
            Write-Host "[OK] NvFBC.dll backup completed"
        }
    }
    else {
        Write-Warning "NvFBC.dll not found"
    }

    # Step 3: Copy 64-bit wrapper to system32
    if (Test-Path $wrapperNvFBC64) {
        Write-Host "Copy $wrapperNvFBC64 to $originalNvFBC64"
        Copy-Item -Path $wrapperNvFBC64 -Destination $originalNvFBC64 -Force
        Write-Host "[OK] 64-bit wrapper copied"
    }
    else {
        throw "nvfbcwrp64.dll not found"
    }

    # Step 4: Copy 32-bit wrapper SysWOW64
    if (Test-Path $wrapperNvFBC32) {
        Write-Host "Copy $wrapperNvFBC32 to $originalNvFBC32"
        Copy-Item -Path $wrapperNvFBC32 -Destination $originalNvFBC32 -Force
        Write-Host "[OK] 32-bit wrapper copied"
    }
    else {
        throw "nvfbcwrp32.dll not found"
    }
}
catch {
    Write-Error "$($_.Exception.Message)" -ErrorAction Continue
    Write-Error "Patch install failed!" -ErrorAction Continue
    Write-Host "Rolling back changes..."
    if ((Test-Path $backupNvFBC64) -and (-not (Test-Path $originalNvFBC64))) {
        Move-Item -Path $backupNvFBC64 -Destination $originalNvFBC64 -Force -ErrorAction SilentlyContinue
    }
    if ((Test-Path $backupNvFBC32) -and (-not (Test-Path $originalNvFBC32))) {
        Move-Item -Path $backupNvFBC32 -Destination $originalNvFBC32 -Force -ErrorAction SilentlyContinue
    }
    Read-Host "Press to stop."
    exit 1
}

pause
# End
