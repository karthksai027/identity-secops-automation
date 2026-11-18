<#
.SYNOPSIS
    Collects a hardware asset register (serial, model, CPU, RAM, disk, MAC, IP, user) from domain computers over WinRM/CIM.

.DESCRIPTION
    1. Reads computer objects from AD (whole domain or one OU), or uses -ComputerName.
    2. Tests WinRM reachability first so unreachable machines fail fast.
    3. Opens one CIM session per machine and collects hardware, network and user data.
       If nobody is signed in, the last logged-on user is read from the registry.
    4. Writes reachable machines to an asset register CSV and unreachable or failed machines
       to a separate CSV with the reason.

    Useful for asset registers, licence true-ups, and for scoping endpoint controls
    (for example confirming every machine in a device-control OU is accounted for).

    Read-only on target machines.

.PARAMETER SearchBase
    Distinguished name of the OU to inventory. Default: whole domain.

.PARAMETER ComputerName
    Explicit list of computer FQDNs. Overrides the AD lookup.

.PARAMETER Credential
    Optional credential for the CIM connections.

.PARAMETER IncludeDisabled
    Include disabled computer objects from AD (skipped by default).

.PARAMETER OutputDirectory
    Folder for the CSV reports. Default: .\Reports

.EXAMPLE
    .\Get-ADHardwareInventory.ps1 -SearchBase "OU=Workstations,DC=contoso,DC=com" -Verbose

.EXAMPLE
    .\Get-ADHardwareInventory.ps1 -ComputerName pc01.contoso.com, pc02.contoso.com -Credential (Get-Credential)

.NOTES
    Author      : Karthik (github.com/karthksai027)
    Project     : Karthik's Identity & SecOps Toolkit
    Permissions : Local administrator on target machines; read access to computer objects in AD.
    Requires    : WinRM enabled on targets (Enable-PSRemoting or GPO), TCP 5985/5986 open.
    Module      : ActiveDirectory (RSAT)

.LINK
    https://github.com/karthksai027/identity-secops-automation
#>

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

[CmdletBinding(DefaultParameterSetName = 'AD')]
param(
    [Parameter(ParameterSetName = 'AD')]
    [string]$SearchBase,

    [Parameter(ParameterSetName = 'AD')]
    [switch]$IncludeDisabled,

    [Parameter(ParameterSetName = 'List', Mandatory)]
    [string[]]$ComputerName,

    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty,

    [string]$OutputDirectory = (Join-Path -Path (Get-Location) -ChildPath 'Reports')
)

$ErrorActionPreference = 'Stop'

# ---- Step 1: Target list ----
if ($PSCmdlet.ParameterSetName -eq 'AD') {
    $adParams = @{
        Filter     = if ($IncludeDisabled) { '*' } else { 'Enabled -eq $true' }
        Properties = 'DNSHostName'
    }
    if ($SearchBase) { $adParams.SearchBase = $SearchBase }
    $targets = @(Get-ADComputer @adParams | Where-Object DNSHostName | Select-Object -ExpandProperty DNSHostName)
}
else {
    $targets = $ComputerName
}
Write-Verbose "Target computers: $($targets.Count)"

$sessionParams = @{ ErrorAction = 'Stop'; OperationTimeoutSec = 30 }
if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) { $sessionParams.Credential = $Credential }

$assets = New-Object System.Collections.Generic.List[object]
$failed = New-Object System.Collections.Generic.List[object]
$i = 0

foreach ($fqdn in $targets) {
    $i++
    Write-Progress -Activity 'Hardware inventory' -Status $fqdn -PercentComplete (($i / [math]::Max($targets.Count, 1)) * 100)

    # ---- Step 2: WinRM pre-check ----
    try {
        Test-WSMan -ComputerName $fqdn -ErrorAction Stop | Out-Null
    }
    catch {
        $failed.Add([PSCustomObject]@{ FQDN = $fqdn; Stage = 'WinRM'; Reason = 'WinRM not reachable' })
        continue
    }

    # ---- Step 3: Collect ----
    $session = $null
    try {
        $session = New-CimSession -ComputerName $fqdn @sessionParams

        $cs   = Get-CimInstance -CimSession $session -ClassName Win32_ComputerSystem
        $bios = Get-CimInstance -CimSession $session -ClassName Win32_BIOS
        $os   = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem
        $cpu  = Get-CimInstance -CimSession $session -ClassName Win32_Processor | Select-Object -First 1
        $disk = (Get-CimInstance -CimSession $session -ClassName Win32_LogicalDisk -Filter 'DriveType=3' |
                 Measure-Object -Property Size -Sum).Sum
        $nics = @(Get-CimInstance -CimSession $session -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True')

        $primaryNic = $nics | Where-Object DefaultIPGateway | Select-Object -First 1
        if (-not $primaryNic) { $primaryNic = $nics | Select-Object -First 1 }

        $user = $cs.UserName
        $userSource = 'Signed in'
        if (-not $user) {
            $reg = Invoke-CimMethod -CimSession $session -ClassName StdRegProv -MethodName GetStringValue -Arguments @{
                hDefKey     = [uint32]2147483650   # HKEY_LOCAL_MACHINE
                sSubKeyName = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI'
                sValueName  = 'LastLoggedOnUser'
            }
            $user = $reg.sValue
            $userSource = 'Last logged on'
        }

        $assets.Add([PSCustomObject]@{
            MachineName     = $cs.Name
            FQDN            = $fqdn
            Manufacturer    = $cs.Manufacturer
            Model           = $cs.Model
            SerialNumber    = $bios.SerialNumber
            OperatingSystem = $os.Caption
            OSBuild         = $os.BuildNumber
            LastBootTime    = $os.LastBootUpTime
            Processor       = $cpu.Name
            RAM_GB          = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
            Disk_GB         = if ($disk) { [math]::Round($disk / 1GB, 1) } else { $null }
            MACAddress1     = if ($nics.Count -ge 1) { $nics[0].MACAddress } else { $null }
            MACAddress2     = if ($nics.Count -ge 2) { $nics[1].MACAddress } else { $null }
            IPv4Address     = if ($primaryNic) { $primaryNic.IPAddress | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -First 1 } else { $null }
            HasGateway      = [bool]($primaryNic -and $primaryNic.DefaultIPGateway)
            User            = $user
            UserSource      = $userSource
            CollectedOn     = Get-Date
        })
    }
    catch {
        $failed.Add([PSCustomObject]@{ FQDN = $fqdn; Stage = 'CIM'; Reason = $_.Exception.Message })
    }
    finally {
        if ($session) { Remove-CimSession -CimSession $session }
    }
}
Write-Progress -Activity 'Hardware inventory' -Completed

# ---- Step 4: Export ----
if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
$stamp      = '{0:yyyyMMdd_HHmm}' -f (Get-Date)
$assetPath  = Join-Path $OutputDirectory "Hardware_AssetRegister_$stamp.csv"
$failedPath = Join-Path $OutputDirectory "Hardware_Unreachable_$stamp.csv"

$assets | Export-Csv -Path $assetPath -NoTypeInformation -Encoding UTF8
$failed | Export-Csv -Path $failedPath -NoTypeInformation -Encoding UTF8

Write-Verbose ("Collected: {0}. Failed: {1}. Register: {2}. Failures: {3}" -f $assets.Count, $failed.Count, $assetPath, $failedPath)
$assets
