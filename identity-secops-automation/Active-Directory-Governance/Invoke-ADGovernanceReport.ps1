<#
.SYNOPSIS
    Runs the full monthly Active Directory governance pack and writes an HTML summary.

.DESCRIPTION
    Orchestrates the individual scripts in this repository into one dated evidence folder:

      Users inventory           Active-Directory-Governance\Get-ADUserInventory.ps1
      Inactive users            Active-Directory-Governance\Get-ADInactiveUser.ps1
      Stale disabled users      Active-Directory-Governance\Get-ADStaleDisabledUser.ps1
      Privileged group members  Active-Directory-Governance\Get-ADPrivilegedGroupMember.ps1
      Computer inventory        Endpoint-Asset-Inventory\Get-ADComputerInventory.ps1
      Security posture          Identity-Security-Posture\Get-ADSecurityPostureSummary.ps1

    Produces a CSV per report plus Summary.html for managers and auditors.
    Schedule monthly under a gMSA with Task Scheduler.

    Read-only.

.PARAMETER InactiveDays
    Inactivity threshold for users. Default: 90.

.PARAMETER DisabledDays
    Threshold for stale disabled users. Default: 180.

.PARAMETER StaleComputerDays
    Threshold for stale computers. Default: 60.

.PARAMETER Server
    Optional domain controller or domain to query.

.PARAMETER OutputRoot
    Parent folder; a dated sub-folder is created per run. Default: .\Reports

.EXAMPLE
    .\Invoke-ADGovernanceReport.ps1 -OutputRoot '\\fileserver\Audit$\AD' -Verbose

.NOTES
    Author      : Karthik (github.com/karthksai027)
    Project     : Karthik's Identity & SecOps Toolkit
    Permissions : Read access to AD users, computers and groups.
    Module      : ActiveDirectory (RSAT)

.LINK
    https://github.com/karthksai027/identity-secops-automation
#>

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [ValidateRange(1, 3650)][int]$InactiveDays = 90,
    [ValidateRange(1, 3650)][int]$DisabledDays = 180,
    [ValidateRange(1, 3650)][int]$StaleComputerDays = 60,
    [string]$Server,
    [string]$OutputRoot = (Join-Path -Path (Get-Location) -ChildPath 'Reports')
)

$ErrorActionPreference = 'Stop'

$repoRoot  = Split-Path -Path $PSScriptRoot -Parent
$runFolder = Join-Path $OutputRoot ("ADGovernance_{0:yyyyMMdd_HHmm}" -f (Get-Date))
New-Item -Path $runFolder -ItemType Directory -Force | Out-Null

$common = @{ OutputDirectory = $runFolder }
if ($Server) { $common.Server = $Server }

$jobs = [ordered]@{
    'User inventory'           = @{ Path = 'Active-Directory-Governance\Get-ADUserInventory.ps1';         Args = @{} }
    'Inactive users'           = @{ Path = 'Active-Directory-Governance\Get-ADInactiveUser.ps1';          Args = @{ DaysInactive = $InactiveDays } }
    'Stale disabled users'     = @{ Path = 'Active-Directory-Governance\Get-ADStaleDisabledUser.ps1';     Args = @{ DaysDisabled = $DisabledDays } }
    'Privileged group members' = @{ Path = 'Active-Directory-Governance\Get-ADPrivilegedGroupMember.ps1'; Args = @{ InactiveDays = $InactiveDays } }
    'Computer inventory'       = @{ Path = 'Endpoint-Asset-Inventory\Get-ADComputerInventory.ps1';        Args = @{ StaleDays = $StaleComputerDays } }
    'Security posture'         = @{ Path = 'Identity-Security-Posture\Get-ADSecurityPostureSummary.ps1';  Args = @{ InactiveDays = $InactiveDays } }
}

$results = @{}
$summary = foreach ($name in $jobs.Keys) {
    $script = Join-Path $repoRoot ($jobs[$name].Path -replace '\\', [IO.Path]::DirectorySeparatorChar)
    $params = $common + $jobs[$name].Args
    Write-Verbose "Running: $name"
    try {
        $data = @(& $script @params)
        $results[$name] = $data
        [PSCustomObject]@{ Report = $name; Rows = $data.Count; Status = 'OK'; Error = '' }
    }
    catch {
        [PSCustomObject]@{ Report = $name; Rows = 0; Status = 'Failed'; Error = $_.Exception.Message }
    }
}

# ---- Key metrics ----
$computers = @($results['Computer inventory'])
$priv      = @($results['Privileged group members'])
$metrics = [ordered]@{
    'Enabled users'                       = @($results['User inventory']).Count
    "Inactive users ($InactiveDays d)"    = @($results['Inactive users']).Count
    "Stale disabled users ($DisabledDays d)" = @($results['Stale disabled users']).Count
    'Unique privileged users'             = @($priv | Where-Object ObjectClass -eq 'user' | Select-Object -ExpandProperty SamAccountName -Unique).Count
    'Privileged members with findings'    = @($priv | Where-Object Findings).Count
    'Computers'                           = $computers.Count
    "Stale computers ($StaleComputerDays d)" = @($computers | Where-Object IsStale).Count
    'Legacy OS computers'                 = @($computers | Where-Object IsLegacyOS).Count
}

# ---- HTML summary ----
$style = @'
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1f2937}
h1{font-size:20px} h2{font-size:16px;margin-top:28px}
table{border-collapse:collapse;min-width:480px} th,td{border:1px solid #d1d5db;padding:6px 10px;text-align:left;font-size:13px}
th{background:#f3f4f6} .Risk{color:#b91c1c;font-weight:600} .Review{color:#b45309;font-weight:600} .OK{color:#15803d}
</style>
'@
function ConvertTo-HtmlText { param($Value) [System.Net.WebUtility]::HtmlEncode("$Value") }

$metricRows  = ($metrics.GetEnumerator() | ForEach-Object { "<tr><td>$(ConvertTo-HtmlText $_.Key)</td><td>$(ConvertTo-HtmlText $_.Value)</td></tr>" }) -join ''
$postureRows = (@($results['Security posture']) | ForEach-Object {
    "<tr><td>$(ConvertTo-HtmlText $_.Category)</td><td>$(ConvertTo-HtmlText $_.Check)</td><td>$(ConvertTo-HtmlText $_.Value)</td><td class='$($_.Status)'>$($_.Status)</td><td>$(ConvertTo-HtmlText $_.Recommendation)</td></tr>"
}) -join ''
$runRows     = ($summary | ForEach-Object { "<tr><td>$($_.Report)</td><td>$($_.Rows)</td><td class='$(if ($_.Status -eq 'OK') {'OK'} else {'Risk'})'>$($_.Status)</td><td>$(ConvertTo-HtmlText $_.Error)</td></tr>" }) -join ''

$html = @"
<html><head><meta charset='utf-8'><title>AD Governance Report</title>$style</head><body>
<h1>Active Directory Governance Report</h1>
<p>Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') by $([Environment]::UserName) with Karthik's Identity &amp; SecOps Toolkit. Detailed CSVs are in this folder.</p>
<h2>Key metrics</h2><table><tr><th>Metric</th><th>Value</th></tr>$metricRows</table>
<h2>Security posture</h2><table><tr><th>Category</th><th>Check</th><th>Value</th><th>Status</th><th>Recommendation</th></tr>$postureRows</table>
<h2>Run status</h2><table><tr><th>Report</th><th>Rows</th><th>Status</th><th>Error</th></tr>$runRows</table>
</body></html>
"@
$htmlPath = Join-Path $runFolder 'Summary.html'
Set-Content -Path $htmlPath -Value $html -Encoding UTF8

Write-Verbose "Governance pack written to $runFolder"
$summary
