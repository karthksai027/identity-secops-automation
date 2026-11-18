<#
.SYNOPSIS
    Runs a Microsoft Defender XDR advanced hunting query (inline or from a .kql file) through Microsoft Graph and saves the results to CSV.

.DESCRIPTION
    Lets you run the same KQL you'd type into the Defender portal from PowerShell, so hunts can
    be scripted, scheduled, or run across a whole folder of queries in one go.

    Pass a query with -Query, or point -Path at one or more .kql files (for example the queries in
    SC-200-Threat-Hunting\Defender-XDR). Comment lines are fine; they're sent as part of the query.
    Each query's results are written to their own CSV and returned as objects.

    Advanced hunting covers 30 days of data and returns up to 100,000 rows per query.

    Read-only.

.PARAMETER Query
    KQL text to run.

.PARAMETER Path
    One or more .kql files to run. Wildcards allowed.

.PARAMETER Timespan
    Optional ISO 8601 duration to limit the time range (for example P7D for seven days).
    If omitted, the time filter inside the query applies.

.PARAMETER OutputDirectory
    Folder for the CSV results. Default: .\Reports

.EXAMPLE
    .\Invoke-DefenderAdvancedHunting.ps1 -Query 'DeviceInfo | summarize arg_max(Timestamp, *) by DeviceId | count'

.EXAMPLE
    .\Invoke-DefenderAdvancedHunting.ps1 -Path ..\SC-200-Threat-Hunting\Defender-XDR\*.kql -Verbose

.NOTES
    Author      : Karthik (github.com/karthksai027)
    Project     : Karthik's Identity & SecOps Toolkit
    Module      : Microsoft.Graph.Authentication
    Scopes      : ThreatHunting.Read.All
    Role        : Security Reader
    Licence     : Microsoft Defender XDR. Tables you can query depend on which Defender workloads you own.

.LINK
    https://github.com/karthksai027/identity-secops-automation
#>

#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(DefaultParameterSetName = 'Inline')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Inline')]
    [ValidateNotNullOrEmpty()]
    [string]$Query,

    [Parameter(Mandatory, ParameterSetName = 'File')]
    [string[]]$Path,

    [ValidatePattern('^P(\d+D)?(T(\d+H)?(\d+M)?)?$')]
    [string]$Timespan,

    [string]$OutputDirectory = (Join-Path -Path (Get-Location) -ChildPath 'Reports')
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-GraphIfNeeded {
    param([Parameter(Mandatory)][string[]]$Scopes)
    $ctx = Get-MgContext
    if (-not $ctx) {
        Connect-MgGraph -Scopes $Scopes -NoWelcome
        $ctx = Get-MgContext
    }
    if ($ctx.AuthType -eq 'Delegated') {
        $missing = $Scopes | Where-Object { $_ -notin $ctx.Scopes }
        if ($missing) { Write-Warning "Graph session is missing scopes: $($missing -join ', '). Reconnect with Connect-MgGraph -Scopes $($Scopes -join ',')" }
    }
    $ctx
}

function Invoke-GraphPaged {
    param([Parameter(Mandatory)][string]$Uri)
    $items = New-Object System.Collections.Generic.List[object]
    while ($Uri) {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject
        if ($resp.PSObject.Properties.Name -contains 'value') { foreach ($v in $resp.value) { $items.Add($v) } }
        else { $items.Add($resp) }
        $Uri = $resp.'@odata.nextLink'
    }
    , $items.ToArray()
}
#endregion

Connect-GraphIfNeeded -Scopes 'ThreatHunting.Read.All' | Out-Null

$jobs = @()
if ($PSCmdlet.ParameterSetName -eq 'Inline') {
    $jobs += [PSCustomObject]@{ Name = 'InlineQuery'; Text = $Query }
}
else {
    foreach ($file in (Get-ChildItem -Path $Path -File)) {
        $jobs += [PSCustomObject]@{ Name = $file.BaseName; Text = (Get-Content -Path $file.FullName -Raw) }
    }
    if ($jobs.Count -eq 0) { throw "No .kql files found at '$($Path -join ', ')'." }
}

if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
$stamp = '{0:yyyyMMdd_HHmm}' -f (Get-Date)

foreach ($job in $jobs) {
    $body = @{ Query = $job.Text }
    if ($Timespan) { $body.Timespan = $Timespan }

    Write-Verbose "Running hunting query '$($job.Name)'..."
    try {
        $resp = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' `
            -Body ($body | ConvertTo-Json -Depth 3) -ContentType 'application/json' -OutputType PSObject
    }
    catch {
        Write-Warning "Query '$($job.Name)' failed: $($_.Exception.Message)"
        continue
    }

    $columns = @($resp.schema | ForEach-Object { $_.name })
    $rows = foreach ($r in @($resp.results)) {
        $o = [ordered]@{}
        foreach ($c in $columns) {
            $v = $r.$c
            # Flatten dynamic columns so they survive CSV export
            if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { $v = ($v | ConvertTo-Json -Depth 5 -Compress) }
            elseif ($v -is [psobject] -and $v.PSObject.Properties.Count -gt 0 -and $v -isnot [string] -and $v -isnot [datetime] -and $v -isnot [ValueType]) { $v = ($v | ConvertTo-Json -Depth 5 -Compress) }
            $o[$c] = $v
        }
        [PSCustomObject]$o
    }
    $rows = @($rows)

    $csv = Join-Path $OutputDirectory ("Hunting_{0}_{1}.csv" -f ($job.Name -replace '[^A-Za-z0-9_-]', '_'), $stamp)
    $rows | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    Write-Verbose ("'{0}': {1} row(s), {2} column(s) -> {3}" -f $job.Name, $rows.Count, $columns.Count, $csv)

    $rows | ForEach-Object { $_ | Add-Member -NotePropertyName QueryName -NotePropertyValue $job.Name -PassThru }
}
