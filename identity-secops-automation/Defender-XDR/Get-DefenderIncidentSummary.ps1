<#
.SYNOPSIS
    Morning triage view of Microsoft Defender XDR incidents: what's open, what's high severity, what nobody owns, and what's been sitting too long.

.DESCRIPTION
    Pulls incidents from the Microsoft Graph security API (the same incidents you see in the
    Defender portal, correlated across Defender for Endpoint, Identity, Office 365 and Cloud Apps)
    and turns them into a short triage list.

    Each incident is flagged when it is:
      - High severity and still open
      - Open and not assigned to anyone
      - Open for longer than -StaleDays
      - Resolved without a classification (true positive / false positive / informational),
        which leaves gaps in reporting and tuning

    A summary by severity, status and detection source is printed with -Verbose, and both the
    incident list and the per-alert breakdown are written to CSV.

    Read-only.

.PARAMETER Days
    How far back to look, based on incident creation time. Default: 7.

.PARAMETER StaleDays
    Open incidents older than this are flagged. Default: 3.

.PARAMETER OpenOnly
    Return only incidents that are still active or in progress.

.PARAMETER OutputDirectory
    Folder for the CSV reports. Default: .\Reports

.EXAMPLE
    .\Get-DefenderIncidentSummary.ps1 -Verbose | Where-Object Findings | Format-Table Severity, Title, AssignedTo, AgeDays, Findings

.EXAMPLE
    .\Get-DefenderIncidentSummary.ps1 -Days 30 -OpenOnly

.NOTES
    Author      : Karthik (github.com/karthksai027)
    Project     : Karthik's Identity & SecOps Toolkit
    Module      : Microsoft.Graph.Authentication
    Scopes      : SecurityIncident.Read.All
    Role        : Security Reader (or Security Operator)
    Licence     : Microsoft Defender XDR (any Defender workload that raises incidents)

.LINK
    https://github.com/karthksai027/identity-secops-automation
#>

#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [ValidateRange(1, 180)]
    [int]$Days = 7,

    [ValidateRange(1, 365)]
    [int]$StaleDays = 3,

    [switch]$OpenOnly,

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

Connect-GraphIfNeeded -Scopes 'SecurityIncident.Read.All' | Out-Null

$now   = Get-Date
$since = $now.ToUniversalTime().AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
$uri   = "https://graph.microsoft.com/v1.0/security/incidents?`$filter=createdDateTime ge $since&`$expand=alerts&`$top=50"

Write-Verbose "Reading incidents created since $since..."
$incidents = Invoke-GraphPaged -Uri $uri

$alertRows = New-Object System.Collections.Generic.List[object]

$report = foreach ($i in $incidents) {
    $isOpen = $i.status -in 'active', 'inProgress'
    if ($OpenOnly -and -not $isOpen) { continue }

    $created = [datetime]$i.createdDateTime
    $age     = [math]::Round(($now - $created).TotalDays, 1)
    $alerts  = @($i.alerts)

    foreach ($a in $alerts) {
        $alertRows.Add([PSCustomObject]@{
            IncidentId      = $i.id
            AlertTitle      = $a.title
            Severity        = $a.severity
            Status          = $a.status
            ServiceSource   = $a.serviceSource
            DetectionSource = $a.detectionSource
            Category        = $a.category
            MitreTechniques = (@($a.mitreTechniques) -join ', ')
            Created         = $a.createdDateTime
        })
    }

    $findings = New-Object System.Collections.Generic.List[string]
    if ($isOpen -and $i.severity -eq 'high') { $findings.Add('High severity and open') }
    if ($isOpen -and -not $i.assignedTo)     { $findings.Add('Unassigned') }
    if ($isOpen -and $age -gt $StaleDays)    { $findings.Add("Open for more than $StaleDays days") }
    if ($i.status -eq 'resolved' -and ($i.classification -in $null, '', 'unknown')) { $findings.Add('Resolved without classification') }

    [PSCustomObject]@{
        IncidentId     = $i.id
        Title          = $i.displayName
        Severity       = $i.severity
        Status         = $i.status
        AssignedTo     = $i.assignedTo
        Classification = $i.classification
        Determination  = $i.determination
        AlertCount     = $alerts.Count
        Sources        = (@($alerts | ForEach-Object { $_.serviceSource } | Where-Object { $_ } | Sort-Object -Unique) -join ', ')
        Created        = $created
        LastUpdated    = $i.lastUpdateDateTime
        AgeDays        = $age
        Findings       = $findings -join '; '
        PortalUrl      = $i.incidentWebUrl
    }
}

$severityRank = @{ high = 0; medium = 1; low = 2; informational = 3 }
$report = @($report | Sort-Object @{ e = { if ($severityRank.ContainsKey("$($_.Severity)")) { $severityRank["$($_.Severity)"] } else { 9 } } }, @{ e = 'AgeDays'; Descending = $true })

if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
$stamp = '{0:yyyyMMdd_HHmm}' -f $now
$report    | Export-Csv -Path (Join-Path $OutputDirectory "Defender_Incidents_$stamp.csv") -NoTypeInformation -Encoding UTF8
$alertRows | Export-Csv -Path (Join-Path $OutputDirectory "Defender_IncidentAlerts_$stamp.csv") -NoTypeInformation -Encoding UTF8

Write-Verbose ("Incidents: {0}. Open: {1}. High and open: {2}. Unassigned and open: {3}." -f $report.Count,
    @($report | Where-Object { $_.Status -in 'active', 'inProgress' }).Count,
    @($report | Where-Object { $_.Findings -match 'High severity' }).Count,
    @($report | Where-Object { $_.Findings -match 'Unassigned' }).Count)
Write-Verbose ("By source:`n" + ($alertRows | Group-Object ServiceSource | Sort-Object Count -Descending | ForEach-Object { "  $($_.Name): $($_.Count)" } | Out-String))

$report
