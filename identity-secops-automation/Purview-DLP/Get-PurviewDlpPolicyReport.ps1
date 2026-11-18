<#
.SYNOPSIS
    Shows what Microsoft Purview DLP actually protects: which policies are enforced, which are still in test mode, which workloads have no coverage, and which sensitive data types nobody is watching.

.DESCRIPTION
    It's common to find DLP policies that were created, left in "test" mode, and forgotten. This
    report connects to Security & Compliance PowerShell and lists every DLP policy and rule with:

      - Mode           : Enforced, Test with notifications, Test without notifications, or Off
      - Workloads      : Exchange, SharePoint, OneDrive, Teams, Endpoint devices
      - Sensitive info : the sensitive information types each rule looks for
      - Action         : whether the rule blocks, or only notifies / reports

    It then checks coverage and flags:
      - Workloads with no enforced DLP policy
      - Policies left in test mode
      - Enforced rules that never block anything
      - Sensitive information types from -RequiredSensitiveTypes that no enforced rule covers
      - No published sensitivity labels

    The default -RequiredSensitiveTypes include Indian PAN and Aadhaar alongside card and bank numbers.

    Read-only.

.PARAMETER RequiredSensitiveTypes
    Sensitive information type names that should be covered by at least one enforced rule.

.PARAMETER OutputDirectory
    Folder for the CSV reports. Default: .\Reports

.EXAMPLE
    .\Get-PurviewDlpPolicyReport.ps1 | Format-Table Check, Status, Detail -AutoSize

.EXAMPLE
    .\Get-PurviewDlpPolicyReport.ps1 -RequiredSensitiveTypes 'Credit Card Number', 'U.S. Social Security Number (SSN)'

.NOTES
    Author      : Karthik (github.com/karthksai027)
    Project     : Karthik's Identity & SecOps Toolkit
    Module      : ExchangeOnlineManagement v3 (Connect-IPPSSession)
    Role        : Compliance Administrator, Compliance Data Administrator, or Global Reader
    Licence     : Microsoft 365 E3 for Exchange/SharePoint/OneDrive DLP; E5 (or E5 Compliance) for Teams and Endpoint DLP

.LINK
    https://github.com/karthksai027/identity-secops-automation
#>

#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [string[]]$RequiredSensitiveTypes = @(
        'Credit Card Number'
        'International Banking Account Number (IBAN)'
        'India Permanent Account Number (PAN)'
        'India Unique Identification (Aadhaar) number'
    ),

    [string]$OutputDirectory = (Join-Path -Path (Get-Location) -ChildPath 'Reports')
)

$ErrorActionPreference = 'Stop'

# Security & Compliance cmdlets only exist after Connect-IPPSSession
if (-not (Get-Command -Name Get-DlpCompliancePolicy -ErrorAction SilentlyContinue)) {
    Write-Verbose 'Connecting to Security & Compliance PowerShell...'
    Connect-IPPSSession -ShowBanner:$false
}

$modeName = @{
    Enable                    = 'Enforced'
    TestWithNotifications     = 'Test (with notifications)'
    TestWithoutNotifications  = 'Test (silent)'
    Disable                   = 'Off'
    PendingDeletion           = 'Pending deletion'
}

$workloadMap = [ordered]@{
    Exchange   = 'ExchangeLocation'
    SharePoint = 'SharePointLocation'
    OneDrive   = 'OneDriveLocation'
    Teams      = 'TeamsLocation'
    Endpoint   = 'EndpointDlpLocation'
}

function Get-RuleSensitiveType {
    param($Rule)
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($entry in @($Rule.ContentContainsSensitiveInformation)) {
        if ($null -eq $entry) { continue }
        if ($entry -is [System.Collections.IDictionary]) {
            if ($entry['name']) { $names.Add([string]$entry['name']) }
            foreach ($g in @($entry['groups'] | Where-Object { $_ })) {
                foreach ($s in @($g['sensitivetypes'] | Where-Object { $_ })) { if ($s['name']) { $names.Add([string]$s['name']) } }
            }
        }
        elseif ($entry.name) { $names.Add([string]$entry.name) }
    }
    # Rules built in the new Purview editor keep their conditions in AdvancedRule (JSON)
    if ($Rule.AdvancedRule) {
        foreach ($m in [regex]::Matches([string]$Rule.AdvancedRule, '"[Nn]ame"\s*:\s*"([^"]+)"')) { $names.Add($m.Groups[1].Value) }
    }
    @($names | Sort-Object -Unique)
}

Write-Verbose 'Reading DLP policies and rules...'
$policies = @(Get-DlpCompliancePolicy)
$rules    = @(Get-DlpComplianceRule)

# ---- Policy inventory ----
$policyRows = foreach ($p in $policies) {
    $workloads = foreach ($w in $workloadMap.Keys) { if (@($p.($workloadMap[$w]) | Where-Object { $_ }).Count -gt 0) { $w } }
    [PSCustomObject]@{
        Policy     = $p.Name
        Mode       = if ($modeName.ContainsKey("$($p.Mode)")) { $modeName["$($p.Mode)"] } else { "$($p.Mode)" }
        Enforced   = "$($p.Mode)" -eq 'Enable'
        Workloads  = (@($workloads) -join ', ')
        Priority   = $p.Priority
        RuleCount  = @($rules | Where-Object { $_.ParentPolicyName -eq $p.Name }).Count
        LastChange = $p.WhenChanged
        Comment    = $p.Comment
    }
}

# ---- Rule inventory ----
$ruleRows = foreach ($r in $rules) {
    $parent = $policyRows | Where-Object Policy -eq $r.ParentPolicyName | Select-Object -First 1
    $types  = Get-RuleSensitiveType -Rule $r
    [PSCustomObject]@{
        Policy          = $r.ParentPolicyName
        Rule            = $r.Name
        PolicyMode      = if ($parent) { $parent.Mode } else { '' }
        RuleDisabled    = [bool]$r.Disabled
        SensitiveTypes  = ($types -join '; ')
        Blocks          = [bool]$r.BlockAccess
        NotifiesUser    = [bool](@($r.NotifyUser | Where-Object { $_ }).Count)
        IncidentReports = [bool](@($r.GenerateIncidentReport | Where-Object { $_ }).Count)
        Severity        = $r.ReportSeverityLevel
        Workloads       = if ($parent) { $parent.Workloads } else { '' }
        Enforced        = [bool]($parent -and $parent.Enforced -and -not $r.Disabled)
    }
}

# ---- Coverage checks ----
$checks = New-Object System.Collections.Generic.List[object]
function Add-Check { param($Check, $Status, $Detail) $checks.Add([PSCustomObject]@{ Check = $Check; Status = $Status; Detail = $Detail }) }

$enforcedPolicies = @($policyRows | Where-Object Enforced)
foreach ($w in $workloadMap.Keys) {
    $covering = @($enforcedPolicies | Where-Object { $_.Workloads -split ', ' -contains $w })
    if ($covering.Count -gt 0) { Add-Check "$w covered by an enforced policy" 'Pass' ($covering.Policy -join ', ') }
    else { Add-Check "$w covered by an enforced policy" 'Fail' "No enforced DLP policy includes $w." }
}

$testPolicies = @($policyRows | Where-Object { $_.Mode -like 'Test*' })
Add-Check 'Policies left in test mode' $(if ($testPolicies) { 'Review' } else { 'Pass' }) `
    $(if ($testPolicies) { ($testPolicies.Policy -join ', ') + '. Check the DLP alerts/Activity explorer, then turn them on.' } else { 'None' })

$nonBlocking = @($ruleRows | Where-Object { $_.Enforced -and -not $_.Blocks })
Add-Check 'Enforced rules that never block' $(if ($nonBlocking) { 'Review' } else { 'Pass' }) `
    $(if ($nonBlocking) { ($nonBlocking | ForEach-Object { "$($_.Policy) / $($_.Rule)" }) -join ', ' } else { 'None' })

$enforcedTypes = @($ruleRows | Where-Object Enforced | ForEach-Object { $_.SensitiveTypes -split '; ' } | Where-Object { $_ })
foreach ($t in $RequiredSensitiveTypes) {
    $hit = $enforcedTypes | Where-Object { $_ -eq $t }
    Add-Check "Sensitive type covered: $t" $(if ($hit) { 'Pass' } else { 'Fail' }) $(if ($hit) { 'Covered by an enforced rule' } else { 'No enforced rule detects this type.' })
}

try {
    $labels       = @(Get-Label -ErrorAction Stop)
    $labelPolicies = @(Get-LabelPolicy -ErrorAction Stop)
    $published    = @($labelPolicies | Where-Object { $_.Enabled -ne $false -and @($_.Labels).Count -gt 0 })
    Add-Check 'Sensitivity labels published' $(if ($published) { 'Pass' } else { 'Fail' }) `
        ("{0} label(s), {1} label policy(ies) publishing them" -f $labels.Count, $published.Count)
}
catch {
    Add-Check 'Sensitivity labels published' 'Error' $_.Exception.Message
}

# ---- Output ----
if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}
$stamp = '{0:yyyyMMdd_HHmm}' -f (Get-Date)
@($policyRows) | Export-Csv -Path (Join-Path $OutputDirectory "Purview_DlpPolicies_$stamp.csv") -NoTypeInformation -Encoding UTF8
@($ruleRows)   | Export-Csv -Path (Join-Path $OutputDirectory "Purview_DlpRules_$stamp.csv") -NoTypeInformation -Encoding UTF8
$checks        | Export-Csv -Path (Join-Path $OutputDirectory "Purview_DlpCoverage_$stamp.csv") -NoTypeInformation -Encoding UTF8

Write-Verbose ("Policies: {0} (enforced {1}, test {2}). Rules: {3}. Failed checks: {4}." -f @($policyRows).Count,
    $enforcedPolicies.Count, $testPolicies.Count, @($ruleRows).Count, @($checks | Where-Object Status -eq 'Fail').Count)

$checks
