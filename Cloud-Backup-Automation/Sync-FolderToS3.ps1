<#
.SYNOPSIS
    Incrementally syncs a local folder to Amazon S3 with pre-flight checks and a structured log. Built for unattended Task Scheduler runs.

.DESCRIPTION
    Wraps "aws s3 sync" with the checks an unattended backup job needs:

      1. AWS CLI present
      2. Credentials valid (aws sts get-caller-identity)
      3. Bucket reachable
      4. Source folder exists and is not empty

    Every step is written to a timestamped log. The script exits non-zero on failure so
    Task Scheduler and monitoring can alert on it.

    By default the sync is additive. -Mirror adds --delete so objects removed locally are
    also removed from S3. Enable S3 Versioning on the bucket before using -Mirror, and try
    -DryRun first.

.PARAMETER SourcePath
    Local folder to back up.

.PARAMETER BucketName
    Target S3 bucket name (no s3:// prefix).

.PARAMETER Prefix
    Optional key prefix (folder) inside the bucket.

.PARAMETER AwsProfile
    AWS CLI named profile. Default: default.

.PARAMETER Region
    AWS region. Default: the profile's configured region.

.PARAMETER StorageClass
    S3 storage class. Default: STANDARD_IA.

.PARAMETER Mirror
    Delete objects in S3 that no longer exist locally (--delete).

.PARAMETER DryRun
    Show what would be transferred without changing anything (--dryrun).

.PARAMETER LogDirectory
    Folder for log files. Default: .\Logs

.EXAMPLE
    .\Sync-FolderToS3.ps1 -SourcePath 'D:\Projects' -BucketName 'contoso-backup' -Prefix 'projects' -DryRun

.EXAMPLE
    # Task Scheduler action
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Sync-FolderToS3.ps1" -SourcePath "D:\Projects" -BucketName "contoso-backup" -AwsProfile backup

.NOTES
    Author      : Karthik (github.com/karthksai027)
    Project     : Karthik's Identity & SecOps Toolkit
    Requires    : AWS CLI v2 on PATH with a configured profile (or an EC2/SSM instance role).
    IAM policy  : s3:ListBucket on the bucket; s3:PutObject on bucket/*; s3:DeleteObject on bucket/* only if -Mirror is used.
    Run as      : a gMSA or dedicated service account, not a personal admin account.

.LINK
    https://github.com/karthksai027/identity-secops-automation
#>

#Requires -Version 5.1

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Region', Justification = 'Used inside Invoke-AwsCli via script scope')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -Path $_ -PathType Container })]
    [string]$SourcePath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$')]
    [string]$BucketName,

    [string]$Prefix,

    [string]$AwsProfile = 'default',

    [string]$Region,

    [ValidateSet('STANDARD', 'STANDARD_IA', 'ONEZONE_IA', 'INTELLIGENT_TIERING', 'GLACIER_IR')]
    [string]$StorageClass = 'STANDARD_IA',

    [switch]$Mirror,

    [switch]$DryRun,

    [string]$LogDirectory = (Join-Path -Path (Get-Location) -ChildPath 'Logs')
)

if (-not (Test-Path -Path $LogDirectory)) {
    New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
}
$logFile = Join-Path $LogDirectory ("s3-sync_{0:yyyyMMdd}.log" -f (Get-Date))

function Write-SyncLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')][string]$Level = 'INFO'
    )
    $line = '{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}' -f (Get-Date), $Level, $Message
    Add-Content -Path $logFile -Value $line -Encoding UTF8
    Write-Output $line
}

function Invoke-AwsCli {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $allArgs = $Arguments + @('--profile', $AwsProfile)
    if ($Region) { $allArgs += @('--region', $Region) }
    $out = & aws @allArgs 2>&1
    [PSCustomObject]@{ ExitCode = $LASTEXITCODE; Output = ($out | Out-String).Trim() }
}

$destination = if ($Prefix) { "s3://$BucketName/$($Prefix.Trim('/'))/" } else { "s3://$BucketName/" }
Write-SyncLog "=== Sync started: $SourcePath -> $destination (Mirror=$([bool]$Mirror), DryRun=$([bool]$DryRun)) ==="

# 1. AWS CLI
if (-not (Get-Command -Name aws -ErrorAction SilentlyContinue)) {
    Write-SyncLog 'AWS CLI not found on PATH.' 'ERROR'
    exit 1
}

# 2. Credentials
$identity = Invoke-AwsCli -Arguments @('sts', 'get-caller-identity', '--query', 'Arn', '--output', 'text')
if ($identity.ExitCode -ne 0) {
    Write-SyncLog "AWS credentials invalid for profile '$AwsProfile': $($identity.Output)" 'ERROR'
    exit 1
}
Write-SyncLog "Authenticated as $($identity.Output)"

# 3. Bucket
$bucketCheck = Invoke-AwsCli -Arguments @('s3api', 'head-bucket', '--bucket', $BucketName)
if ($bucketCheck.ExitCode -ne 0) {
    Write-SyncLog "Bucket '$BucketName' not reachable: $($bucketCheck.Output)" 'ERROR'
    exit 1
}

# 4. Source
$fileCount = @(Get-ChildItem -Path $SourcePath -Recurse -File -ErrorAction SilentlyContinue).Count
if ($fileCount -eq 0) {
    Write-SyncLog 'Source folder is empty. Nothing to sync.' 'WARN'
    if ($Mirror) { Write-SyncLog 'Skipping to avoid mirroring an empty folder (would delete the bucket contents).' 'WARN' }
    exit 0
}
Write-SyncLog "Source files: $fileCount"

# 5. Sync
$syncArgs = @('s3', 'sync', $SourcePath, $destination, '--storage-class', $StorageClass, '--only-show-errors')
if ($Mirror) { $syncArgs += '--delete' }
if ($DryRun) { $syncArgs = $syncArgs -ne '--only-show-errors'; $syncArgs += '--dryrun' }

$start  = Get-Date
$result = Invoke-AwsCli -Arguments $syncArgs
$elapsed = (Get-Date) - $start

if ($result.Output) { Write-SyncLog "aws output: $($result.Output)" }

if ($result.ExitCode -eq 0) {
    Write-SyncLog ("Sync completed in {0:hh\:mm\:ss}." -f $elapsed) 'SUCCESS'
    exit 0
}
else {
    # Exit code 2 = some files skipped (for example locked files); 1 = failure
    Write-SyncLog ("Sync finished with exit code {0} after {1:hh\:mm\:ss}." -f $result.ExitCode, $elapsed) 'ERROR'
    exit $result.ExitCode
}
