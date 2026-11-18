@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Scripts are run interactively and by Task Scheduler; progress/verbose output is intentional.
        'PSAvoidUsingWriteHost'
        # Set-ScheduledTask only accepts a plain-text password; it is taken from a PSCredential in memory.
        'PSAvoidUsingPlainTextForPassword'
    )
    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.4')
        }
    }
}
