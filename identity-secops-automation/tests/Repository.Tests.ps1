#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Static quality gates for every script and query in the repository.
    Run locally:  Invoke-Pester -Path ./tests -Output Detailed
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester shares variables across BeforeAll/It blocks')]
param()

BeforeDiscovery {
    $repoRoot = Split-Path -Path $PSScriptRoot -Parent
    $scripts  = Get-ChildItem -Path $repoRoot -Recurse -Filter '*.ps1' |
                Where-Object { $_.FullName -notmatch '[\\/]tests[\\/]' } |
                ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } }
    $queries  = Get-ChildItem -Path $repoRoot -Recurse -Filter '*.kql' |
                ForEach-Object { @{ Name = $_.Name; Path = $_.FullName } }
}

Describe 'PowerShell script <Name>' -ForEach $scripts {

    BeforeAll {
        $content = Get-Content -Path $Path -Raw
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        $help = $ast.GetHelpContent()
    }

    It 'parses without syntax errors' {
        $errors | Should -BeNullOrEmpty
    }

    It 'uses an approved verb' {
        $verb = ($Name -split '-')[0]
        (Get-Verb).Verb | Should -Contain $verb
    }

    It 'declares [CmdletBinding()]' {
        $ast.ParamBlock.Attributes.TypeName.Name | Should -Contain 'CmdletBinding'
    }

    It 'has comment-based help with SYNOPSIS, DESCRIPTION, EXAMPLE and NOTES' {
        $help | Should -Not -BeNullOrEmpty
        $help.Synopsis    | Should -Not -BeNullOrEmpty
        $help.Description | Should -Not -BeNullOrEmpty
        $help.Examples.Count | Should -BeGreaterThan 0
        $help.Notes       | Should -Not -BeNullOrEmpty
    }

    It 'documents every parameter' {
        foreach ($p in $ast.ParamBlock.Parameters) {
            $help.Parameters.Keys | Should -Contain $p.Name.VariablePath.UserPath.ToUpper()
        }
    }

    It 'contains no hard-coded secrets' {
        $content | Should -Not -Match '(?i)-Password\s+["''][^"''$]+["'']'
        $content | Should -Not -Match '(?i)(client_?secret|api_?key)\s*=\s*["''][^"'']{8,}["'']'
        $content | Should -Not -Match 'AKIA[0-9A-Z]{16}'
        $content | Should -Not -Match '(?i)ConvertTo-SecureString\s+["''][^"'']+["'']\s+-AsPlainText'
    }
}

Describe 'KQL query <Name>' -ForEach $queries {

    BeforeAll { $content = Get-Content -Path $Path -Raw }

    It 'has a title, MITRE ATT&CK mapping and data source in the header' {
        $content | Should -Match '//\s*Title\s*:'
        $content | Should -Match '//\s*MITRE ATT&CK\s*:\s*T\d{4}'
        $content | Should -Match '//\s*Data source\s*:'
    }

    It 'uses snake_case file naming' {
        $Name | Should -Match '^[a-z0-9]+(_[a-z0-9]+)*\.kql$'
    }

    It 'bounds the time range' {
        $content | Should -Match 'ago\('
    }
}
