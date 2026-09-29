$modulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\H1SSTriage.psd1'
Import-Module -Name $modulePath -Force

Describe 'Scheduled task rules' {
    InModuleScope H1SSTriage {
        It 'does not trust a task only because it uses the Microsoft namespace' {
            $task = [PSCustomObject]@{
                RecordId='task:microsoft-masked'; TaskName='Telemetry'; TaskPath='\Microsoft\Windows\Update\'; Hidden=$false
                PrincipalRunLevel='Highest'; Actions=@([PSCustomObject]@{Execute='cmd.exe';Arguments='/c C:\ProgramData\cache\stage.bat';WorkingDirectory=''})
            }
            $findings = @(Invoke-H1SSTaskRules -Tasks @($task) -CollectorStatus Success)
            $findings.Count | Should Be 1
            ($findings[0].Signals -contains 'TASK.MICROSOFT_NAMESPACE_CONTEXT') | Should Be $true
            ($findings[0].Signals -contains 'TASK.USER_WRITABLE_PATH') | Should Be $true
        }

        It 'does not mark PowerShell alone as an alert' {
            $task = [PSCustomObject]@{
                RecordId='task:legit'; TaskName='Inventory'; TaskPath='\Corporate\'; Hidden=$false
                PrincipalRunLevel='Limited'; Actions=@([PSCustomObject]@{Execute='powershell.exe';Arguments='-NoProfile -File C:\Program Files\Corp\inventory.ps1';WorkingDirectory='C:\Program Files\Corp'})
            }
            @(Invoke-H1SSTaskRules -Tasks @($task) -CollectorStatus Success).Count | Should Be 0
        }

        It 'requires correlated signals before assigning High' {
            $task = [PSCustomObject]@{
                RecordId='task:suspicious'; TaskName='Updater'; TaskPath='\'; Hidden=$false
                PrincipalRunLevel='Highest'; Actions=@([PSCustomObject]@{Execute='powershell.exe';Arguments='-enc AAAA C:\Users\Public\stage.ps1';WorkingDirectory='C:\Users\Public'})
            }
            $finding = @(Invoke-H1SSTaskRules -Tasks @($task) -CollectorStatus Success)[0]
            $finding.Severity | Should Be 'High'
            $finding.Signals.Count | Should BeGreaterThan 2
        }
    }
}

Describe 'Process rule correlations' {
    InModuleScope H1SSTriage {
        It 'treats a Temp path alone as contextual rather than High' {
            $process = [PSCustomObject]@{
                RecordId='process:1:1'; PID=1; Name='setup.exe'; ExecutablePath='C:\Users\TestUser\AppData\Local\Temp\setup.exe'; CommandLine='setup.exe'
                SignatureStatus='Valid'; FileLastWriteTimeUtc=$null; ParentName='explorer.exe'
            }
            $finding = @(Invoke-H1SSProcessRules -Processes @($process) -Network @() -PersistenceReferences @() -CollectorStatus Success)[0]
            $finding.Severity | Should Be 'Medium'
            $finding.EvidenceStrength | Should Be 'Heuristic'
        }
    }
}

Describe 'Network context rules' {
    InModuleScope H1SSTriage {
        It 'reports internal administrative connections as context, not malware' {
            $connection = [PSCustomObject]@{ RecordId='tcp:1'; Protocol='TCP'; State='Established'; RemoteClassification='Private'; RemotePort=445; ProcessPath='C:\Windows\System32\svchost.exe' }
            $finding = @(Invoke-H1SSNetworkRules -Network @($connection) -CollectorStatus Success)[0]
            $finding.Severity | Should Be 'Informational'
            $finding.EvidenceStrength | Should Be 'Contextual'
        }
    }
}
