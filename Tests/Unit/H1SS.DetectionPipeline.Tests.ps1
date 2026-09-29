$modulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\H1SSTriage.psd1'
Import-Module -Name $modulePath -Force

Describe 'Detection-required enrichment pipeline' {
    InModuleScope H1SSTriage {
        It 'enriches a raw masked Microsoft task before rules and produces the expected finding' {
            Mock Get-H1SSFileMetadata {
                [PSCustomObject]@{ FileExists=$true; SHA256=$null; SignatureStatus='NotSigned'; SignerSubject=$null; SignerIssuer=$null; SignerThumbprint=$null; CompanyName=$null; ProductName=$null; OriginalFileName='update.exe'; FileVersion=$null; FileCreationTimeUtc=$null; FileLastWriteTimeUtc=$null; FileSize=123; MetadataError=$null }
            }
            $task = [PSCustomObject]@{
                RecordId='task:pipeline-masked'; TaskName='Update'; TaskPath='\Microsoft\Windows\Update\'; State='Ready'; Enabled=$true; Hidden=$false; PrincipalRunLevel='Highest'
                Actions=@([PSCustomObject]@{ Execute='C:\Users\TestUser\AppData\Roaming\update.exe'; Arguments='-enc AAAA'; WorkingDirectory='C:\Users\TestUser\AppData\Roaming' })
                Triggers=@([PSCustomObject]@{ Type='LogonTrigger' }); ActionFileMetadata=@(); DetectionEnrichmentStatus='Pending'; DetectionEnrichmentErrors=@()
            }
            $data = @{ Processes=@(); Services=@(); Network=@(); ScheduledTasks=@($task); RunKeys=@(); Startup=@(); AdvancedPersistence=@() }
            $states = @{ Processes=[PSCustomObject]@{Status='Success'}; Services=[PSCustomObject]@{Status='Success'}; Network=[PSCustomObject]@{Status='Success'}; ScheduledTasks=[PSCustomObject]@{Status='Success'}; RunKeys=[PSCustomObject]@{Status='Success'} }

            @(Add-H1SSDetectionEnrichment -Data $data).Count | Should Be 0
            @($task.ActionFileMetadata).Count | Should Be 1
            $task.ActionFileMetadata[0].Metadata.SignatureStatus | Should Be 'NotSigned'
            $task.DetectionEnrichmentStatus | Should Be 'Success'

            $finding = @(Invoke-H1SSRules -Data $data -StateByName $states | Where-Object RuleId -eq 'TASK.MULTI_SIGNAL.001')[0]
            $finding.Severity | Should Be 'High'
            $finding.Why | Should Match 'metadata=Success'
            ($finding.Signals -contains 'TASK.NAMESPACE_MASQUERADE') | Should Be $true
        }

        It 'uses trusted action metadata in the real flow without an aggressive finding' {
            Mock Get-H1SSFileMetadata {
                [PSCustomObject]@{ FileExists=$true; SHA256=$null; SignatureStatus='Valid'; SignerSubject='CN=Fixture'; SignerIssuer='CN=Fixture CA'; SignerThumbprint='FIXTURE'; CompanyName='Fixture'; ProductName='Fixture'; OriginalFileName='fixture.exe'; FileVersion='1.0'; FileCreationTimeUtc=$null; FileLastWriteTimeUtc=$null; FileSize=456; MetadataError=$null; PathExpected=$true; PublisherExpected=$true; OriginalFileNameExpected=$true; CompanyExpected=$true; HashKnown=$true }
            }
            $task = [PSCustomObject]@{
                RecordId='task:pipeline-legitimate'; TaskName='FixtureMaintenance'; TaskPath='\Microsoft\Windows\Fixture\'; State='Ready'; Enabled=$true; Hidden=$false; PrincipalRunLevel='Limited'
                Actions=@([PSCustomObject]@{ Execute='C:\Windows\System32\fixture.exe'; Arguments='/maintenance'; WorkingDirectory='C:\Windows\System32' })
                Triggers=@([PSCustomObject]@{ Type='CalendarTrigger' }); ActionFileMetadata=@(); DetectionEnrichmentStatus='Pending'; DetectionEnrichmentErrors=@()
            }
            $data = @{ Processes=@(); Services=@(); Network=@(); ScheduledTasks=@($task); RunKeys=@(); Startup=@(); AdvancedPersistence=@() }
            $states = @{ Processes=[PSCustomObject]@{Status='Success'}; Services=[PSCustomObject]@{Status='Success'}; Network=[PSCustomObject]@{Status='Success'}; ScheduledTasks=[PSCustomObject]@{Status='Success'}; RunKeys=[PSCustomObject]@{Status='Success'} }

            @(Add-H1SSDetectionEnrichment -Data $data).Count | Should Be 0
            (Get-H1SSTaskTrustAssessment -Task $task).TrustLevel | Should Be 'Trusted'
            @(Invoke-H1SSRules -Data $data -StateByName $states | Where-Object RuleId -eq 'TASK.MULTI_SIGNAL.001').Count | Should Be 0
        }

        It 'records required enrichment failure as Partial instead of benign unknown' {
            Mock Get-H1SSFileMetadata {
                [PSCustomObject]@{ FileExists=$false; SHA256=$null; SignatureStatus='Error'; SignerSubject=$null; SignerIssuer=$null; SignerThumbprint=$null; CompanyName=$null; ProductName=$null; OriginalFileName=$null; FileVersion=$null; FileCreationTimeUtc=$null; FileLastWriteTimeUtc=$null; FileSize=$null; MetadataError='Access denied' }
            }
            $task = [PSCustomObject]@{
                RecordId='task:pipeline-partial'; TaskName='Partial'; TaskPath='\Fixture\'; State='Ready'; Enabled=$true; Hidden=$false; PrincipalRunLevel='Limited'
                Actions=@([PSCustomObject]@{ Execute='C:\Fixture\denied.exe'; Arguments=''; WorkingDirectory='C:\Fixture' }); Triggers=@(); ActionFileMetadata=@()
            }
            $data = @{ ScheduledTasks=@($task) }

            $errors = @(Add-H1SSDetectionEnrichment -Data $data)
            $errors.Count | Should Be 1
            $errors[0].ErrorType | Should Be 'MetadataAcquisitionError'
            $task.DetectionEnrichmentStatus | Should Be 'Partial'
            (Get-H1SSTaskTrustAssessment -Task $task).AssessmentStatus | Should Be 'Partial'
        }

        It 'does not equate a calculated SHA256 with HashKnown' {
            Mock Get-H1SSFileMetadata {
                [PSCustomObject]@{ FileExists=$true; SHA256='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; SignatureStatus='Valid'; SignerSubject='CN=Fixture'; SignerIssuer='CN=Fixture CA'; SignerThumbprint='FIXTURE'; CompanyName='Fixture'; ProductName='Fixture'; OriginalFileName='fixture.exe'; FileVersion='1.0'; FileCreationTimeUtc=$null; FileLastWriteTimeUtc=$null; FileSize=456; MetadataError=$null }
            }
            $task = [PSCustomObject]@{
                RecordId='task:hashknown'; TaskName='HashKnown'; TaskPath='\Fixture\'; State='Ready'; Enabled=$true; Hidden=$false; PrincipalRunLevel='Limited'
                Actions=@([PSCustomObject]@{ Execute='C:\Windows\System32\fixture.exe'; Arguments=''; WorkingDirectory='C:\Windows\System32' }); Triggers=@(); ActionFileMetadata=@()
            }
            $data = @{ ScheduledTasks=@($task) }

            Add-H1SSDetectionEnrichment -Data $data
            $task.ActionFileMetadata[0].Metadata.SHA256 | Should Not BeNullOrEmpty
            $task.ActionFileMetadata[0].Metadata.HashKnown | Should BeNullOrEmpty
            (Get-H1SSTaskTrustAssessment -Task $task).TrustLevel | Should Be 'LikelyTrusted'
        }

        It 'produces deterministic task decisions from the same raw and enrichment fixtures' {
            Mock Get-H1SSFileMetadata {
                [PSCustomObject]@{ FileExists=$true; SHA256=$null; SignatureStatus='NotSigned'; SignerSubject=$null; SignerIssuer=$null; SignerThumbprint=$null; CompanyName=$null; ProductName=$null; OriginalFileName='update.exe'; FileVersion=$null; FileCreationTimeUtc=$null; FileLastWriteTimeUtc=$null; FileSize=123; MetadataError=$null }
            }
            $results = @()
            foreach ($iteration in 1..2) {
                $task = [PSCustomObject]@{
                    RecordId='task:deterministic-pipeline'; TaskName='Update'; TaskPath='\Microsoft\Windows\Update\'; State='Ready'; Enabled=$true; Hidden=$false; PrincipalRunLevel='Highest'
                    Actions=@([PSCustomObject]@{ Execute='C:\Users\TestUser\AppData\Roaming\update.exe'; Arguments='-enc AAAA'; WorkingDirectory='C:\Users\TestUser\AppData\Roaming' }); Triggers=@(); ActionFileMetadata=@()
                }
                $data = @{ ScheduledTasks=@($task) }
                Add-H1SSDetectionEnrichment -Data $data
                $results += @(Invoke-H1SSTaskRules -Tasks @($task) -CollectorStatus Success)[0]
            }
            ($results[0].Signals -join '|') | Should Be ($results[1].Signals -join '|')
            $results[0].Severity | Should Be $results[1].Severity
            $results[0].Confidence | Should Be $results[1].Confidence
            $results[0].EvidenceStrength | Should Be $results[1].EvidenceStrength
            $results[0].RuleId | Should Be $results[1].RuleId
        }
    }
}

Describe 'Global finding score contract' {
    InModuleScope H1SSTriage {
        It 'keeps Score equal to Signals.Count across process service task persistence and network findings' {
            $process = [PSCustomObject]@{ RecordId='process:score'; PID=42; Name='stage.exe'; ExecutablePath='C:\Users\TestUser\AppData\Roaming\stage.exe'; CommandLine='stage.exe'; SignatureStatus='NotSigned'; FileLastWriteTimeUtc=$null; ObservedAtUtc='2026-01-01T00:00:00Z'; ParentName='explorer.exe'; TrustLevel='Suspicious' }
            $service = [PSCustomObject]@{ RecordId='service:score'; Name='Fixture'; UnquotedServicePath=$true; FileExists=$true; ExecutablePath='C:\Users\TestUser\AppData\Roaming\service.exe'; WritableExecutable=$false; WritableDirectory=$false; SignatureStatus='NotSigned'; ServiceDll=$null }
            $task = [PSCustomObject]@{ RecordId='task:score'; TaskName='Update'; TaskPath='\Microsoft\Windows\Update\'; State='Ready'; Enabled=$true; Hidden=$false; PrincipalRunLevel='Highest'; Actions=@([PSCustomObject]@{Execute='C:\Users\TestUser\AppData\Roaming\update.exe';Arguments='-enc AAAA';WorkingDirectory=''}); Triggers=@(); ActionFileMetadata=@() }
            $runKey = [PSCustomObject]@{ RecordId='runkey:score'; Name='Fixture'; RegistryPath='HKCU:\Fixture'; Value='powershell.exe -enc AAAA C:\Users\TestUser\stage.ps1' }
            $advanced = [PSCustomObject]@{ RecordId='advanced:score'; Type='IFEO' }
            $startup = [PSCustomObject]@{ RecordId='startup:score'; FullName='C:\Fixture.lnk'; TargetPath='C:\Users\TestUser\AppData\Roaming\stage.exe'; Arguments='' }
            $network = @(
                [PSCustomObject]@{ RecordId='tcp:score-external'; Protocol='TCP'; State='Established'; RemoteClassification='Public'; RemoteAddress='203.0.113.20'; RemotePort=443; ProcessRecordId='process:score'; ProcessPath=$process.ExecutablePath; ProcessSignatureStatus='NotSigned' },
                [PSCustomObject]@{ RecordId='tcp:score-private'; Protocol='TCP'; State='Established'; RemoteClassification='Private'; RemoteAddress='192.168.1.10'; RemotePort=445; ProcessRecordId='process:system'; ProcessPath='C:\Windows\System32\svchost.exe'; ProcessSignatureStatus='Valid' }
            )
            $data = @{ Processes=@($process); Services=@($service); Network=$network; ScheduledTasks=@($task); RunKeys=@($runKey); Startup=@($startup); AdvancedPersistence=@($advanced) }
            $states = @{ Processes=[PSCustomObject]@{Status='Success'}; Services=[PSCustomObject]@{Status='Success'}; Network=[PSCustomObject]@{Status='Success'}; ScheduledTasks=[PSCustomObject]@{Status='Success'}; RunKeys=[PSCustomObject]@{Status='Success'} }

            $findings = @(Invoke-H1SSRules -Data $data -StateByName $states)
            @($findings | Where-Object RuleId -like 'PROC.*').Count | Should BeGreaterThan 0
            @($findings | Where-Object RuleId -like 'SVC.*').Count | Should BeGreaterThan 0
            @($findings | Where-Object RuleId -like 'TASK.*').Count | Should BeGreaterThan 0
            @($findings | Where-Object RuleId -like 'PERSIST.*').Count | Should BeGreaterThan 0
            @($findings | Where-Object RuleId -like 'NET.*').Count | Should BeGreaterThan 0
            foreach ($finding in $findings) { $finding.Score | Should Be @($finding.Signals).Count }
        }
    }
}

Describe 'CGNAT network semantics' {
    InModuleScope H1SSTriage {
        It 'distinguishes private enterprise context CGNAT and public addresses' {
            $private = Get-H1SSAddressClassification '192.168.1.10'
            $cgnat = Get-H1SSAddressClassification '100.64.1.10'
            $publicAddress = ('{0}.{0}.{0}.{0}' -f 8)
            $public = Get-H1SSAddressClassification $publicAddress
            $private.Classification | Should Be 'Private'
            $private.IsInternal | Should Be $true
            $cgnat.Classification | Should Be 'CGNAT'
            $cgnat.IsInternal | Should Be $false
            $public.Classification | Should Be 'Public'
            $public.IsInternal | Should Be $false

            $connections = @(
                [PSCustomObject]@{RecordId='tcp:private-smb';Protocol='TCP';State='Established';RemoteClassification='Private';RemoteAddress='192.168.1.10';RemotePort=445;ProcessPath='C:\Windows\System32\svchost.exe'},
                [PSCustomObject]@{RecordId='tcp:cgnat-smb';Protocol='TCP';State='Established';RemoteClassification='CGNAT';RemoteAddress='100.64.1.10';RemotePort=445;ProcessPath='C:\Windows\System32\svchost.exe'}
            )
            $findings = @(Invoke-H1SSNetworkRules -Network $connections -CollectorStatus Success)
            @($findings | Where-Object EntityId -eq 'tcp:private-smb').Count | Should Be 1
            @($findings | Where-Object EntityId -eq 'tcp:cgnat-smb').Count | Should Be 0
            $findings[0].RuleVersion | Should Be '2.1'
        }
    }
}
