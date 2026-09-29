$modulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\H1SSTriage.psd1'
Import-Module -Name $modulePath -Force

Describe 'Attribute-based trust model' {
    InModuleScope H1SSTriage {
        It 'does not trust an application because its path contains a familiar product name' {
            $trust = Get-H1SSTrustAssessment -Path 'C:\Users\TestUser\AppData\Roaming\Discord\update.exe' -SignatureStatus NotSigned
            $trust.TrustLevel | Should Be 'Suspicious'
            $trust.TrustLevel | Should Not Be 'Trusted'
            $trust.TrustLevel | Should Not Be 'LikelyTrusted'
        }

        It 'requires all explicit strong attributes for Trusted' {
            $trust = Get-H1SSTrustAssessment -Path 'C:\Program Files\Fixture\fixture.exe' -SignatureStatus Valid -PathExpected $true -PublisherExpected $true -OriginalFileNameExpected $true -CompanyExpected $true -HashKnown $true
            $trust.TrustLevel | Should Be 'Trusted'
            ($trust.TrustSignals -contains 'TRUST.HASH_KNOWN') | Should Be $true
        }

        It 'does not let a valid signature override an explicit publisher mismatch' {
            $trust = Get-H1SSTrustAssessment -Path 'C:\Program Files\Fixture\fixture.exe' -SignatureStatus Valid -PathExpected $true -PublisherExpected $false
            $trust.TrustLevel | Should Be 'Suspicious'
            ($trust.TrustSignals -contains 'TRUST.PUBLISHER_UNEXPECTED') | Should Be $true
        }
    }
}

Describe 'Scheduled task detection correctness' {
    InModuleScope H1SSTriage {
        It 'does not alert on a coherent Microsoft namespace administrative task' {
            $task = [PSCustomObject]@{
                RecordId='task:microsoft-legitimate'; TaskName='FixtureInventory'; TaskPath='\Microsoft\Windows\Fixture\'; State='Ready'; Enabled=$true; Hidden=$false
                PrincipalRunLevel='Limited'; Actions=@([PSCustomObject]@{Execute='powershell.exe';Arguments='-NoProfile -File "C:\Program Files\Fixture\inventory.ps1"';WorkingDirectory='C:\Program Files\Fixture'})
                Triggers=@([PSCustomObject]@{Type='CalendarTrigger'})
                ActionFileMetadata=@([PSCustomObject]@{ResolvedPath='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe';Metadata=[PSCustomObject]@{SignatureStatus='Valid';PathExpected=$true;PublisherExpected=$true;OriginalFileNameExpected=$true;CompanyExpected=$true;HashKnown=$true}})
            }
            @(Invoke-H1SSTaskRules -Tasks @($task) -CollectorStatus Success).Count | Should Be 0
        }

        It 'detects a Microsoft namespace masquerade using a user profile executable and encoded arguments' {
            $task = [PSCustomObject]@{
                RecordId='task:microsoft-masquerade'; TaskName='Update'; TaskPath='\Microsoft\Windows\Update\'; State='Ready'; Enabled=$true; Hidden=$false
                PrincipalRunLevel='Highest'; Actions=@([PSCustomObject]@{Execute='C:\Users\TestUser\AppData\Roaming\update.exe';Arguments='-enc AAAA';WorkingDirectory='C:\Users\TestUser\AppData\Roaming'})
                Triggers=@([PSCustomObject]@{Type='LogonTrigger'}); ActionFileMetadata=@()
            }
            $finding = @(Invoke-H1SSTaskRules -Tasks @($task) -CollectorStatus Success)[0]
            $finding.Severity | Should Be 'High'
            ($finding.Signals -contains 'TASK.MICROSOFT_NAMESPACE_CONTEXT') | Should Be $true
            ($finding.Signals -contains 'TASK.NAMESPACE_MASQUERADE') | Should Be $true
            ($finding.Signals -contains 'TASK.USER_WRITABLE_PATH') | Should Be $true
            $finding.RuleVersion | Should Be '2.0'
        }

        It 'keeps a disabled suspicious task in rule evaluation' {
            $task = [PSCustomObject]@{
                RecordId='task:disabled'; TaskName='DisabledFixture'; TaskPath='\Fixture\'; State='Disabled'; Enabled=$false; Hidden=$true
                PrincipalRunLevel='Highest'; Actions=@([PSCustomObject]@{Execute='powershell.exe';Arguments='-enc AAAA C:\Users\TestUser\stage.ps1';WorkingDirectory='C:\Users\TestUser'})
                Triggers=@(); ActionFileMetadata=@()
            }
            $finding = @(Invoke-H1SSTaskRules -Tasks @($task) -CollectorStatus Success)[0]
            ($finding.Signals -contains 'TASK.DISABLED') | Should Be $true
            $finding.ValidationSteps.Count | Should BeGreaterThan 1
        }

        It 'evaluates every action and preserves multiple action and trigger context' {
            $task = [PSCustomObject]@{
                RecordId='task:multiple'; TaskName='MultipleFixture'; TaskPath='\Fixture\'; State='Ready'; Enabled=$true; Hidden=$false; PrincipalRunLevel='Limited'
                Actions=@(
                    [PSCustomObject]@{Execute='C:\Program Files\Fixture\first.exe';Arguments='';WorkingDirectory='C:\Program Files\Fixture'},
                    [PSCustomObject]@{Execute='powershell.exe';Arguments='-enc AAAA C:\Users\TestUser\stage.ps1';WorkingDirectory='C:\Users\TestUser'}
                )
                Triggers=@([PSCustomObject]@{Type='BootTrigger'},[PSCustomObject]@{Type='LogonTrigger'}); ActionFileMetadata=@()
            }
            $finding = @(Invoke-H1SSTaskRules -Tasks @($task) -CollectorStatus Success)[0]
            ($finding.Signals -contains 'TASK.SUSPICIOUS_ARGUMENTS') | Should Be $true
            ($finding.Signals -contains 'TASK.MULTIPLE_ACTIONS') | Should Be $true
            ($finding.Signals -contains 'TASK.MULTIPLE_TRIGGERS') | Should Be $true
        }
    }
}

Describe 'Process false-positive and correlation behavior' {
    InModuleScope H1SSTriage {
        It 'does not classify a signed Temp executable as High from path alone' {
            $process = [PSCustomObject]@{RecordId='process:temp';PID=10;Name='setup.exe';ExecutablePath='C:\Users\TestUser\AppData\Local\Temp\setup.exe';CommandLine='setup.exe';SignatureStatus='Valid';FileLastWriteTimeUtc=$null;ObservedAtUtc='2026-01-01T00:00:00Z';ParentName='explorer.exe';TrustLevel='Unknown'}
            $finding = @(Invoke-H1SSProcessRules -Processes @($process) -Network @() -PersistenceReferences @() -CollectorStatus Success)[0]
            $finding.Severity | Should Be 'Medium'
            $finding.Severity | Should Not Be 'High'
            $finding.EvidenceStrength | Should Be 'Heuristic'
        }

        It 'does not classify a signed AppData application as High from location alone' {
            $process = [PSCustomObject]@{RecordId='process:appdata';PID=11;Name='app.exe';ExecutablePath='C:\Users\TestUser\AppData\Local\Fixture\app.exe';CommandLine='app.exe';SignatureStatus='Valid';FileLastWriteTimeUtc=$null;ObservedAtUtc='2026-01-01T00:00:00Z';ParentName='explorer.exe';TrustLevel='Unknown'}
            $finding = @(Invoke-H1SSProcessRules -Processes @($process) -Network @() -PersistenceReferences @() -CollectorStatus Success)[0]
            $finding.Severity | Should Be 'Low'
            $finding.Confidence | Should Be 'Low'
        }

        It 'raises a correlated unsigned user-writable process with an external connection' {
            $process = [PSCustomObject]@{RecordId='process:external';PID=12;Name='stage.exe';ExecutablePath='C:\Users\TestUser\AppData\Roaming\stage.exe';CommandLine='stage.exe';SignatureStatus='NotSigned';FileLastWriteTimeUtc=$null;ObservedAtUtc='2026-01-01T00:00:00Z';ParentName='explorer.exe';TrustLevel='Suspicious'}
            $network = [PSCustomObject]@{Protocol='TCP';State='Established';RemoteClassification='Public';ProcessRecordId='process:external'}
            $finding = @(Invoke-H1SSProcessRules -Processes @($process) -Network @($network) -PersistenceReferences @() -CollectorStatus Success)[0]
            $finding.Severity | Should Be 'High'
            $finding.EvidenceStrength | Should Be 'Strong'
            ($finding.Signals -contains 'PROC.UNSIGNED') | Should Be $true
            ($finding.Signals -contains 'PROC.EXTERNAL_CONNECTION') | Should Be $true
            $finding.Why | Should Match 'não confirmam comprometimento'
        }

        It 'raises a user-writable unsigned binary referenced by persistence' {
            $path = 'C:\Users\TestUser\AppData\Roaming\persist.exe'
            $process = [PSCustomObject]@{RecordId='process:persist';PID=13;Name='persist.exe';ExecutablePath=$path;CommandLine='persist.exe';SignatureStatus='NotSigned';FileLastWriteTimeUtc=$null;ObservedAtUtc='2026-01-01T00:00:00Z';ParentName='explorer.exe';TrustLevel='Suspicious'}
            $persistence = [PSCustomObject]@{RecordId='runkey:fixture';Value=$path}
            $finding = @(Invoke-H1SSProcessRules -Processes @($process) -Network @() -PersistenceReferences @($persistence) -CollectorStatus Success)[0]
            $finding.Severity | Should Be 'High'
            ($finding.Signals -contains 'PROC.PERSISTENCE_REFERENCE') | Should Be $true
        }

        It 'produces identical signals and classification for identical normalized input' {
            $process = [PSCustomObject]@{RecordId='process:deterministic';PID=14;Name='stage.exe';ExecutablePath='C:\Users\TestUser\AppData\Roaming\stage.exe';CommandLine='stage.exe';SignatureStatus='NotSigned';FileLastWriteTimeUtc='2025-12-31T23:00:00Z';ObservedAtUtc='2026-01-01T00:00:00Z';ParentName='explorer.exe';TrustLevel='Suspicious'}
            $network = [PSCustomObject]@{Protocol='TCP';State='Established';RemoteClassification='Public';ProcessRecordId='process:deterministic'}
            $first = @(Invoke-H1SSProcessRules -Processes @($process) -Network @($network) -PersistenceReferences @() -CollectorStatus Success)[0]
            $second = @(Invoke-H1SSProcessRules -Processes @($process) -Network @($network) -PersistenceReferences @() -CollectorStatus Success)[0]
            ($first.Signals -join '|') | Should Be ($second.Signals -join '|')
            $first.Severity | Should Be $second.Severity
            $first.Confidence | Should Be $second.Confidence
            $first.EvidenceStrength | Should Be $second.EvidenceStrength
        }
    }
}

Describe 'Network context and address classification' {
    InModuleScope H1SSTriage {
        It 'does not flag a signed browser using external TCP 443 from a protected path' {
            $connection = [PSCustomObject]@{RecordId='tcp:browser';Protocol='TCP';State='Established';RemoteClassification='Public';RemoteAddress='203.0.113.10';RemotePort=443;ProcessRecordId='process:browser';ProcessPath='C:\Program Files\Fixture Browser\browser.exe';ProcessSignatureStatus='Valid'}
            @(Invoke-H1SSNetworkRules -Network @($connection) -CollectorStatus Success).Count | Should Be 0
        }

        It 'correlates external network activity with unsigned user-writable process context' {
            $connection = [PSCustomObject]@{RecordId='tcp:external';Protocol='TCP';State='Established';RemoteClassification='Public';RemoteAddress='198.51.100.25';RemotePort=8443;ProcessRecordId='process:external';ProcessPath='C:\Users\TestUser\AppData\Roaming\stage.exe';ProcessSignatureStatus='NotSigned'}
            $finding = @(Invoke-H1SSNetworkRules -Network @($connection) -CollectorStatus Success)[0]
            $finding.RuleId | Should Be 'NET.PROCESS_CONTEXT.001'
            $finding.RuleVersion | Should Be '1.0'
            $finding.Severity | Should Be 'High'
            ($finding.Signals -contains 'NET.EXTERNAL_CONNECTION') | Should Be $true
            ($finding.Signals -contains 'PROC.UNSIGNED') | Should Be $true
        }

        It 'treats internal SMB and RDP as contextual rather than malicious verdicts' {
            $connections = @(
                [PSCustomObject]@{RecordId='tcp:smb';Protocol='TCP';State='Established';RemoteClassification='Private';RemotePort=445;ProcessPath='C:\Windows\System32\svchost.exe'},
                [PSCustomObject]@{RecordId='tcp:rdp';Protocol='TCP';State='Established';RemoteClassification='Private';RemotePort=3389;ProcessPath='C:\Windows\System32\mstsc.exe'}
            )
            $findings = @(Invoke-H1SSNetworkRules -Network $connections -CollectorStatus Success)
            $findings.Count | Should Be 2
            @($findings | Where-Object Severity -ne 'Informational').Count | Should Be 0
            @($findings | Where-Object EvidenceStrength -ne 'Contextual').Count | Should Be 0
        }

        It 'classifies IPv4 IPv6 mapped private CGNAT and link-local deterministically' {
            (Get-H1SSAddressClassification '127.0.0.1').Classification | Should Be 'Loopback'
            (Get-H1SSAddressClassification '::1').Classification | Should Be 'Loopback'
            (Get-H1SSAddressClassification '10.10.10.10').Classification | Should Be 'Private'
            (Get-H1SSAddressClassification '172.31.255.1').Classification | Should Be 'Private'
            (Get-H1SSAddressClassification '192.168.10.1').Classification | Should Be 'Private'
            (Get-H1SSAddressClassification '100.127.255.254').Classification | Should Be 'CGNAT'
            (Get-H1SSAddressClassification '169.254.10.1').Classification | Should Be 'LinkLocal'
            (Get-H1SSAddressClassification '::ffff:192.168.1.10').Classification | Should Be 'Private'
        }
    }
}

Describe 'ADSI principal source classification' {
    InModuleScope H1SSTriage {
        It 'distinguishes local domain built-in and unresolved authorities without guessing Local' {
            (Resolve-H1SSPrincipalSource -Name 'HOST-TEST-01\TestUser' -ADsPath 'WinNT://HOST-TEST-01/TestUser,user' -SID 'S-1-5-21-111111111-222222222-333333333-1001' -LocalHostName HOST-TEST-01 -LocalSamName HOST-TEST-01 -DomainName TESTDOMAIN) | Should Be 'Local'
            (Resolve-H1SSPrincipalSource -Name 'TESTDOMAIN\Domain Admins' -ADsPath 'WinNT://TESTDOMAIN/Domain Admins,group' -SID 'S-1-5-21-444444444-555555555-666666666-512' -LocalHostName HOST-TEST-01 -LocalSamName HOST-TEST-01 -DomainName TESTDOMAIN) | Should Be 'Domain'
            (Resolve-H1SSPrincipalSource -Name 'BUILTIN\Administrators' -ADsPath 'WinNT://BUILTIN/Administrators,group' -SID 'S-1-5-32-544' -LocalHostName HOST-TEST-01 -LocalSamName HOST-TEST-01 -DomainName TESTDOMAIN) | Should Be 'BuiltIn'
            (Resolve-H1SSPrincipalSource -Name 'UNRESOLVED\Mystery' -ADsPath 'WinNT://UNRESOLVED/Mystery,user' -SID $null -LocalHostName HOST-TEST-01 -LocalSamName HOST-TEST-01 -DomainName TESTDOMAIN) | Should Be 'Unknown'
            (Resolve-H1SSPrincipalSource -Name 'Mystery' -ADsPath $null -SID 'S-1-5-21-777777777-888888888-999999999-1005' -LocalHostName HOST-TEST-01 -LocalSamName HOST-TEST-01 -DomainName TESTDOMAIN) | Should Be 'Unknown'
        }
    }
}
