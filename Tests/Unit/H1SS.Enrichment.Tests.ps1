$modulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\H1SSTriage.psd1'
Import-Module -Name $modulePath -Force

Describe 'Shared file metadata contract' {
    InModuleScope H1SSTriage {
        It 'returns size timestamps and version fields for an existing file' {
            $path = Join-Path $TestDrive 'fixture.bin'
            Set-Content -LiteralPath $path -Value 'fixture' -Encoding ASCII
            $metadata = Get-H1SSFileMetadata -LiteralPath $path
            $metadata.FileExists | Should Be $true
            (@('Success','Partial') -contains $metadata.MetadataStatus) | Should Be $true
            $metadata.FileSize | Should BeGreaterThan 0
            $metadata.FileCreationTimeUtc | Should Not BeNullOrEmpty
            $metadata.FileLastWriteTimeUtc | Should Not BeNullOrEmpty
            ($metadata.PSObject.Properties.Name -contains 'CompanyName') | Should Be $true
            ($metadata.PSObject.Properties.Name -contains 'OriginalFileName') | Should Be $true
            ($metadata.PSObject.Properties.Name -contains 'FileVersion') | Should Be $true
        }

        It 'distinguishes a missing file from metadata acquisition failure' {
            $metadata = Get-H1SSFileMetadata -LiteralPath (Join-Path $TestDrive 'missing.exe')
            $metadata.FileExists | Should Be $false
            $metadata.MetadataStatus | Should Be 'Missing'
            $metadata.MetadataError | Should BeNullOrEmpty
        }

        It 'preserves valid signature identity and version metadata from the common provider' {
            Mock Get-Item { [PSCustomObject]@{ PSIsContainer=$false; CreationTimeUtc=[datetime]'2026-01-01Z'; LastWriteTimeUtc=[datetime]'2026-01-02Z'; Length=321; VersionInfo=[PSCustomObject]@{CompanyName='Fixture Corp';ProductName='Fixture Product';OriginalFilename='fixture.exe';FileVersion='3.0'} } }
            Mock Get-AuthenticodeSignature { [PSCustomObject]@{ Status='Valid'; SignerCertificate=[PSCustomObject]@{Subject='CN=Fixture';Issuer='CN=Fixture CA';Thumbprint='AABB'} } }
            $metadata = Get-H1SSFileMetadata -LiteralPath 'C:\Fixture\fixture.exe'
            $metadata.SignatureStatus | Should Be 'Valid'
            $metadata.SignerSubject | Should Be 'CN=Fixture'
            $metadata.SignerIssuer | Should Be 'CN=Fixture CA'
            $metadata.SignerThumbprint | Should Be 'AABB'
            $metadata.CompanyName | Should Be 'Fixture Corp'
            $metadata.OriginalFileName | Should Be 'fixture.exe'
            $metadata.FileVersion | Should Be '3.0'
        }

        It 'preserves an unsigned result without calling it malicious' {
            Mock Get-Item { [PSCustomObject]@{ PSIsContainer=$false; CreationTimeUtc=[datetime]'2026-01-01Z'; LastWriteTimeUtc=[datetime]'2026-01-02Z'; Length=10; VersionInfo=[PSCustomObject]@{} } }
            Mock Get-AuthenticodeSignature { [PSCustomObject]@{ Status='NotSigned'; SignerCertificate=$null } }
            $metadata = Get-H1SSFileMetadata -LiteralPath 'C:\Fixture\unsigned.exe'
            $metadata.SignatureStatus | Should Be 'NotSigned'
            $metadata.MetadataStatus | Should Be 'Success'
        }

        It 'records metadata access failure as Partial' {
            Mock Get-Item { throw (New-Object System.UnauthorizedAccessException('fixture access denied')) }
            $metadata = Get-H1SSFileMetadata -LiteralPath 'C:\Fixture\denied.exe'
            $metadata.FileExists | Should Be $false
            $metadata.MetadataStatus | Should Be 'Partial'
            $metadata.MetadataError | Should Match 'access denied'
        }

        It 'records hash success separately from HashKnown' {
            Mock Get-Item { [PSCustomObject]@{ PSIsContainer=$false; CreationTimeUtc=[datetime]'2026-01-01Z'; LastWriteTimeUtc=[datetime]'2026-01-02Z'; Length=10; VersionInfo=[PSCustomObject]@{} } }
            Mock Get-AuthenticodeSignature { [PSCustomObject]@{ Status='NotSigned'; SignerCertificate=$null } }
            Mock Get-FileHash { [PSCustomObject]@{ Hash=('A' * 64) } }
            $metadata = Get-H1SSFileMetadata -LiteralPath 'C:\Fixture\hash.exe' -IncludeHash
            $metadata.HashStatus | Should Be 'Success'
            $metadata.SHA256 | Should Be ('A' * 64)
            ($metadata.PSObject.Properties.Name -contains 'HashKnown') | Should Be $false
        }

        It 'records hash failure without converting it to file absence' {
            Mock Get-Item { [PSCustomObject]@{ PSIsContainer=$false; CreationTimeUtc=[datetime]'2026-01-01Z'; LastWriteTimeUtc=[datetime]'2026-01-02Z'; Length=10; VersionInfo=[PSCustomObject]@{} } }
            Mock Get-AuthenticodeSignature { [PSCustomObject]@{ Status='NotSigned'; SignerCertificate=$null } }
            Mock Get-FileHash { throw (New-Object System.UnauthorizedAccessException('fixture hash denied')) }
            $metadata = Get-H1SSFileMetadata -LiteralPath 'C:\Fixture\hash-denied.exe' -IncludeHash
            $metadata.FileExists | Should Be $true
            $metadata.HashStatus | Should Be 'Failed'
            $metadata.MetadataStatus | Should Be 'Partial'
            $metadata.MetadataError | Should Match 'hash denied'
        }
    }
}

Describe 'Per-run file metadata cache' {
    InModuleScope H1SSTriage {
        It 'calls the metadata provider once for the same normalized Windows path' {
            Mock Get-H1SSFileMetadata { [PSCustomObject]@{FileExists=$true;MetadataStatus='Success';SHA256=$null;HashStatus='NotRequested';SignatureStatus='NotSigned';MetadataError=$null} }
            $cache = New-H1SSFileMetadataCache
            Get-H1SSCachedFileMetadata -LiteralPath 'C:\Fixture\App.exe' -MetadataCache $cache
            Get-H1SSCachedFileMetadata -LiteralPath 'c:\fixture\app.exe' -MetadataCache $cache
            Assert-MockCalled Get-H1SSFileMetadata 1 -Exactly -Scope It
            $cache.Hits | Should Be 1
            $cache.Misses | Should Be 1
        }

        It 'keeps different paths independent' {
            Mock Get-H1SSFileMetadata { [PSCustomObject]@{FileExists=$true;MetadataStatus='Success';SHA256=$null;HashStatus='NotRequested';SignatureStatus='NotSigned';MetadataError=$null} }
            $cache = New-H1SSFileMetadataCache
            Get-H1SSCachedFileMetadata -LiteralPath 'C:\Fixture\one.exe' -MetadataCache $cache
            Get-H1SSCachedFileMetadata -LiteralPath 'C:\Fixture\two.exe' -MetadataCache $cache
            Assert-MockCalled Get-H1SSFileMetadata 2 -Exactly -Scope It
        }

        It 'calculates a repeated selective hash only once' {
            Mock Get-FileHash { [PSCustomObject]@{Hash=('B' * 64)} }
            $cache = New-H1SSFileMetadataCache
            (Get-H1SSCachedFileHash -LiteralPath 'C:\Fixture\same.exe' -MetadataCache $cache).SHA256 | Should Be ('B' * 64)
            (Get-H1SSCachedFileHash -LiteralPath 'c:\fixture\same.exe' -MetadataCache $cache).SHA256 | Should Be ('B' * 64)
            Assert-MockCalled Get-FileHash 1 -Exactly -Scope It
        }
    }
}

Describe 'Process metadata and temporal parent resolution' {
    InModuleScope H1SSTriage {
        It 'resolves owner and SID without losing process metadata' {
            Mock Get-CimInstance { @([PSCustomObject]@{ProcessId=200;ParentProcessId=0;Name='child.exe';ExecutablePath='C:\Fixture\child.exe';CommandLine='child.exe -x';CreationDate=[datetime]'2026-01-01T00:01:00Z'}) }
            Mock Get-Process { @([PSCustomObject]@{Id=200;UserName='TESTDOMAIN\TestUser';SessionId=2;CPU=1.5;WorkingSet64=4096}) }
            Mock Resolve-H1SSOwnerSid { 'S-1-5-21-111111111-222222222-333333333-1001' }
            Mock Get-H1SSCachedFileMetadata { [PSCustomObject]@{FileExists=$true;MetadataStatus='Success';SHA256=$null;HashStatus='NotRequested';SignatureStatus='NotSigned';SignerSubject=$null;SignerIssuer=$null;SignerThumbprint=$null;CompanyName='Fixture';ProductName='Fixture';OriginalFileName='child.exe';FileVersion='1.0';FileCreationTimeUtc='2026-01-01T00:00:00Z';FileLastWriteTimeUtc='2026-01-01T00:00:30Z';FileSize=4096;MetadataError=$null} }
            $result = Get-H1SSProcessesCollector -Mode Standard
            $process = @($result.Records)[0]
            $process.Owner | Should Be 'TESTDOMAIN\TestUser'
            $process.OwnerSid | Should Be 'S-1-5-21-111111111-222222222-333333333-1001'
            $process.OwnerResolutionStatus | Should Be 'Resolved'
            $process.RawExecutablePath | Should Be 'C:\Fixture\child.exe'
            $process.FileSize | Should Be 4096
        }

        It 'resolves a normal parent created before its child' {
            $parent=[PSCustomObject]@{RecordId='p1';PID=100;PPID=0;Name='parent.exe';ExecutablePath='C:\Fixture\parent.exe';CreationDate='2026-01-01T00:00:00Z'}
            $child=[PSCustomObject]@{RecordId='c1';PID=101;PPID=100;Name='child.exe';ExecutablePath='C:\Fixture\child.exe';CreationDate='2026-01-01T00:01:00Z'}
            Resolve-H1SSProcessParents -Processes @($parent,$child)
            $child.ParentResolutionStatus | Should Be 'Resolved'
            $child.ParentName | Should Be 'parent.exe'
            $child.ParentCreationTime | Should Be '2026-01-01T00:00:00Z'
        }

        It 'chooses only the latest temporally compatible parent during PID reuse' {
            $old=[PSCustomObject]@{RecordId='old';PID=100;PPID=0;Name='old.exe';ExecutablePath='C:\Fixture\old.exe';CreationDate='2026-01-01T00:00:00Z'}
            $child=[PSCustomObject]@{RecordId='child';PID=101;PPID=100;Name='child.exe';ExecutablePath='C:\Fixture\child.exe';CreationDate='2026-01-01T00:05:00Z'}
            $reused=[PSCustomObject]@{RecordId='new';PID=100;PPID=0;Name='new.exe';ExecutablePath='C:\Fixture\new.exe';CreationDate='2026-01-01T00:10:00Z'}
            Resolve-H1SSProcessParents -Processes @($old,$child,$reused)
            $child.ParentResolutionStatus | Should Be 'Resolved'
            $child.ParentName | Should Be 'old.exe'
        }

        It 'marks a missing snapshot parent as ExitedOrUnavailable' {
            $child=[PSCustomObject]@{RecordId='child';PID=101;PPID=100;Name='child.exe';ExecutablePath='C:\Fixture\child.exe';CreationDate='2026-01-01T00:05:00Z'}
            Resolve-H1SSProcessParents -Processes @($child)
            $child.ParentResolutionStatus | Should Be 'ExitedOrUnavailable'
            $child.ParentName | Should BeNullOrEmpty
        }

        It 'does not invent a parent when child creation time is missing' {
            $parent=[PSCustomObject]@{RecordId='p1';PID=100;PPID=0;Name='parent.exe';ExecutablePath='C:\Fixture\parent.exe';CreationDate='2026-01-01T00:00:00Z'}
            $child=[PSCustomObject]@{RecordId='c1';PID=101;PPID=100;Name='child.exe';ExecutablePath='C:\Fixture\child.exe';CreationDate=$null}
            Resolve-H1SSProcessParents -Processes @($parent,$child)
            $child.ParentResolutionStatus | Should Be 'Unresolved'
            $child.ParentName | Should BeNullOrEmpty
        }
    }
}

Describe 'Service enrichment' {
    InModuleScope H1SSTriage {
        It 'parses service arguments and driver paths without discarding the raw value' {
            $service = ConvertFrom-H1SSServiceImagePath '"C:\Program Files\Fixture\svc.exe" --service --port 10'
            $service.RawImagePath | Should Be '"C:\Program Files\Fixture\svc.exe" --service --port 10'
            $service.ExecutablePath | Should Be 'C:\Program Files\Fixture\svc.exe'
            $service.Arguments | Should Be '--service --port 10'
            $driver = ConvertFrom-H1SSServiceImagePath 'C:\Windows\System32\drivers\fixture.sys -flag'
            $driver.ExecutablePath | Should Be 'C:\Windows\System32\drivers\fixture.sys'
            $driver.Arguments | Should Be '-flag'
        }

        It 'keeps executable metadata separate from ServiceDll metadata' {
            Mock Get-CimInstance { @([PSCustomObject]@{Name='FixtureSvc';DisplayName='Fixture Service';State='Running';StartMode='Auto';StartName='LocalSystem';ProcessId=50;PathName='"C:\Fixture\service.exe" -k';ServiceType='Own Process'}) }
            Mock Get-H1SSOptionalRegistryValue { [PSCustomObject]@{Value='C:\Fixture\service.dll';ErrorMessage=$null} }
            Mock Get-H1SSCachedFileMetadata {
                if ($LiteralPath -like '*.dll') { [PSCustomObject]@{FileExists=$true;MetadataStatus='Success';SHA256=$null;HashStatus='NotRequested';SignatureStatus='NotSigned';SignerSubject=$null;SignerIssuer=$null;SignerThumbprint=$null;CompanyName='DLL Corp';ProductName='DLL';OriginalFileName='service.dll';FileVersion='2.0';FileCreationTimeUtc=$null;FileLastWriteTimeUtc=$null;FileSize=200;MetadataError=$null} }
                else { [PSCustomObject]@{FileExists=$true;MetadataStatus='Success';SHA256=$null;HashStatus='NotRequested';SignatureStatus='Valid';SignerSubject='CN=Service';SignerIssuer='CN=CA';SignerThumbprint='CCDD';CompanyName='Service Corp';ProductName='Service';OriginalFileName='service.exe';FileVersion='1.0';FileCreationTimeUtc=$null;FileLastWriteTimeUtc=$null;FileSize=100;MetadataError=$null} }
            }
            Mock Test-H1SSPathPotentiallyWritable { $false }
            $result = Get-H1SSServicesCollector -Mode Standard
            $record = @($result.Records)[0]
            $record.SignatureStatus | Should Be 'Valid'
            $record.CompanyName | Should Be 'Service Corp'
            $record.ServiceDllMetadata.SignatureStatus | Should Be 'NotSigned'
            $record.ServiceDllMetadata.CompanyName | Should Be 'DLL Corp'
            $record.Arguments | Should Be '-k'
        }

        It 'preserves missing binary and ACL uncertainty explicitly' {
            Mock Get-CimInstance { @([PSCustomObject]@{Name='MissingSvc';DisplayName='Missing';State='Stopped';StartMode='Manual';StartName='LocalSystem';ProcessId=0;PathName='C:\Fixture\missing.exe';ServiceType='Own Process'}) }
            Mock Get-H1SSOptionalRegistryValue { [PSCustomObject]@{Value=$null;ErrorMessage=$null} }
            Mock Get-H1SSCachedFileMetadata { [PSCustomObject]@{FileExists=$false;MetadataStatus='Missing';SHA256=$null;HashStatus='NotRequested';SignatureStatus='Unavailable';SignerSubject=$null;SignerIssuer=$null;SignerThumbprint=$null;CompanyName=$null;ProductName=$null;OriginalFileName=$null;FileVersion=$null;FileCreationTimeUtc=$null;FileLastWriteTimeUtc=$null;FileSize=$null;MetadataError=$null} }
            Mock Test-H1SSPathPotentiallyWritable { if ($ErrorMessage) { $ErrorMessage.Value='fixture ACL denied' }; $null }
            $result = Get-H1SSServicesCollector -Mode Standard
            $record = @($result.Records)[0]
            $record.FileExists | Should Be $false
            $record.MetadataStatus | Should Be 'Missing'
            $record.WritableExecutable | Should BeNullOrEmpty
            $record.ExecutableAclStatus | Should Be 'Partial'
            $result.Status | Should Be 'Partial'
        }
    }
}

Describe 'Scheduled task rich collection and pipeline order' {
    InModuleScope H1SSTriage {
        It 'preserves disabled state multiple actions triggers XML and a consistent XML hash' {
            $actions=@([PSCustomObject]@{Execute='C:\Fixture\one.exe';Arguments='-one';WorkingDirectory='C:\Fixture'},[PSCustomObject]@{Execute='C:\Fixture\two.exe';Arguments='-two';WorkingDirectory='C:\Fixture'})
            $triggers=@([PSCustomObject]@{CimClass=[PSCustomObject]@{CimClassName='BootTrigger'};Enabled=$true;StartBoundary=$null;EndBoundary=$null;Repetition=$null},[PSCustomObject]@{CimClass=[PSCustomObject]@{CimClassName='LogonTrigger'};Enabled=$true;StartBoundary=$null;EndBoundary=$null;Repetition=$null})
            Mock Get-ScheduledTask { @([PSCustomObject]@{TaskName='FixtureTask';TaskPath='\Fixture\';State='Disabled';Author='Fixture';Description='Fixture task';Principal=[PSCustomObject]@{UserId='SYSTEM';LogonType='ServiceAccount';RunLevel='Highest'};Actions=$actions;Triggers=$triggers;Settings=[PSCustomObject]@{Hidden=$true}}) }
            Mock Get-ScheduledTaskInfo { [PSCustomObject]@{LastRunTime=[datetime]'2026-01-01Z';NextRunTime=[datetime]'2026-01-02Z';LastTaskResult=0;NumberOfMissedRuns=1} }
            Mock Export-ScheduledTask { '<Task><Actions /></Task>' }
            $result = Get-H1SSScheduledTasksCollector
            $task = @($result.Records)[0]
            $task.Enabled | Should Be $false
            @($task.Actions).Count | Should Be 2
            @($task.Triggers).Count | Should Be 2
            $task.XML | Should Be '<Task><Actions /></Task>'
            $task.XmlSHA256 | Should Be (Get-H1SSStringSha256 -Value $task.XML)
            $task.DetectionEnrichmentStatus | Should Be 'Pending'
        }
    }
}

Describe 'Selective hashing policy' {
    InModuleScope H1SSTriage {
        It 'hashes a process referenced by a relevant network finding but not an unrelated process in Quick' {
            Mock Get-FileHash { [PSCustomObject]@{Hash=('C' * 64)} }
            $target=[PSCustomObject]@{RecordId='process:target';FileExists=$true;ExecutablePath='C:\Fixture\target.exe';SHA256=$null;HashStatus='NotRequested'}
            $other=[PSCustomObject]@{RecordId='process:other';FileExists=$true;ExecutablePath='C:\Fixture\other.exe';SHA256=$null;HashStatus='NotRequested'}
            $finding=[PSCustomObject]@{Bucket='Alert';EntityId='tcp:target';SourceRecordIds=@('tcp:target','process:target')}
            $data=@{Processes=@($target,$other);Services=@();ScheduledTasks=@();RunKeys=@();Startup=@()}
            $errors=@(Add-H1SSSelectiveFileHashes -Findings @($finding) -Data $data -Mode Quick -MetadataCache (New-H1SSFileMetadataCache))
            $errors.Count | Should Be 0
            $target.SHA256 | Should Be ('C' * 64)
            $target.HashStatus | Should Be 'Success'
            $other.SHA256 | Should BeNullOrEmpty
            Assert-MockCalled Get-FileHash 1 -Exactly -Scope It
        }

        It 'propagates a selective hash failure and keeps the file distinct from missing' {
            Mock Get-FileHash { throw (New-Object System.UnauthorizedAccessException('fixture selective hash denied')) }
            $target=[PSCustomObject]@{RecordId='process:target';FileExists=$true;ExecutablePath='C:\Fixture\target.exe';SHA256=$null;HashStatus='NotRequested'}
            $finding=[PSCustomObject]@{Bucket='Alert';EntityId='process:target';SourceRecordIds=@('process:target')}
            $data=@{Processes=@($target);Services=@();ScheduledTasks=@();RunKeys=@();Startup=@()}
            $errors=@(Add-H1SSSelectiveFileHashes -Findings @($finding) -Data $data -Mode Quick -MetadataCache (New-H1SSFileMetadataCache))
            $errors.Count | Should Be 1
            $errors[0].ErrorType | Should Be 'HashAcquisitionError'
            $target.FileExists | Should Be $true
            $target.HashStatus | Should Be 'Failed'
        }
    }
}
