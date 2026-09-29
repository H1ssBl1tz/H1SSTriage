$modulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\H1SSTriage.psd1'
Import-Module -Name $modulePath -Force

Describe 'Optional acquisition semantics' {
    InModuleScope H1SSTriage {
        It 'treats a missing optional registry value as normal absence' {
            Mock Get-ItemProperty { throw (New-Object System.Management.Automation.ItemNotFoundException('fixture missing')) }

            $result = Get-H1SSOptionalRegistryValue -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Fixture' -Name 'OptionalValue'

            $result.Present | Should Be $false
            $result.ErrorMessage | Should Be ''
        }

        It 'does not convert AccessDenied into absence' {
            Mock Get-ItemProperty { throw (New-Object System.UnauthorizedAccessException('fixture access denied')) }

            $result = Get-H1SSOptionalRegistryValue -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Fixture' -Name 'ProtectedValue'

            $result.Present | Should Be $false
            $result.ErrorType | Should Match 'UnauthorizedAccessException'
            $result.ErrorMessage | Should Match 'access denied'
        }

        It 'propagates a ServiceDll AccessDenied result as Partial' {
            Mock Get-CimInstance {
                @([PSCustomObject]@{ Name='FixtureSvc'; DisplayName='Fixture Service'; State='Running'; StartMode='Auto'; StartName='LocalSystem'; ProcessId=123; PathName='C:\Fixture\service.exe'; ServiceType='Own Process' })
            }
            Mock Get-ItemProperty { throw (New-Object System.UnauthorizedAccessException('fixture ServiceDll access denied')) }
            Mock Get-H1SSFileMetadata { [PSCustomObject]@{ FileExists=$false; SignatureStatus='Unavailable'; SignerSubject=$null; MetadataError=$null } }
            Mock Test-H1SSPathPotentiallyWritable { $null }

            $result = Get-H1SSServicesCollector -Mode Quick

            $result.Status | Should Be 'Partial'
            $result.ErrorMessage | Should Match 'ServiceDll'
            $result.ErrorMessage | Should Match 'access denied'
        }

        It 'records an unexpected AdvancedPersistence subsource exception as Partial' {
            Mock Get-ItemProperty { throw (New-Object System.Management.Automation.ItemNotFoundException('fixture missing')) }
            Mock Get-ChildItem { @() }
            Mock Get-ChildItem { throw (New-Object System.InvalidOperationException('fixture provider failure')) } -ParameterFilter { $LiteralPath -like '*SilentProcessExit' }
            Mock Get-CimInstance { @() }

            $result = Get-H1SSAdvancedPersistenceCollector

            $result.Status | Should Be 'Partial'
            $result.ErrorMessage | Should Match 'SilentProcessExit'
            $result.ErrorMessage | Should Match 'provider failure'
        }
    }
}

Describe 'Post-collection enrichment reliability' {
    InModuleScope H1SSTriage {
        It 'returns hash acquisition errors instead of discarding them' {
            Mock Get-FileHash { throw (New-Object System.UnauthorizedAccessException('fixture hash denied')) }
            $process = [PSCustomObject]@{ RecordId='process:fixture'; FileExists=$true; ExecutablePath='C:\Fixture\sample.exe'; SHA256=$null }
            $data = @{ Processes=@($process); Services=@(); ScheduledTasks=@() }

            $errors = @(Add-H1SSSelectiveFileHashes -Findings @() -Data $data -Mode Deep)

            $errors.Count | Should Be 1
            $errors[0].CollectorName | Should Be 'Processes'
            $errors[0].ErrorMessage | Should Match 'hash denied'
        }
    }
}

Describe 'Manifest reliability context' {
    InModuleScope H1SSTriage {
        It 'serializes the current collector SID without a non-terminating property error' {
            $errors = @()
            $preflight = Get-H1SSPreflight -ToolScriptPath $null -OutputPath $TestDrive -ErrorVariable errors

            $errors.Count | Should Be 0
            $preflight.CollectorUserSid | Should Match '^S-1-'
        }

        It 'records the collection mode and effective parameter values' {
            $reportDir = Join-Path -Path $TestDrive -ChildPath 'manifest'
            [void][IO.Directory]::CreateDirectory($reportDir)
            $now = [DateTime]::UtcNow
            $preflight = [PSCustomObject]@{
                PowerShellVersion='5.1.19041.1'; PowerShellEdition='Desktop'; PowerShellBitness=64
                CollectorUser='TESTDOMAIN\TestUser'; CollectorUserSid='S-1-5-21-111111111-222222222-333333333-1001'
                IsElevated=$false; IntegrityLevel='Medium'; ToolScriptPath='C:\Tools\H1SSTriage.ps1'; ToolSha256='FIXTURE'
                Capabilities=@(); ModuleImports=@()
            }
            $state = New-H1SSCollectorState -CollectorName Processes -Status Success -StartedAtUtc $now -FinishedAtUtc $now -Required $true
            $parameters = [ordered]@{ eventLogHours=48; recentFileHours=12; maxRecentFiles=321; maxScanDurationSeconds=45 }

            Write-H1SSManifest -ReportDir $reportDir -RunId 'A1B2C3D4' -OverallStatus Complete -Preflight $preflight -CollectorStates @($state) -OutputFiles @() -SystemData @() -StartedAtUtc $now -FinishedAtUtc $now -CollectionMode Quick -CollectionParameters $parameters
            $manifest = Get-Content -Raw -LiteralPath (Join-Path $reportDir '00_MANIFEST.json') -Encoding UTF8 | ConvertFrom-Json

            $manifest.collectionMode | Should Be 'Quick'
            $manifest.collectionParameters.eventLogHours | Should Be 48
            $manifest.collectionParameters.recentFileHours | Should Be 12
            $manifest.collectionParameters.maxRecentFiles | Should Be 321
            $manifest.collectionParameters.maxScanDurationSeconds | Should Be 45
        }
    }
}

Describe 'Incomplete collection reporting' {
    InModuleScope H1SSTriage {
        It 'warns about incomplete coverage when there are zero findings' {
            $summaryPath = Join-Path -Path $TestDrive -ChildPath '00_SUMARIO.txt'
            $now = [DateTime]::UtcNow
            $preflight = [PSCustomObject]@{ CollectorUser='TESTDOMAIN\TestUser'; CollectorUserSid='S-1-5-21-111111111-222222222-333333333-1001'; IsElevated=$false; IntegrityLevel='Medium' }
            $state = New-H1SSCollectorState -CollectorName Processes -Status Failed -StartedAtUtc $now -FinishedAtUtc $now -Required $true -ErrorType 'FixtureFailure' -ErrorMessage 'fixture collection failure'

            Write-H1SSSummary -LiteralPath $summaryPath -OverallStatus Failed -RunId 'A1B2C3D4' -Preflight $preflight -CollectorStates @($state) -Findings @() -StartedAtUtc $now -FinishedAtUtc $now
            $summary = Get-Content -Raw -LiteralPath $summaryPath -Encoding UTF8

            $summary | Should Match 'coleta foi parcial ou falhou'
            $summary | Should Match 'Ausência de dados não é evidência de ausência de comprometimento'
            $summary | Should Match 'Consulte 00_MANIFEST.json'
        }
    }
}
