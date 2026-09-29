$modulePath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\H1SSTriage.psd1'
Import-Module -Name $modulePath -Force

Describe 'Collector state semantics' {
    InModuleScope H1SSTriage {
        It 'treats a successful zero-result collection as Success' {
            $result = Invoke-H1SSCollector -Name Zero -Required $true -ScriptBlock { New-H1SSCollectorPayload -Records @() }
            $result.State.Status | Should Be 'Success'
            $result.State.RecordCount | Should Be 0
        }

        It 'treats an exception as Failed instead of Success' {
            $result = Invoke-H1SSCollector -Name Broken -Required $true -ScriptBlock { throw [System.InvalidOperationException]'fixture failure' }
            $result.State.Status | Should Be 'Failed'
            $result.State.ErrorMessage | Should Match 'fixture failure'
        }

        It 'does not report Complete when a required collector fails' {
            $now = [DateTime]::UtcNow
            $states = @(
                (New-H1SSCollectorState -CollectorName Processes -Status Success -StartedAtUtc $now -FinishedAtUtc $now -Required $true)
                (New-H1SSCollectorState -CollectorName Services -Status Failed -StartedAtUtc $now -FinishedAtUtc $now -Required $true)
            )
            (Get-H1SSOverallStatus -CollectorStates $states) | Should Be 'Partial'
        }
    }
}

Describe 'CSV injection projection' {
    InModuleScope H1SSTriage {
        It 'prefixes formula-leading strings' {
            (Protect-H1SSCsvValue '=1+1') | Should Be "'=1+1"
            (Protect-H1SSCsvValue '+SUM(A1)') | Should Be "'+SUM(A1)"
            (Protect-H1SSCsvValue '-2+3') | Should Be "'-2+3"
            (Protect-H1SSCsvValue '@link') | Should Be "'@link"
        }

        It 'does not change ordinary text' {
            (Protect-H1SSCsvValue 'powershell.exe') | Should Be 'powershell.exe'
        }
    }
}

Describe 'IP classification' {
    InModuleScope H1SSTriage {
        It 'classifies public, private, loopback, CGNAT and mapped addresses' {
            (Get-H1SSAddressClassification '203.0.113.1').Classification | Should Be 'Public'
            (Get-H1SSAddressClassification '192.168.1.1').Classification | Should Be 'Private'
            (Get-H1SSAddressClassification '127.0.0.1').Classification | Should Be 'Loopback'
            (Get-H1SSAddressClassification '100.64.10.1').Classification | Should Be 'CGNAT'
            (Get-H1SSAddressClassification '::ffff:10.1.2.3').Classification | Should Be 'Private'
            (Get-H1SSAddressClassification 'fd00::1').Classification | Should Be 'Private'
        }
    }
}

Describe 'Service image path parsing' {
    InModuleScope H1SSTriage {
        It 'parses quoted paths and arguments' {
            $result = ConvertFrom-H1SSServiceImagePath '"C:\Program Files\Vendor\svc.exe" -service'
            $result.ExecutablePath | Should Be 'C:\Program Files\Vendor\svc.exe'
            $result.Arguments | Should Be '-service'
            $result.UnquotedServicePath | Should Be $false
        }

        It 'flags an unquoted path with spaces as a misconfiguration' {
            $result = ConvertFrom-H1SSServiceImagePath 'C:\Program Files\Vendor App\svc.exe -service'
            $result.ExecutablePath | Should Be 'C:\Program Files\Vendor App\svc.exe'
            $result.UnquotedServicePath | Should Be $true
        }
    }
}

Describe 'Safe output paths and unique RunId' {
    InModuleScope H1SSTriage {
        It 'supports spaces, Unicode and square brackets literally' {
            $path = Join-Path $TestDrive 'Relatório [IR] espaço'
            $resolved = Resolve-H1SSOutputBasePath $path
            (Test-Path -LiteralPath $resolved -PathType Container) | Should Be $true
        }

        It 'creates distinct report directories' {
            $base = Resolve-H1SSOutputBasePath (Join-Path $TestDrive 'runs')
            $first = New-H1SSRunDirectory $base
            $second = New-H1SSRunDirectory $base
            $first.Path | Should Not Be $second.Path
            $first.RunId.Length | Should Be 8
        }
    }
}

Describe 'Windows PowerShell 5.1 source encoding' {
    InModuleScope H1SSTriage {
        It 'ships PowerShell source files with UTF-8 BOM' {
            $sourceFiles = Get-ChildItem -Recurse -File -LiteralPath $Script:ModuleRoot | Where-Object { $_.Extension -in @('.ps1','.psm1','.psd1') }
            foreach ($file in $sourceFiles) {
                $bytes = [IO.File]::ReadAllBytes($file.FullName)
                ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) | Should Be $true
            }
        }
    }
}
