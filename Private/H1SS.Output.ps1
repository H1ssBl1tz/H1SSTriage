function Write-H1SSJsonFile {
    param([Parameter(Mandatory = $true)][string]$LiteralPath, [Parameter(Mandatory = $true)][object]$Value, [int]$Depth = 10)
    $json = $Value | ConvertTo-Json -Depth $Depth
    Set-Content -LiteralPath $LiteralPath -Value $json -Encoding UTF8 -ErrorAction Stop
}

function Export-H1SSCsvFile {
    param([Parameter(Mandatory = $true)][string]$LiteralPath, [object[]]$Records)
    if (@($Records).Count -eq 0) {
        Set-Content -LiteralPath $LiteralPath -Value '' -Encoding UTF8 -ErrorAction Stop
        return
    }
    @($Records) | ConvertTo-H1SSCsvSafeObject | Export-Csv -LiteralPath $LiteralPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
}

function ConvertTo-H1SSFlatTask {
    param([object]$Task)
    [PSCustomObject]@{
        TaskName=$Task.TaskName; TaskPath=$Task.TaskPath; State=$Task.State; Enabled=$Task.Enabled; Author=$Task.Author; Description=$Task.Description
        PrincipalUserId=$Task.PrincipalUserId; PrincipalLogonType=$Task.PrincipalLogonType; PrincipalRunLevel=$Task.PrincipalRunLevel
        Actions=(@($Task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; ')
        WorkingDirectory=(@($Task.Actions | ForEach-Object WorkingDirectory) -join '; ')
        Triggers=(@($Task.Triggers | ForEach-Object { "$($_.Type):$($_.StartBoundary)" }) -join '; ')
        LastRunTime=$Task.LastRunTime; NextRunTime=$Task.NextRunTime; LastTaskResult=$Task.LastTaskResult; NumberOfMissedRuns=$Task.NumberOfMissedRuns
        Hidden=$Task.Hidden; XmlSHA256=$Task.XmlSHA256; ItemCollectionStatus=$Task.ItemCollectionStatus; ItemErrors=(@($Task.ItemErrors) -join '; ')
        DetectionEnrichmentStatus=$Task.DetectionEnrichmentStatus; DetectionEnrichmentErrors=(@($Task.DetectionEnrichmentErrors) -join '; ')
        ActionFileMetadata=(@($Task.ActionFileMetadata | ForEach-Object { "$($_.ResolvedPath)|$($_.SignatureStatus)|$($_.MetadataStatus)|$($_.HashStatus)" }) -join '; ')
    }
}

function ConvertTo-H1SSFlatFinding {
    param([object]$Finding)
    [PSCustomObject]@{
        FindingId=$Finding.FindingId; RuleId=$Finding.RuleId; RuleVersion=$Finding.RuleVersion; Severity=$Finding.Severity; Confidence=$Finding.Confidence
        EvidenceStrength=$Finding.EvidenceStrength; ObservedAtUtc=$Finding.ObservedAtUtc; Collector=$Finding.Collector; CollectorStatus=$Finding.CollectorStatus
        EntityType=$Finding.EntityType; EntityId=$Finding.EntityId; Score=$Finding.Score; Signals=(@($Finding.Signals) -join '; '); Why=$Finding.Why
        Recommendation=$Finding.Recommendation; ValidationSteps=(@($Finding.ValidationSteps) -join '; '); SourceRecordIds=(@($Finding.SourceRecordIds) -join '; ')
        SourceFiles=(@($Finding.SourceFiles) -join '; ')
    }
}

function Write-H1SSSummary {
    param(
        [string]$LiteralPath,
        [string]$OverallStatus,
        [string]$RunId,
        [object]$Preflight,
        [object[]]$CollectorStates,
        [object[]]$Findings,
        [DateTime]$StartedAtUtc,
        [DateTime]$FinishedAtUtc
    )
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('RELATÓRIO DE TRIAGEM H1SSTRIAGE') | Out-Null
    $lines.Add("Versão: $Script:H1SSTriageVersion | Schema: $Script:SchemaVersion | Rules: $Script:RuleSetVersion") | Out-Null
    $lines.Add("RunId: $RunId") | Out-Null
    $lines.Add("Estado geral da coleta: $OverallStatus") | Out-Null
    $lines.Add("Início UTC: $(ConvertTo-H1SSIsoUtc $StartedAtUtc)") | Out-Null
    $lines.Add("Fim UTC: $(ConvertTo-H1SSIsoUtc $FinishedAtUtc)") | Out-Null
    $lines.Add("Usuário: $($Preflight.CollectorUser) | SID: $($Preflight.CollectorUserSid) | Elevado: $($Preflight.IsElevated) | Integrity: $($Preflight.IntegrityLevel)") | Out-Null
    $lines.Add('') | Out-Null
    $lines.Add('COBERTURA DOS COLETORES') | Out-Null
    foreach ($state in $CollectorStates) {
        $suffix = if ($state.ErrorMessage) { " | $($state.ErrorMessage)" } else { '' }
        $lines.Add(("- {0}: {1} | Required={2} | Records={3} | {4}ms{5}" -f $state.CollectorName,$state.Status,$state.Required,$state.RecordCount,$state.DurationMs,$suffix)) | Out-Null
    }
    $lines.Add('') | Out-Null
    if ($OverallStatus -ne 'Complete') {
        $lines.Add('ATENÇÃO: a coleta foi parcial ou falhou. Revise 00_MANIFEST.json antes de interpretar a ausência de findings.') | Out-Null
        $lines.Add('Ausência de dados não é evidência de ausência de comprometimento.') | Out-Null
        $lines.Add('') | Out-Null
    }
    $alerts = @($Findings | Where-Object Bucket -eq 'Alert')
    $lines.Add('FINDINGS INVESTIGÁVEIS') | Out-Null
    if ($alerts.Count -eq 0) {
        $lines.Add('Nenhuma regra de detecção foi acionada nas fontes coletadas com sucesso.') | Out-Null
        $lines.Add('Consulte 00_MANIFEST.json para verificar cobertura, falhas e limitações da coleta.') | Out-Null
    }
    else {
        foreach ($finding in $alerts | Sort-Object @{Expression={ switch ($_.Severity) { 'Critical'{1};'High'{2};'Medium'{3};'Low'{4};default{5} } }},RuleId) {
            $lines.Add(("[{0}/{1}] {2} | {3} | Signals={4}" -f $finding.Severity,$finding.Confidence,$finding.RuleId,$finding.Why,(@($finding.Signals) -join ','))) | Out-Null
        }
    }
    $lines.Add('') | Out-Null
    $lines.Add('Este relatório é live response/triage. Não é antivírus, EDR ou aquisição forense bit-a-bit e não prova que o sistema está limpo.') | Out-Null
    Set-Content -LiteralPath $LiteralPath -Value $lines -Encoding UTF8 -ErrorAction Stop
}

function Write-H1SSProcessTree {
    param([string]$LiteralPath,[object[]]$Processes)
    $children = @{}
    foreach ($process in $Processes | Where-Object ParentResolutionStatus -eq 'Resolved') {
        $key = [int]$process.PPID
        if (-not $children.ContainsKey($key)) { $children[$key] = New-Object System.Collections.Generic.List[object] }
        $children[$key].Add($process) | Out-Null
    }
    $visited = @{}
    $lines = New-Object System.Collections.Generic.List[string]
    function Add-TreeNode {
        param([object]$Node,[int]$Depth)
        if ($Depth -gt 64 -or $visited.ContainsKey($Node.RecordId)) { return }
        $visited[$Node.RecordId]=$true
        $lines.Add((('{0}{1} [PID={2} PPID={3} Parent={4}] {5}' -f ('  ' * $Depth),$Node.Name,$Node.PID,$Node.PPID,$Node.ParentResolutionStatus,$Node.ExecutablePath))) | Out-Null
        if ($children.ContainsKey([int]$Node.PID)) { foreach ($child in $children[[int]$Node.PID] | Sort-Object CreationDate,PID) { Add-TreeNode -Node $child -Depth ($Depth+1) } }
    }
    foreach ($root in $Processes | Where-Object ParentResolutionStatus -ne 'Resolved' | Sort-Object CreationDate,PID) { Add-TreeNode -Node $root -Depth 0 }
    foreach ($orphan in $Processes | Where-Object { -not $visited.ContainsKey($_.RecordId) }) { Add-TreeNode -Node $orphan -Depth 0 }
    Set-Content -LiteralPath $LiteralPath -Value $lines -Encoding UTF8 -ErrorAction Stop
}

function Export-H1SSReports {
    param([string]$ReportDir, [hashtable]$Data, [object[]]$Findings, [string]$OverallStatus, [string]$RunId, [object]$Preflight, [object[]]$CollectorStates, [DateTime]$StartedAtUtc, [DateTime]$FinishedAtUtc)

    $summaryPath = Join-Path $ReportDir '00_SUMARIO.txt'
    Write-H1SSSummary -LiteralPath $summaryPath -OverallStatus $OverallStatus -RunId $RunId -Preflight $Preflight -CollectorStates $CollectorStates -Findings $Findings -StartedAtUtc $StartedAtUtc -FinishedAtUtc $FinishedAtUtc
    Write-H1SSProcessTree -LiteralPath (Join-Path $ReportDir 'process_tree.txt') -Processes @($Data.Processes)

    $jsonFiles = [ordered]@{
        'system.json'          = @($Data.System)
        'users.json'           = [PSCustomObject]@{ Users=@($Data.Users); Administrators=@($Data.Administrators) }
        'processes.json'       = @($Data.Processes)
        'services.json'        = @($Data.Services)
        'network.json'         = [PSCustomObject]@{ Configuration=@($Data.NetworkConfiguration); Endpoints=@($Data.Network); Dns=@($Data.DNS) }
        'scheduled_tasks.json' = @($Data.ScheduledTasks)
        'persistence.json'     = [PSCustomObject]@{ RunKeys=@($Data.RunKeys); Startup=@($Data.Startup); StartupCommands=@($Data.StartupCommands); Advanced=@($Data.AdvancedPersistence) }
        'events.json'          = @($Data.Events)
        'defender.json'        = @($Data.Defender)
        'recent_files.json'    = @($Data.RecentFiles)
        'findings.json'        = @($Findings)
    }
    foreach ($entry in $jsonFiles.GetEnumerator()) {
        Write-H1SSJsonFile -LiteralPath (Join-Path $ReportDir $entry.Key) -Value ([PSCustomObject]@{ schemaVersion=$Script:SchemaVersion; generatedAtUtc=ConvertTo-H1SSIsoUtc (Get-H1SSUtcNow); records=$entry.Value }) -Depth 14
    }

    Export-H1SSCsvFile (Join-Path $ReportDir '01_usuarios_locais.csv') @($Data.Users)
    Export-H1SSCsvFile (Join-Path $ReportDir '01b_membros_administrators.csv') @($Data.Administrators)
    Export-H1SSCsvFile (Join-Path $ReportDir '02_processos_completos.csv') @($Data.Processes)
    Export-H1SSCsvFile (Join-Path $ReportDir '03_top_cpu.csv') @($Data.Processes | Sort-Object CPUSeconds -Descending | Select-Object -First 15)
    Export-H1SSCsvFile (Join-Path $ReportDir '04_top_memoria.csv') @($Data.Processes | Sort-Object WorkingSet -Descending | Select-Object -First 15)
    Export-H1SSCsvFile (Join-Path $ReportDir '04b_processos_alto_risco.csv') @($Data.Processes | Where-Object { $_.ExecutablePath -match '(?i)\\(Temp|Users\\Public|\$Recycle\.Bin|PerfLogs)\\' })
    Export-H1SSCsvFile (Join-Path $ReportDir '04c_processos_para_revisar.csv') @($Data.Processes | Where-Object { $_.TrustLevel -in @('Unknown','Suspicious') -and (Test-H1SSUserWritablePath $_.ExecutablePath) })
    Export-H1SSCsvFile (Join-Path $ReportDir '04d_processos_apps_conhecidos.csv') @($Data.Processes | Where-Object TrustLevel -in @('Trusted','LikelyTrusted'))
    Export-H1SSCsvFile (Join-Path $ReportDir '05_servicos.csv') @($Data.Services)
    Export-H1SSCsvFile (Join-Path $ReportDir '05b_servicos_em_execucao.csv') @($Data.Services | Where-Object State -eq 'Running')
    Set-Content -LiteralPath (Join-Path $ReportDir '06_configuracao_rede.txt') -Value (@($Data.NetworkConfiguration) | Format-List | Out-String -Width 240) -Encoding UTF8
    Export-H1SSCsvFile (Join-Path $ReportDir '07_enderecos_ip.csv') @($Data.NetworkConfiguration)
    Export-H1SSCsvFile (Join-Path $ReportDir '08_conexoes_tcp_todas.csv') @($Data.Network | Where-Object Protocol -eq 'TCP')
    Export-H1SSCsvFile (Join-Path $ReportDir '09_conexoes_estabelecidas.csv') @($Data.Network | Where-Object { $_.Protocol -eq 'TCP' -and $_.State -eq 'Established' })
    Export-H1SSCsvFile (Join-Path $ReportDir '10_portas_tcp_em_escuta.csv') @($Data.Network | Where-Object { $_.Protocol -eq 'TCP' -and $_.State -eq 'Listen' })
    Export-H1SSCsvFile (Join-Path $ReportDir '10b_endpoints_udp.csv') @($Data.Network | Where-Object Protocol -eq 'UDP')
    Export-H1SSCsvFile (Join-Path $ReportDir '11_cache_dns.csv') @($Data.DNS)
    Export-H1SSCsvFile (Join-Path $ReportDir '12_tarefas_agendadas_ativas.csv') @($Data.ScheduledTasks | ForEach-Object { ConvertTo-H1SSFlatTask $_ })
    Export-H1SSCsvFile (Join-Path $ReportDir '13_registry_run_keys.csv') @($Data.RunKeys)
    Export-H1SSCsvFile (Join-Path $ReportDir '14_pastas_startup.csv') @($Data.Startup)
    Export-H1SSCsvFile (Join-Path $ReportDir '15_win32_startupcommand.csv') @($Data.StartupCommands)
    Export-H1SSCsvFile (Join-Path $ReportDir '16_alertas.csv') @($Findings | Where-Object Bucket -eq 'Alert' | ForEach-Object { ConvertTo-H1SSFlatFinding $_ })
    Export-H1SSCsvFile (Join-Path $ReportDir '17_hardening.csv') @($Findings | Where-Object Bucket -eq 'Hardening' | ForEach-Object { ConvertTo-H1SSFlatFinding $_ })
    Export-H1SSCsvFile (Join-Path $ReportDir '18_info.csv') @($Findings | Where-Object Bucket -eq 'Info' | ForEach-Object { ConvertTo-H1SSFlatFinding $_ })
    Export-H1SSCsvFile (Join-Path $ReportDir '19_arquivos_recentes_temp.csv') @($Data.RecentFiles)
}

function Get-H1SSOutputFileMetadata {
    param([string]$ReportDir)
    @(
        Get-ChildItem -LiteralPath $ReportDir -File -ErrorAction Stop |
            Where-Object { $_.Name -notin @('00_MANIFEST.json','00_MANIFEST.sha256') } |
            Sort-Object Name |
            ForEach-Object {
                [PSCustomObject]@{ File=$_.Name; SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash; Size=$_.Length }
            }
    )
}

function Write-H1SSManifest {
    param(
        [string]$ReportDir,
        [string]$RunId,
        [string]$OverallStatus,
        [object]$Preflight,
        [object[]]$CollectorStates,
        [object[]]$OutputFiles,
        [object[]]$SystemData,
        [DateTime]$StartedAtUtc,
        [DateTime]$FinishedAtUtc,
        [ValidateSet('Quick','Standard','Deep')][string]$CollectionMode,
        [System.Collections.IDictionary]$CollectionParameters
    )
    $system = @($SystemData | Select-Object -First 1)[0]
    $localStart = $StartedAtUtc.ToLocalTime(); $localFinish = $FinishedAtUtc.ToLocalTime()
    $manifest = [ordered]@{
        schemaVersion=$Script:SchemaVersion; toolName='H1SSTriage'; toolVersion=$Script:H1SSTriageVersion; ruleSetVersion=$Script:RuleSetVersion; runId=$RunId
        collectionMode=$CollectionMode; collectionParameters=$CollectionParameters
        hostname=if($system){$system.Hostname}else{$env:COMPUTERNAME}; fqdn=if($system){$system.Fqdn}else{$env:COMPUTERNAME}; domainOrWorkgroup=if($system){$system.DomainOrWorkgroup}else{$null}; machineGuid=if($system){$system.MachineGuid}else{$null}
        windowsEdition=if($system){$system.WindowsEdition}else{$null}; windowsVersion=if($system){$system.WindowsVersion}else{$null}; windowsBuild=if($system){$system.WindowsBuild}else{$null}; architecture=if($system){$system.Architecture}else{$null}
        powerShellVersion=$Preflight.PowerShellVersion; powerShellEdition=$Preflight.PowerShellEdition; powerShellBitness=$Preflight.PowerShellBitness
        collectorUser=$Preflight.CollectorUser; collectorUserSid=$Preflight.CollectorUserSid; isElevated=$Preflight.IsElevated; integrityLevel=$Preflight.IntegrityLevel
        startedAtUtc=ConvertTo-H1SSIsoUtc $StartedAtUtc; finishedAtUtc=ConvertTo-H1SSIsoUtc $FinishedAtUtc; startedAtLocal=ConvertTo-H1SSIsoLocal $localStart; finishedAtLocal=ConvertTo-H1SSIsoLocal $localFinish
        timezone=[TimeZoneInfo]::Local.Id; utcOffset=[TimeZoneInfo]::Local.GetUtcOffset($localFinish).ToString(); outputPath=$ReportDir
        toolScriptPath=$Preflight.ToolScriptPath; toolSha256=$Preflight.ToolSha256; overallStatus=$OverallStatus
        capabilities=@($Preflight.Capabilities); moduleImports=@($Preflight.ModuleImports); preflightErrors=@($Preflight.Errors); collectors=@($CollectorStates); outputFiles=@($OutputFiles)
    }
    $manifestPath = Join-Path $ReportDir '00_MANIFEST.json'
    Write-H1SSJsonFile -LiteralPath $manifestPath -Value ([PSCustomObject]$manifest) -Depth 12
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256 -ErrorAction Stop).Hash
    Set-Content -LiteralPath (Join-Path $ReportDir '00_MANIFEST.sha256') -Value ("{0}  00_MANIFEST.json" -f $manifestHash) -Encoding ASCII -ErrorAction Stop
}
