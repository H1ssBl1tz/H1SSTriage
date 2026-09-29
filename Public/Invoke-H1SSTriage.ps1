function Invoke-H1SSTriage {
    [CmdletBinding()]
    param(
        [string]$OutputPath = (Get-Location).Path,
        [ValidateSet('Quick','Standard','Deep')][string]$Mode = 'Standard',
        [ValidateRange(1,720)][int]$EventLogHours = 24,
        [ValidateRange(1,720)][int]$RecentFileHours = 24,
        [ValidateRange(1,10000)][int]$MaxRecentFiles = 200,
        [ValidateRange(1,3600)][int]$MaxScanDurationSeconds = 30,
        [string]$ToolScriptPath
    )

    $startedAtUtc = Get-H1SSUtcNow
    $basePath = Resolve-H1SSOutputBasePath -Path $OutputPath
    $run = New-H1SSRunDirectory -BasePath $basePath
    $reportDir = $run.Path
    $preflight = Get-H1SSPreflight -ToolScriptPath $ToolScriptPath -OutputPath $reportDir
    $states = New-Object System.Collections.Generic.List[object]
    $data = @{}
    $fileMetadataCache = New-H1SSFileMetadataCache

    function Add-CollectorResult {
        param([string]$Name,[object]$Result)
        $states.Add($Result.State) | Out-Null
        $data[$Name] = @($Result.Data)
        Write-Verbose ("{0}: {1} ({2} registros)" -f $Name,$Result.State.Status,$Result.State.RecordCount)
    }
    function Add-SkippedCollector {
        param([string]$Name,[bool]$Required=$false,[string]$Reason='Não selecionado pelo modo de coleta.')
        $now=Get-H1SSUtcNow; $states.Add((New-H1SSCollectorState -CollectorName $Name -Status Skipped -StartedAtUtc $now -FinishedAtUtc $now -Required $Required -ErrorType 'ModePolicy' -ErrorMessage $Reason)) | Out-Null; $data[$Name]=@()
    }

    if (-not $preflight.IsWindows -or -not $preflight.PowerShellSupported) {
        $now = Get-H1SSUtcNow
        foreach ($name in @('System','Users','Administrators','Processes','Services','Network','ScheduledTasks','RunKeys','Startup','DNS')) { $states.Add((New-H1SSCollectorState -CollectorName $name -Status Unsupported -StartedAtUtc $now -FinishedAtUtc $now -Required $true -ErrorType 'UnsupportedPlatform' -ErrorMessage 'Requer Windows e PowerShell 5.1 ou superior.')) | Out-Null; $data[$name]=@() }
    }
    else {
        Add-CollectorResult System (Invoke-H1SSCollector -Name System -Required $true -ScriptBlock { Get-H1SSSystemCollector })
        Add-CollectorResult Users (Invoke-H1SSCollector -Name Users -Required $true -ScriptBlock { Get-H1SSUsersCollector })
        Add-CollectorResult Administrators (Invoke-H1SSCollector -Name Administrators -Required $true -ScriptBlock { Get-H1SSAdministratorsCollector })
        Add-CollectorResult Processes (Invoke-H1SSCollector -Name Processes -Required $true -ScriptBlock { Get-H1SSProcessesCollector -Mode $Mode -MetadataCache $fileMetadataCache })
        Add-CollectorResult NetworkConfiguration (Invoke-H1SSCollector -Name NetworkConfiguration -Required $false -ScriptBlock { Get-H1SSNetworkConfigurationCollector })
        Add-CollectorResult Network (Invoke-H1SSCollector -Name Network -Required $true -ScriptBlock { Get-H1SSNetworkCollector -Processes @($data.Processes) })
        Add-CollectorResult Services (Invoke-H1SSCollector -Name Services -Required $true -ScriptBlock { Get-H1SSServicesCollector -Mode $Mode -MetadataCache $fileMetadataCache })
        Add-CollectorResult DNS (Invoke-H1SSCollector -Name DNS -Required $false -ScriptBlock { Get-H1SSDnsCollector })
        Add-CollectorResult ScheduledTasks (Invoke-H1SSCollector -Name ScheduledTasks -Required $true -ScriptBlock { Get-H1SSScheduledTasksCollector })
        Add-CollectorResult RunKeys (Invoke-H1SSCollector -Name RunKeys -Required $true -ScriptBlock { Get-H1SSRunKeysCollector })
        Add-CollectorResult Startup (Invoke-H1SSCollector -Name Startup -Required $true -ScriptBlock { Get-H1SSStartupCollector })
        Add-CollectorResult StartupCommands (Invoke-H1SSCollector -Name StartupCommands -Required $false -ScriptBlock { Get-H1SSStartupCommandsCollector })
        if ($Mode -in @('Standard','Deep')) {
            Add-CollectorResult AdvancedPersistence (Invoke-H1SSCollector -Name AdvancedPersistence -Required $false -ScriptBlock { Get-H1SSAdvancedPersistenceCollector })
            Add-CollectorResult Events (Invoke-H1SSCollector -Name Events -Required $false -ScriptBlock { Get-H1SSEventsCollector -EventLogHours $EventLogHours })
            Add-CollectorResult Defender (Invoke-H1SSCollector -Name Defender -Required $false -ScriptBlock { Get-H1SSDefenderCollector })
        }
        else { Add-SkippedCollector AdvancedPersistence; Add-SkippedCollector Events; Add-SkippedCollector Defender }
        if ($Mode -eq 'Deep') { Add-CollectorResult RecentFiles (Invoke-H1SSCollector -Name RecentFiles -Required $false -ScriptBlock { Get-H1SSRecentFilesCollector -RecentFileHours $RecentFileHours -MaxRecentFiles $MaxRecentFiles -MaxScanDurationSeconds $MaxScanDurationSeconds }) }
        else { Add-SkippedCollector RecentFiles }
    }

    foreach ($name in @('System','Users','Administrators','Processes','Services','NetworkConfiguration','Network','DNS','ScheduledTasks','RunKeys','Startup','StartupCommands','AdvancedPersistence','Events','Defender','RecentFiles')) { if (-not $data.ContainsKey($name)) { $data[$name]=@() } }
    $stateByName = @{}; foreach ($state in $states) { $stateByName[$state.CollectorName]=$state }
    $collectorStateArray = $states.ToArray()
    $detectionEnrichmentErrors = @(Add-H1SSDetectionEnrichment -Data $data -MetadataCache $fileMetadataCache)
    foreach ($group in @($detectionEnrichmentErrors | Group-Object CollectorName)) {
        if ($stateByName.ContainsKey($group.Name)) {
            $errorTypes = @($group.Group | ForEach-Object ErrorType | Select-Object -Unique) -join ','
            $errorMessages = @($group.Group | ForEach-Object ErrorMessage | Select-Object -Unique) -join ' | '
            Set-H1SSCollectorPartial -State $stateByName[$group.Name] -ErrorType $errorTypes -ErrorMessage $errorMessages
        }
    }
    $collectorStateArray = $states.ToArray()
    $findings = @(Invoke-H1SSRules -Data $data -StateByName $stateByName)
    $enrichmentErrors = @(Add-H1SSSelectiveFileHashes -Findings $findings -Data $data -Mode $Mode -MetadataCache $fileMetadataCache)
    foreach ($group in @($enrichmentErrors | Group-Object CollectorName)) {
        if ($stateByName.ContainsKey($group.Name)) {
            $errorTypes = @($group.Group | ForEach-Object ErrorType | Select-Object -Unique) -join ','
            $errorMessages = @($group.Group | ForEach-Object ErrorMessage | Select-Object -Unique) -join ' | '
            Set-H1SSCollectorPartial -State $stateByName[$group.Name] -ErrorType $errorTypes -ErrorMessage $errorMessages
        }
    }
    $collectorStateArray = $states.ToArray()
    $overallStatus = Get-H1SSOverallStatus -CollectorStates $collectorStateArray
    foreach ($finding in $findings) {
        if ($stateByName.ContainsKey([string]$finding.Collector)) { $finding.CollectorStatus = $stateByName[[string]$finding.Collector].Status }
    }

    if (@($findings | Where-Object Bucket -eq 'Alert').Count -eq 0) {
        $findings += New-H1SSFinding -RuleId 'STATUS.NO_RULE_MATCH.001' -Severity Informational -Confidence High -EvidenceStrength Contextual -Collector Collection -CollectorStatus $overallStatus -EntityType Collection -EntityId $run.RunId -Signals @('STATUS.NO_RULE_MATCH') -Why 'Nenhuma regra de detecção foi acionada nas fontes coletadas com sucesso. O manifesto deve ser consultado para cobertura e falhas.' -Recommendation 'Continuar revisão manual e validar 00_MANIFEST.json.' -ValidationSteps @('Revisar coletores Failed/Partial/Unavailable/Unsupported.','Revisar dados brutos e contexto do ambiente.') -SourceFiles @('00_MANIFEST.json') -Score 1 -Bucket Info
    }
    if ($overallStatus -ne 'Complete') {
        $findings += New-H1SSFinding -RuleId 'STATUS.COLLECTION_INCOMPLETE.001' -Severity Informational -Confidence High -EvidenceStrength Confirmed -Collector Collection -CollectorStatus $overallStatus -EntityType Collection -EntityId $run.RunId -Signals @('STATUS.COLLECTION_INCOMPLETE') -Why 'Um ou mais coletores obrigatórios não terminaram com Success.' -Recommendation 'Não interpretar ausência de findings como ausência de comprometimento.' -ValidationSteps @('Abrir 00_MANIFEST.json.','Corrigir pré-requisitos/permissões e repetir somente se operacionalmente apropriado.') -SourceFiles @('00_MANIFEST.json') -Score 1 -Bucket Info
    }

    $finishedAtUtc = Get-H1SSUtcNow
    Export-H1SSReports -ReportDir $reportDir -Data $data -Findings $findings -OverallStatus $overallStatus -RunId $run.RunId -Preflight $preflight -CollectorStates $collectorStateArray -StartedAtUtc $startedAtUtc -FinishedAtUtc $finishedAtUtc
    $outputFiles = Get-H1SSOutputFileMetadata -ReportDir $reportDir
    $collectionParameters = [ordered]@{
        eventLogHours = $EventLogHours
        recentFileHours = $RecentFileHours
        maxRecentFiles = $MaxRecentFiles
        maxScanDurationSeconds = $MaxScanDurationSeconds
    }
    Write-H1SSManifest -ReportDir $reportDir -RunId $run.RunId -OverallStatus $overallStatus -Preflight $preflight -CollectorStates $collectorStateArray -OutputFiles $outputFiles -SystemData @($data.System) -StartedAtUtc $startedAtUtc -FinishedAtUtc $finishedAtUtc -CollectionMode $Mode -CollectionParameters $collectionParameters
    $reportDir
}
