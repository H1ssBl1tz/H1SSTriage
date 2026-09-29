function New-H1SSFinding {
    param(
        [Parameter(Mandatory = $true)][string]$RuleId,
        [string]$RuleVersion = '1.0',
        [Parameter(Mandatory = $true)][ValidateSet('Critical','High','Medium','Low','Informational')][string]$Severity,
        [Parameter(Mandatory = $true)][ValidateSet('High','Medium','Low')][string]$Confidence,
        [Parameter(Mandatory = $true)][ValidateSet('Confirmed','Strong','Heuristic','Contextual')][string]$EvidenceStrength,
        [Parameter(Mandatory = $true)][string]$Collector,
        [Parameter(Mandatory = $true)][string]$CollectorStatus,
        [Parameter(Mandatory = $true)][string]$EntityType,
        [Parameter(Mandatory = $true)][string]$EntityId,
        [Parameter(Mandatory = $true)][string[]]$Signals,
        [Parameter(Mandatory = $true)][string]$Why,
        [Parameter(Mandatory = $true)][string]$Recommendation,
        [Parameter(Mandatory = $true)][string[]]$ValidationSteps,
        [string[]]$SourceRecordIds = @(),
        [string[]]$SourceFiles = @(),
        [int]$Score = 0,
        [ValidateSet('Alert','Hardening','Info')][string]$Bucket = 'Alert'
    )
    [PSCustomObject]@{
        FindingId        = 'H1SSF-{0}' -f ([guid]::NewGuid().ToString('N').Substring(0,12).ToUpperInvariant())
        RuleId           = $RuleId
        RuleVersion      = $RuleVersion
        Severity         = $Severity
        Confidence       = $Confidence
        EvidenceStrength = $EvidenceStrength
        ObservedAtUtc    = ConvertTo-H1SSIsoUtc -Value (Get-H1SSUtcNow)
        Collector        = $Collector
        CollectorStatus  = $CollectorStatus
        EntityType       = $EntityType
        EntityId         = $EntityId
        Score            = @($Signals).Count
        Signals          = @($Signals)
        Why              = $Why
        Recommendation   = $Recommendation
        ValidationSteps  = @($ValidationSteps)
        SourceRecordIds  = @($SourceRecordIds)
        SourceFiles      = @($SourceFiles)
        Bucket           = $Bucket
    }
}

function Get-H1SSTrustAssessment {
    param(
        [string]$Path,
        [string]$SignatureStatus,
        [Nullable[bool]]$PathExpected,
        [Nullable[bool]]$PublisherExpected,
        [Nullable[bool]]$OriginalFileNameExpected,
        [Nullable[bool]]$CompanyExpected,
        [Nullable[bool]]$HashKnown
    )

    if ($null -eq $PathExpected) {
        $PathExpected = [Nullable[bool]]([bool]($Path -match '(?i)^[A-Z]:\\(Windows|Program Files(?: \(x86\))?)\\'))
    }
    $signatureValid = ($SignatureStatus -eq 'Valid')
    $signals = New-Object System.Collections.Generic.List[string]
    if ($PathExpected -eq $true) { $signals.Add('TRUST.PATH_EXPECTED') | Out-Null }
    elseif ($PathExpected -eq $false -and $Path) { $signals.Add('TRUST.PATH_UNEXPECTED') | Out-Null }
    if ($signatureValid) { $signals.Add('TRUST.SIGNATURE_VALID') | Out-Null }
    elseif ($SignatureStatus -eq 'NotSigned') { $signals.Add('TRUST.SIGNATURE_NOT_SIGNED') | Out-Null }
    elseif ($SignatureStatus -in @('HashMismatch','NotTrusted','UnknownError','Error')) { $signals.Add('TRUST.SIGNATURE_INVALID') | Out-Null }
    if ($PublisherExpected -eq $true) { $signals.Add('TRUST.PUBLISHER_EXPECTED') | Out-Null }
    elseif ($PublisherExpected -eq $false) { $signals.Add('TRUST.PUBLISHER_UNEXPECTED') | Out-Null }
    if ($OriginalFileNameExpected -eq $true) { $signals.Add('TRUST.ORIGINAL_FILENAME_EXPECTED') | Out-Null }
    elseif ($OriginalFileNameExpected -eq $false) { $signals.Add('TRUST.ORIGINAL_FILENAME_UNEXPECTED') | Out-Null }
    if ($CompanyExpected -eq $true) { $signals.Add('TRUST.COMPANY_EXPECTED') | Out-Null }
    elseif ($CompanyExpected -eq $false) { $signals.Add('TRUST.COMPANY_UNEXPECTED') | Out-Null }
    if ($HashKnown -eq $true) { $signals.Add('TRUST.HASH_KNOWN') | Out-Null }

    $explicitMismatch = ($PublisherExpected -eq $false -or $OriginalFileNameExpected -eq $false -or $CompanyExpected -eq $false)
    $allStrongAttributes = ($PathExpected -eq $true -and $signatureValid -and $PublisherExpected -eq $true -and $OriginalFileNameExpected -eq $true -and $CompanyExpected -eq $true -and $HashKnown -eq $true)
    $level = 'Unknown'
    $reason = 'Os atributos disponíveis não estabelecem confiança suficiente.'
    if ($allStrongAttributes) {
        $level = 'Trusted'
        $reason = 'Path, publisher, assinatura, nome original, company e hash correspondem às expectativas explícitas.'
    }
    elseif ($PathExpected -eq $true -and $signatureValid -and -not $explicitMismatch) {
        $level = 'LikelyTrusted'
        $reason = 'Path protegido e assinatura válida reduzem prioridade, mas publisher/hash/baseline completos não foram confirmados.'
    }
    elseif ($explicitMismatch -or ((Test-H1SSUserWritablePath -Path $Path) -and $SignatureStatus -in @('NotSigned','HashMismatch','NotTrusted','UnknownError','Error'))) {
        $level = 'Suspicious'
        $reason = 'Atributos explícitos divergiram ou um path gravável foi combinado com assinatura ausente/inválida.'
    }

    [PSCustomObject]@{
        TrustLevel = $level
        TrustReason = $reason
        PathExpected = $PathExpected
        PublisherExpected = $PublisherExpected
        SignatureValid = $signatureValid
        OriginalFileNameExpected = $OriginalFileNameExpected
        CompanyExpected = $CompanyExpected
        HashKnown = $HashKnown
        TrustSignals = $signals.ToArray()
    }
}

function Resolve-H1SSSignalDecision {
    param(
        [Parameter(Mandatory=$true)][ValidateSet('Process','Service','Task','Persistence')][string]$Family,
        [Parameter(Mandatory=$true)][string[]]$Signals,
        [ValidateSet('Trusted','LikelyTrusted','Unknown','Suspicious')][string]$TrustLevel = 'Unknown'
    )

    $severity = 'Low'; $confidence = 'Low'; $strength = 'Contextual'
    switch ($Family) {
        'Process' {
            $signatureConcern = ($Signals -contains 'PROC.UNSIGNED' -or $Signals -contains 'PROC.INVALID_SIGNATURE')
            $writable = $Signals -contains 'PROC.USER_WRITABLE_PATH'
            $external = $Signals -contains 'PROC.EXTERNAL_CONNECTION'
            $persistence = $Signals -contains 'PROC.PERSISTENCE_REFERENCE'
            $command = $Signals -contains 'PROC.SUSPICIOUS_COMMAND_LINE'
            $parent = $Signals -contains 'PROC.SUSPICIOUS_PARENT'
            if ($writable -and $signatureConcern -and $external -and $persistence -and ($command -or $parent)) { $severity='Critical'; $confidence='High'; $strength='Strong' }
            elseif (($writable -and $signatureConcern -and ($external -or $persistence -or $command -or $parent)) -or ($command -and $parent -and $external)) { $severity='High'; $confidence='Medium'; $strength='Strong' }
            elseif (($writable -and $Signals -contains 'PROC.HIGH_RISK_LOCATION') -or ($command -and ($writable -or $parent)) -or ($external -and ($writable -or $signatureConcern)) -or ($persistence -and ($writable -or $signatureConcern))) { $severity='Medium'; $confidence='Medium'; $strength='Heuristic' }
            else { $severity='Low'; $confidence='Low'; $strength='Contextual' }
        }
        'Service' {
            $writable = ($Signals -contains 'SVC.USER_WRITABLE_PATH' -or $Signals -contains 'SVC.USER_WRITABLE_SERVICE_DLL' -or $Signals -contains 'SVC.WRITABLE_BY_COLLECTOR')
            $signatureConcern = ($Signals -contains 'SVC.UNSIGNED' -or $Signals -contains 'SVC.INVALID_SIGNATURE')
            if ($writable -and $signatureConcern -and $Signals.Count -ge 3) { $severity='High'; $confidence='Medium'; $strength='Strong' }
            elseif ($writable -and ($signatureConcern -or $Signals -contains 'SVC.MISSING_BINARY')) { $severity='Medium'; $confidence='Medium'; $strength='Heuristic' }
            else { $severity='Low'; $confidence='Low'; $strength='Contextual' }
        }
        'Task' {
            $arguments = $Signals -contains 'TASK.SUSPICIOUS_ARGUMENTS'
            $writable = $Signals -contains 'TASK.USER_WRITABLE_PATH'
            $executionContext = ($Signals -contains 'TASK.HIDDEN' -or $Signals -contains 'TASK.HIGHEST_RUNLEVEL' -or $Signals -contains 'TASK.NAMESPACE_MASQUERADE')
            if ($arguments -and $writable -and $executionContext) { $severity='High'; $confidence='Medium'; $strength='Strong' }
            elseif (($arguments -and ($writable -or $executionContext)) -or ($writable -and $executionContext)) { $severity='Medium'; $confidence='Medium'; $strength='Heuristic' }
            else { $severity='Low'; $confidence='Low'; $strength='Contextual' }
        }
        'Persistence' {
            if (($Signals -contains 'PERSIST.SUSPICIOUS_COMMAND') -and ($Signals -contains 'PERSIST.USER_WRITABLE_PATH')) { $severity='High'; $confidence='Medium'; $strength='Strong' }
            elseif ($Signals -contains 'PERSIST.SUSPICIOUS_COMMAND') { $severity='Medium'; $confidence='Medium'; $strength='Heuristic' }
            else { $severity='Low'; $confidence='Low'; $strength='Contextual' }
        }
    }

    if ($TrustLevel -in @('Trusted','LikelyTrusted')) {
        $severity = switch ($severity) { 'Critical' {'High'}; 'High' {'Medium'}; 'Medium' {'Low'}; 'Low' {'Informational'}; default {$severity} }
        $confidence = 'Low'
        if ($strength -eq 'Strong') { $strength = 'Heuristic' }
    }
    [PSCustomObject]@{ Severity=$severity; Confidence=$confidence; EvidenceStrength=$strength; SignalCount=$Signals.Count }
}

function Test-H1SSSuspiciousCommandLine {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $false }
    $CommandLine -match '(?i)(?:^|\s)-(?:e|en|enc|enco|encodedcommand)(?:\s|:)|downloadstring|invoke-expression|\biex\b|frombase64string|windowstyle\s+hidden|-w\s+hidden|invoke-webrequest|\biwr\b|bitsadmin|certutil\s+.*-decode|regsvr32\s+.*\/i:|mshta\s+(?:https?|javascript):'
}

function Test-H1SSObjectContainsString {
    param([object]$InputObject, [string]$Value, [int]$Depth = 0)
    if ($null -eq $InputObject -or [string]::IsNullOrWhiteSpace($Value) -or $Depth -gt 6) { return $false }
    if ($InputObject -is [string]) { return $InputObject.IndexOf($Value, [StringComparison]::OrdinalIgnoreCase) -ge 0 }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($entryValue in $InputObject.Values) { if (Test-H1SSObjectContainsString -InputObject $entryValue -Value $Value -Depth ($Depth + 1)) { return $true } }
        return $false
    }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        foreach ($item in $InputObject) { if (Test-H1SSObjectContainsString -InputObject $item -Value $Value -Depth ($Depth + 1)) { return $true } }
        return $false
    }
    foreach ($property in $InputObject.PSObject.Properties) {
        if ($property.Name -like 'PS*') { continue }
        if (Test-H1SSObjectContainsString -InputObject $property.Value -Value $Value -Depth ($Depth + 1)) { return $true }
    }
    $false
}

function Invoke-H1SSProcessRules {
    param([object[]]$Processes, [object[]]$Network, [object[]]$PersistenceReferences, [string]$CollectorStatus)
    $findings = New-Object System.Collections.Generic.List[object]
    $networkByProcess = @{}
    foreach ($connection in $Network | Where-Object { $_.Protocol -eq 'TCP' -and $_.State -eq 'Established' -and $_.RemoteClassification -eq 'Public' -and $_.ProcessRecordId }) {
        $networkByProcess[$connection.ProcessRecordId] = $true
    }
    foreach ($process in $Processes) {
        $signals = New-Object System.Collections.Generic.List[string]
        if (Test-H1SSUserWritablePath -Path $process.ExecutablePath) { $signals.Add('PROC.USER_WRITABLE_PATH') | Out-Null }
        if ($process.ExecutablePath -match '(?i)\\(Temp|Users\\Public|\$Recycle\.Bin|PerfLogs)\\') { $signals.Add('PROC.HIGH_RISK_LOCATION') | Out-Null }
        if (Test-H1SSSuspiciousCommandLine -CommandLine $process.CommandLine) { $signals.Add('PROC.SUSPICIOUS_COMMAND_LINE') | Out-Null }
        if ($process.SignatureStatus -eq 'NotSigned') { $signals.Add('PROC.UNSIGNED') | Out-Null }
        elseif ($process.SignatureStatus -in @('HashMismatch','NotTrusted','UnknownError','Error')) { $signals.Add('PROC.INVALID_SIGNATURE') | Out-Null }
        if ($process.FileLastWriteTimeUtc -and $process.ObservedAtUtc) {
            $lastWrite = [DateTime]::MinValue; $observedAt = [DateTime]::MinValue
            if ([DateTime]::TryParse([string]$process.FileLastWriteTimeUtc, [ref]$lastWrite) -and [DateTime]::TryParse([string]$process.ObservedAtUtc, [ref]$observedAt) -and $lastWrite.ToUniversalTime() -gt $observedAt.ToUniversalTime().AddHours(-48)) { $signals.Add('PROC.RECENT_FILE') | Out-Null }
        }
        if ($process.ParentName -match '(?i)^(winword|excel|powerpnt|outlook|mshta|wscript|cscript)\.exe$' -and $process.Name -match '(?i)^(powershell|pwsh|cmd|rundll32|regsvr32|mshta)\.exe$') { $signals.Add('PROC.SUSPICIOUS_PARENT') | Out-Null }
        if ($networkByProcess.ContainsKey($process.RecordId)) { $signals.Add('PROC.EXTERNAL_CONNECTION') | Out-Null }
        if ($process.ExecutablePath -and (Test-H1SSObjectContainsString -InputObject $PersistenceReferences -Value $process.ExecutablePath)) { $signals.Add('PROC.PERSISTENCE_REFERENCE') | Out-Null }
        if ($signals.Count -eq 0) { continue }
        $signalArray = $signals.ToArray()
        $trustLevel = if ($process.PSObject.Properties.Name -contains 'TrustLevel' -and $process.TrustLevel) { [string]$process.TrustLevel } else { (Get-H1SSTrustAssessment -Path $process.ExecutablePath -SignatureStatus $process.SignatureStatus).TrustLevel }
        $decision = Resolve-H1SSSignalDecision -Family Process -Signals $signalArray -TrustLevel $trustLevel
        $why = "Processo $($process.Name) (PID $($process.PID)) apresentou a combinação observável: $($signalArray -join ', '). Trust=$trustLevel. Esses sinais exigem investigação e não confirmam comprometimento."
        $findings.Add((New-H1SSFinding -RuleId 'PROC.MULTI_SIGNAL.001' -RuleVersion '2.0' -Severity $decision.Severity -Confidence $decision.Confidence -EvidenceStrength $decision.EvidenceStrength -Collector Processes -CollectorStatus $CollectorStatus -EntityType Process -EntityId $process.RecordId -Signals $signalArray -Why $why -Recommendation 'Preservar o artefato e validar assinatura, hash, parent, usuário, persistência e conexões antes de qualquer contenção.' -ValidationSteps @('Confirmar path, assinatura, publisher e hash em fonte confiável.','Revisar parent/child e command line.','Correlacionar a mesma identidade de processo com rede, persistência e eventos.') -SourceRecordIds @($process.RecordId) -SourceFiles @('02_processos_completos.csv','processes.json') -Score $decision.SignalCount)) | Out-Null
    }
    $findings.ToArray()
}

function Invoke-H1SSServiceRules {
    param([object[]]$Services, [string]$CollectorStatus)
    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($service in $Services) {
        if ($service.UnquotedServicePath) {
            $findings.Add((New-H1SSFinding -RuleId 'SVC.UNQUOTED_PATH.001' -Severity Low -Confidence High -EvidenceStrength Contextual -Collector Services -CollectorStatus $CollectorStatus -EntityType Service -EntityId $service.RecordId -Signals @('SVC.UNQUOTED_PATH') -Why 'O serviço possui caminho com espaços sem aspas. Isso é uma misconfiguration de privilege escalation, não evidência de malware.' -Recommendation 'Validar permissões dos diretórios intermediários e corrigir o ImagePath em change control.' -ValidationSteps @('Inspecionar ACLs de cada segmento do caminho.','Confirmar parsing do executável.','Não classificar como malware sem outros sinais.') -SourceRecordIds @($service.RecordId) -SourceFiles @('05_servicos.csv','services.json') -Score 1 -Bucket Hardening)) | Out-Null
        }
        $signals = New-Object System.Collections.Generic.List[string]
        if (-not $service.FileExists -and $service.ExecutablePath) { $signals.Add('SVC.MISSING_BINARY') | Out-Null }
        if (Test-H1SSUserWritablePath $service.ExecutablePath) { $signals.Add('SVC.USER_WRITABLE_PATH') | Out-Null }
        if ($service.WritableExecutable -eq $true -or $service.WritableDirectory -eq $true) { $signals.Add('SVC.WRITABLE_BY_COLLECTOR') | Out-Null }
        if ($service.SignatureStatus -eq 'NotSigned') { $signals.Add('SVC.UNSIGNED') | Out-Null }
        elseif ($service.SignatureStatus -in @('HashMismatch','NotTrusted','UnknownError','Error')) { $signals.Add('SVC.INVALID_SIGNATURE') | Out-Null }
        if ($service.ServiceDll -and (Test-H1SSUserWritablePath $service.ServiceDll)) { $signals.Add('SVC.USER_WRITABLE_SERVICE_DLL') | Out-Null }
        if ($signals.Count -eq 0) { continue }
        $signalArray = $signals.ToArray()
        $trust = Get-H1SSTrustAssessment -Path $service.ExecutablePath -SignatureStatus $service.SignatureStatus
        $decision = Resolve-H1SSSignalDecision -Family Service -Signals $signalArray -TrustLevel $trust.TrustLevel
        $findings.Add((New-H1SSFinding -RuleId 'SVC.MULTI_SIGNAL.001' -RuleVersion '2.0' -Severity $decision.Severity -Confidence $decision.Confidence -EvidenceStrength $decision.EvidenceStrength -Collector Services -CollectorStatus $CollectorStatus -EntityType Service -EntityId $service.RecordId -Signals $signalArray -Why ("Serviço {0} apresentou sinais verificáveis: {1}. Trust={2}; a combinação requer validação e não estabelece intenção maliciosa." -f $service.Name,($signalArray -join ', '),$trust.TrustLevel) -Recommendation 'Validar ImagePath/ServiceDll, assinatura, ACL, hash e eventos de criação antes de alterar o serviço.' -ValidationSteps @('Comparar configuração com baseline.','Validar binário, publisher e ServiceDll.','Consultar eventos 4697/7045.') -SourceRecordIds @($service.RecordId) -SourceFiles @('05_servicos.csv','services.json') -Score $decision.SignalCount)) | Out-Null
    }
    $findings.ToArray()
}

function Get-H1SSTaskTrustAssessment {
    param([object]$Task)
    $levels = New-Object System.Collections.Generic.List[string]
    $assessmentStatus = if ($Task.PSObject.Properties.Name -contains 'DetectionEnrichmentStatus') { [string]$Task.DetectionEnrichmentStatus } elseif (@($Task.ActionFileMetadata).Count) { 'Success' } else { 'NotRun' }
    foreach ($item in @($Task.ActionFileMetadata)) {
        if (-not $item -or -not $item.Metadata) { continue }
        $metadata = $item.Metadata
        $arguments = @{ Path=[string]$item.ResolvedPath; SignatureStatus=[string]$metadata.SignatureStatus }
        foreach ($name in @('PathExpected','PublisherExpected','OriginalFileNameExpected','CompanyExpected','HashKnown')) {
            if ($metadata.PSObject.Properties.Name -contains $name -and $null -ne $metadata.$name) { $arguments[$name] = [bool]$metadata.$name }
        }
        $assessment = Get-H1SSTrustAssessment @arguments
        $levels.Add($assessment.TrustLevel) | Out-Null
    }
    if ($levels.Count -eq 0) { return [PSCustomObject]@{ TrustLevel='Unknown'; TrustReason='Metadata de actions não disponível para estabelecer trust.'; AssessmentStatus=$assessmentStatus } }
    if ($levels -contains 'Suspicious') { return [PSCustomObject]@{ TrustLevel='Suspicious'; TrustReason='Ao menos uma action possui atributos divergentes ou combinação path/assinatura preocupante.'; AssessmentStatus=$assessmentStatus } }
    if (@($levels | Where-Object { $_ -ne 'Trusted' }).Count -eq 0) { return [PSCustomObject]@{ TrustLevel='Trusted'; TrustReason='Todas as actions avaliadas correspondem a expectativas explícitas fortes.'; AssessmentStatus=$assessmentStatus } }
    if (@($levels | Where-Object { $_ -notin @('Trusted','LikelyTrusted') }).Count -eq 0) { return [PSCustomObject]@{ TrustLevel='LikelyTrusted'; TrustReason='Actions avaliadas têm path esperado e assinatura válida, sem baseline completo.'; AssessmentStatus=$assessmentStatus } }
    [PSCustomObject]@{ TrustLevel='Unknown'; TrustReason='Os atributos disponíveis das actions são inconclusivos.'; AssessmentStatus=$assessmentStatus }
}

function Invoke-H1SSTaskRules {
    param([object[]]$Tasks, [string]$CollectorStatus)
    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($task in $Tasks) {
        $actions = @($task.Actions)
        $triggers = @($task.Triggers)
        $text = (@($actions | ForEach-Object { "$($_.Execute) $($_.Arguments) $($_.WorkingDirectory)" }) -join ' ')
        $signals = New-Object System.Collections.Generic.List[string]
        if ($text -match '(?i)\b(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)(?:\.exe)?\b') { $signals.Add('TASK.INTERPRETER_OR_LOLBIN') | Out-Null }
        if (Test-H1SSSuspiciousCommandLine $text) { $signals.Add('TASK.SUSPICIOUS_ARGUMENTS') | Out-Null }
        if (Test-H1SSUserWritablePath $text) { $signals.Add('TASK.USER_WRITABLE_PATH') | Out-Null }
        if ($task.Hidden) { $signals.Add('TASK.HIDDEN') | Out-Null }
        if ($task.PrincipalRunLevel -eq 'Highest') { $signals.Add('TASK.HIGHEST_RUNLEVEL') | Out-Null }
        $microsoftNamespace = ($task.TaskPath -like '\Microsoft\Windows\*')
        if ($microsoftNamespace) { $signals.Add('TASK.MICROSOFT_NAMESPACE_CONTEXT') | Out-Null }
        if ($microsoftNamespace -and (($signals -contains 'TASK.USER_WRITABLE_PATH') -or ($signals -contains 'TASK.SUSPICIOUS_ARGUMENTS'))) { $signals.Add('TASK.NAMESPACE_MASQUERADE') | Out-Null }
        if (($task.PSObject.Properties.Name -contains 'Enabled' -and $task.Enabled -eq $false) -or $task.State -eq 'Disabled') { $signals.Add('TASK.DISABLED') | Out-Null }
        if ($actions.Count -gt 1) { $signals.Add('TASK.MULTIPLE_ACTIONS') | Out-Null }
        if ($triggers.Count -gt 1) { $signals.Add('TASK.MULTIPLE_TRIGGERS') | Out-Null }
        $investigativeSignals = @($signals | Where-Object { $_ -in @('TASK.SUSPICIOUS_ARGUMENTS','TASK.USER_WRITABLE_PATH','TASK.HIDDEN','TASK.NAMESPACE_MASQUERADE') })
        if ($investigativeSignals.Count -eq 0) { continue }
        $signalArray = $signals.ToArray()
        $trust = Get-H1SSTaskTrustAssessment -Task $task
        $decision = Resolve-H1SSSignalDecision -Family Task -Signals $signalArray -TrustLevel $trust.TrustLevel
        $findings.Add((New-H1SSFinding -RuleId 'TASK.MULTI_SIGNAL.001' -RuleVersion '2.0' -Severity $decision.Severity -Confidence $decision.Confidence -EvidenceStrength $decision.EvidenceStrength -Collector ScheduledTasks -CollectorStatus $CollectorStatus -EntityType ScheduledTask -EntityId $task.RecordId -Signals $signalArray -Why ("Tarefa {0}{1} apresentou: {2}. Trust das actions={3}; metadata={4}. O namespace Microsoft é somente contexto e não prova legitimidade." -f $task.TaskPath,$task.TaskName,($signalArray -join ', '),$trust.TrustLevel,$trust.AssessmentStatus) -Recommendation 'Revisar XML, autor, principal, todas as actions/triggers, assinatura e baseline antes de alterar a tarefa.' -ValidationSteps @('Comparar XML com baseline do mesmo Windows.','Validar todos os executáveis/scripts e argumentos referenciados.','Correlacionar TaskScheduler/Security logs e confirmar o estado Enabled/Disabled.') -SourceRecordIds @($task.RecordId) -SourceFiles @('12_tarefas_agendadas_ativas.csv','scheduled_tasks.json') -Score $decision.SignalCount)) | Out-Null
    }
    $findings.ToArray()
}

function Invoke-H1SSPersistenceRules {
    param([object[]]$RunKeys, [object[]]$Startup, [object[]]$Advanced, [string]$CollectorStatus)
    $findings = New-Object System.Collections.Generic.List[object]
    foreach ($entry in $RunKeys) {
        $signals = New-Object System.Collections.Generic.List[string]
        if (Test-H1SSUserWritablePath $entry.Value) { $signals.Add('PERSIST.USER_WRITABLE_PATH') | Out-Null }
        if (Test-H1SSSuspiciousCommandLine $entry.Value) { $signals.Add('PERSIST.SUSPICIOUS_COMMAND') | Out-Null }
        if ($entry.Value -match '(?i)\b(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)(?:\.exe)?\b') { $signals.Add('PERSIST.INTERPRETER_OR_LOLBIN') | Out-Null }
        if ($signals.Count -eq 0) { continue }
        $signalArray = $signals.ToArray()
        $decision = Resolve-H1SSSignalDecision -Family Persistence -Signals $signalArray
        $findings.Add((New-H1SSFinding -RuleId 'PERSIST.RUNKEY.001' -RuleVersion '2.0' -Severity $decision.Severity -Confidence $decision.Confidence -EvidenceStrength $decision.EvidenceStrength -Collector RunKeys -CollectorStatus $CollectorStatus -EntityType RegistryRunKey -EntityId $entry.RecordId -Signals $signalArray -Why ("Entrada {0} em {1} apresentou: {2}. É uma hipótese de persistência que requer validação." -f $entry.Name,$entry.RegistryPath,($signalArray -join ', ')) -Recommendation 'Preservar/exportar a chave e validar o alvo sem executá-lo.' -ValidationSteps @('Resolver executável e todos os argumentos.','Validar assinatura, publisher e hash.','Correlacionar com usuário, processo e eventos.') -SourceRecordIds @($entry.RecordId) -SourceFiles @('13_registry_run_keys.csv','persistence.json') -Score $decision.SignalCount)) | Out-Null
    }
    foreach ($item in $Advanced) {
        if ($item.Type -in @('IFEO','SilentProcessExit','WMISubscription')) {
            $findings.Add((New-H1SSFinding -RuleId ('PERSIST.{0}.001' -f $item.Type.ToUpperInvariant()) -Severity Medium -Confidence Medium -EvidenceStrength Heuristic -Collector AdvancedPersistence -CollectorStatus $CollectorStatus -EntityType $item.Type -EntityId $item.RecordId -Signals @("PERSIST.$($item.Type.ToUpperInvariant())") -Why "Foi encontrada configuração de persistência/execução em $($item.Type). A presença requer contexto e não confirma malícia." -Recommendation 'Preservar configuração e validar alvo, assinatura, autoria e eventos sem executar conteúdo.' -ValidationSteps @('Comparar com baseline.','Validar artefatos referenciados.','Correlacionar com eventos históricos.') -SourceRecordIds @($item.RecordId) -SourceFiles @('persistence.json') -Score 1)) | Out-Null
        }
    }
    foreach ($item in $Startup) {
        $text = "$($item.FullName) $($item.TargetPath) $($item.Arguments)"
        if ((Test-H1SSSuspiciousCommandLine $text) -or (Test-H1SSUserWritablePath $item.TargetPath)) {
            $findings.Add((New-H1SSFinding -RuleId 'PERSIST.STARTUP.001' -Severity Low -Confidence Low -EvidenceStrength Contextual -Collector Startup -CollectorStatus $CollectorStatus -EntityType StartupItem -EntityId $item.RecordId -Signals @('PERSIST.STARTUP_REVIEW') -Why 'Item de Startup referencia comando/caminho que merece revisão.' -Recommendation 'Validar LNK/target, assinatura, hash e usuário relacionado.' -ValidationSteps @('Inspecionar target e argumentos sem executar.','Comparar com baseline.') -SourceRecordIds @($item.RecordId) -SourceFiles @('14_pastas_startup.csv','persistence.json') -Score 1)) | Out-Null
        }
    }
    $findings.ToArray()
}

function Invoke-H1SSNetworkRules {
    param([object[]]$Network, [string]$CollectorStatus)
    $findings = New-Object System.Collections.Generic.List[object]
    $adminPorts = @(135,445,3389,5985,5986)
    foreach ($connection in $Network | Where-Object { $_.Protocol -eq 'TCP' }) {
        if ($connection.State -eq 'Established' -and $connection.RemoteClassification -eq 'Private' -and $adminPorts -contains [int]$connection.RemotePort) {
            $findings.Add((New-H1SSFinding -RuleId 'NET.INTERNAL_ADMIN_CONNECTION.001' -RuleVersion '2.1' -Severity Informational -Confidence High -EvidenceStrength Contextual -Collector Network -CollectorStatus $CollectorStatus -EntityType NetworkConnection -EntityId $connection.RecordId -Signals @('NET.INTERNAL_ADMIN_CONNECTION') -Why ("Foi observada conexão em endereço privado para a porta administrativa {0}. SMB/RDP/WinRM/RPC podem ser legítimos e a porta, isoladamente, não determina intenção." -f $connection.RemotePort) -Recommendation 'Validar se processo, conta, origem e destino correspondem à administração esperada.' -ValidationSteps @('Confirmar processo e usuário.','Correlacionar com logons e ferramenta de gestão.','Comparar origem/destino com baseline administrativo.') -SourceRecordIds @($connection.RecordId) -SourceFiles @('08_conexoes_tcp_todas.csv','network.json') -Score 1 -Bucket Info)) | Out-Null
        }
        if ($connection.State -eq 'Listen' -and $connection.LocalAddress -in @('0.0.0.0','::') -and (Test-H1SSUserWritablePath $connection.ProcessPath)) {
            $findings.Add((New-H1SSFinding -RuleId 'NET.USER_WRITABLE_LISTENER.001' -RuleVersion '2.0' -Severity Medium -Confidence Medium -EvidenceStrength Heuristic -Collector Network -CollectorStatus $CollectorStatus -EntityType NetworkListener -EntityId $connection.RecordId -Signals @('NET.LISTENING_SOCKET','PROC.USER_WRITABLE_PATH') -Why 'Um processo localizado em path gravável foi observado escutando em todas as interfaces. A exposição efetiva ainda depende do firewall e do contexto do processo.' -Recommendation 'Validar binário, assinatura, firewall e necessidade operacional.' -ValidationSteps @('Confirmar exposição efetiva no firewall.','Validar identidade, assinatura e hash do processo.','Correlacionar com serviço/persistência.') -SourceRecordIds @($connection.RecordId) -SourceFiles @('10_portas_tcp_em_escuta.csv','network.json') -Score 2)) | Out-Null
        }
        if ($connection.State -eq 'Established' -and $connection.RemoteClassification -eq 'Public') {
            $signals = New-Object System.Collections.Generic.List[string]
            $signals.Add('NET.EXTERNAL_CONNECTION') | Out-Null
            if (Test-H1SSUserWritablePath $connection.ProcessPath) { $signals.Add('PROC.USER_WRITABLE_PATH') | Out-Null }
            if ($connection.ProcessSignatureStatus -eq 'NotSigned') { $signals.Add('PROC.UNSIGNED') | Out-Null }
            elseif ($connection.ProcessSignatureStatus -in @('HashMismatch','NotTrusted','UnknownError','Error')) { $signals.Add('PROC.INVALID_SIGNATURE') | Out-Null }
            if ($signals.Count -gt 1) {
                $severity = if (($signals -contains 'PROC.USER_WRITABLE_PATH') -and (($signals -contains 'PROC.UNSIGNED') -or ($signals -contains 'PROC.INVALID_SIGNATURE'))) { 'High' } else { 'Medium' }
                $strength = if ($severity -eq 'High') { 'Strong' } else { 'Heuristic' }
                $signalArray = $signals.ToArray()
                $findings.Add((New-H1SSFinding -RuleId 'NET.PROCESS_CONTEXT.001' -RuleVersion '1.0' -Severity $severity -Confidence Medium -EvidenceStrength $strength -Collector Network -CollectorStatus $CollectorStatus -EntityType NetworkConnection -EntityId $connection.RecordId -Signals $signalArray -Why ("Conexão externa para {0}:{1} foi correlacionada com contexto do processo: {2}. A porta é somente contexto." -f $connection.RemoteAddress,$connection.RemotePort,($signalArray -join ', ')) -Recommendation 'Validar processo, destino, assinatura, hash e finalidade operacional antes de conter.' -ValidationSteps @('Confirmar que o PID/ProcessRecordId ainda corresponde ao processo observado.','Validar assinatura e hash do binário.','Investigar reputação/dono do destino em fonte autorizada e comparar com baseline.') -SourceRecordIds @($connection.RecordId,$connection.ProcessRecordId) -SourceFiles @('08_conexoes_tcp_todas.csv','network.json','processes.json') -Score $signalArray.Count)) | Out-Null
            }
        }
    }
    $findings.ToArray()
}

function Invoke-H1SSRules {
    param(
        [hashtable]$Data,
        [hashtable]$StateByName
    )
    $allPersistence = @($Data.RunKeys) + @($Data.Startup) + @($Data.AdvancedPersistence) + @($Data.ScheduledTasks) + @($Data.Services)
    @(
        Invoke-H1SSProcessRules -Processes @($Data.Processes) -Network @($Data.Network) -PersistenceReferences $allPersistence -CollectorStatus $StateByName.Processes.Status
        Invoke-H1SSServiceRules -Services @($Data.Services) -CollectorStatus $StateByName.Services.Status
        Invoke-H1SSTaskRules -Tasks @($Data.ScheduledTasks) -CollectorStatus $StateByName.ScheduledTasks.Status
        Invoke-H1SSPersistenceRules -RunKeys @($Data.RunKeys) -Startup @($Data.Startup) -Advanced @($Data.AdvancedPersistence) -CollectorStatus $StateByName.RunKeys.Status
        Invoke-H1SSNetworkRules -Network @($Data.Network) -CollectorStatus $StateByName.Network.Status
    )
}
