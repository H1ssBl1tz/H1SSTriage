[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ReportPath)

$resolved = (Get-Item -LiteralPath $ReportPath -ErrorAction Stop).FullName
$manifestPath = Join-Path -Path $resolved -ChildPath '00_MANIFEST.json'
$manifestHashPath = Join-Path -Path $resolved -ChildPath '00_MANIFEST.sha256'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw '00_MANIFEST.json ausente.' }
if (-not (Test-Path -LiteralPath $manifestHashPath -PathType Leaf)) { throw '00_MANIFEST.sha256 ausente.' }

$manifest = Get-Content -Raw -LiteralPath $manifestPath -Encoding UTF8 | ConvertFrom-Json
foreach ($field in @('schemaVersion','toolName','toolVersion','ruleSetVersion','runId','collectionMode','collectionParameters','overallStatus','collectors','outputFiles')) {
    if ($null -eq $manifest.$field) { throw "Campo obrigatório ausente no manifesto: $field" }
}
if ($manifest.collectionMode -notin @('Quick','Standard','Deep')) { throw "collectionMode inválido: $($manifest.collectionMode)" }
foreach ($parameter in @('eventLogHours','recentFileHours','maxRecentFiles','maxScanDurationSeconds')) {
    if ($null -eq $manifest.collectionParameters.$parameter) { throw "Parâmetro efetivo ausente no manifesto: $parameter" }
}
if ($manifest.overallStatus -notin @('Complete','Partial','Failed')) { throw "overallStatus inválido: $($manifest.overallStatus)" }

$requiredProblem = @($manifest.collectors | Where-Object { $_.Required -and $_.Status -ne 'Success' })
if ($requiredProblem.Count -gt 0 -and $manifest.overallStatus -eq 'Complete') { throw 'Manifesto declarou Complete com coletor obrigatório incompleto.' }

foreach ($output in $manifest.outputFiles) {
    if ([IO.Path]::GetFileName([string]$output.File) -ne [string]$output.File) { throw "Nome de output inválido: $($output.File)" }
    $path = Join-Path -Path $resolved -ChildPath $output.File
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Output registrado não existe: $($output.File)" }
    $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
    if ($actualHash -ne $output.SHA256) { throw "Hash divergente: $($output.File)" }
    if ((Get-Item -LiteralPath $path).Length -ne $output.Size) { throw "Tamanho divergente: $($output.File)" }
}

$registeredFiles = @($manifest.outputFiles | ForEach-Object { [string]$_.File } | Sort-Object -Unique)
$physicalOutputFiles = @(Get-ChildItem -LiteralPath $resolved -File -ErrorAction Stop | Where-Object { $_.Name -notin @('00_MANIFEST.json','00_MANIFEST.sha256') } | ForEach-Object Name | Sort-Object -Unique)
$fileSetDifference = @(Compare-Object -ReferenceObject $registeredFiles -DifferenceObject $physicalOutputFiles)
if ($fileSetDifference.Count) { throw "Conjunto físico de outputs difere do manifesto: $($fileSetDifference | Out-String)" }

$requiredFiles = @('00_SUMARIO.txt','findings.json','processes.json','services.json','network.json','scheduled_tasks.json','persistence.json','events.json','defender.json','recent_files.json','system.json','users.json')
foreach ($requiredFile in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path -Path $resolved -ChildPath $requiredFile) -PathType Leaf)) { throw "Output obrigatório ausente: $requiredFile" }
}

$findingDocument = Get-Content -Raw -LiteralPath (Join-Path -Path $resolved -ChildPath 'findings.json') -Encoding UTF8 | ConvertFrom-Json
$findings = @($findingDocument.records)
$requiredFindingFields = @('RuleId','RuleVersion','Severity','Confidence','EvidenceStrength','Signals','Why','Recommendation','ValidationSteps')
foreach ($finding in $findings) {
    foreach ($field in $requiredFindingFields) {
        if ($finding.PSObject.Properties.Name -notcontains $field) { throw "Finding $($finding.FindingId) sem campo obrigatório: $field" }
    }
    if ([string]::IsNullOrWhiteSpace([string]$finding.RuleId) -or [string]::IsNullOrWhiteSpace([string]$finding.RuleVersion)) { throw "Finding $($finding.FindingId) sem identificação de regra coerente." }
    if ($finding.Severity -notin @('Critical','High','Medium','Low','Informational')) { throw "Severity inválida em $($finding.FindingId): $($finding.Severity)" }
    if ($finding.Confidence -notin @('High','Medium','Low')) { throw "Confidence inválida em $($finding.FindingId): $($finding.Confidence)" }
    if ($finding.EvidenceStrength -notin @('Confirmed','Strong','Heuristic','Contextual')) { throw "EvidenceStrength inválida em $($finding.FindingId): $($finding.EvidenceStrength)" }
    $signalCount = @($finding.Signals).Count
    if ([int]$finding.Score -ne $signalCount) { throw "Score divergente em $($finding.FindingId): Score=$($finding.Score), Signals.Count=$signalCount" }
    if ([string]::IsNullOrWhiteSpace([string]$finding.Why) -or [string]::IsNullOrWhiteSpace([string]$finding.Recommendation) -or @($finding.ValidationSteps).Count -eq 0) { throw "Finding $($finding.FindingId) sem explicabilidade mínima." }
}

function Assert-H1SSObjectFields {
    param([object]$InputObject, [string[]]$Fields, [string]$Context)
    foreach ($field in $Fields) {
        if ($InputObject.PSObject.Properties.Name -notcontains $field) { throw "$Context sem campo de contrato: $field" }
    }
}

function Get-H1SSValidatorStringSha256 {
    param([string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))).Replace('-','') }
    finally { $sha.Dispose() }
}

$processDocument = Get-Content -Raw -LiteralPath (Join-Path -Path $resolved -ChildPath 'processes.json') -Encoding UTF8 | ConvertFrom-Json
$processFields = @('ObservedAtUtc','PID','PPID','Name','RawExecutablePath','ExecutablePath','CommandLine','CreationDate','SessionId','Owner','OwnerSid','OwnerResolutionStatus','ParentName','ParentPath','ParentCreationTime','ParentResolutionStatus','FileExists','MetadataStatus','SHA256','HashStatus','SignatureStatus','SignerSubject','SignerIssuer','SignerThumbprint','CompanyName','ProductName','OriginalFileName','FileVersion','FileCreationTimeUtc','FileLastWriteTimeUtc','FileSize')
foreach ($process in @($processDocument.records)) {
    Assert-H1SSObjectFields -InputObject $process -Fields $processFields -Context "Processo $($process.RecordId)"
    if ($process.ParentResolutionStatus -notin @('Resolved','Unresolved','ExitedOrUnavailable','Ambiguous')) { throw "ParentResolutionStatus inválido em $($process.RecordId): $($process.ParentResolutionStatus)" }
    if ($process.OwnerResolutionStatus -notin @('Resolved','Partial','Unavailable','ExitedOrUnavailable')) { throw "OwnerResolutionStatus inválido em $($process.RecordId): $($process.OwnerResolutionStatus)" }
}

$serviceDocument = Get-Content -Raw -LiteralPath (Join-Path -Path $resolved -ChildPath 'services.json') -Encoding UTF8 | ConvertFrom-Json
$serviceFields = @('Name','DisplayName','State','StartMode','StartName','PathName','RawImagePath','ExpandedImagePath','ExecutablePath','Arguments','ServiceDll','ServiceDllMetadata','ServiceType','StartType','FileExists','MetadataStatus','SHA256','HashStatus','SignatureStatus','SignerSubject','SignerIssuer','SignerThumbprint','CompanyName','ProductName','OriginalFileName','FileVersion','FileCreationTimeUtc','FileLastWriteTimeUtc','FileSize','ServiceRegistryPath','UnquotedServicePath','WritableExecutable','WritableDirectory','ExecutableAclStatus','DirectoryAclStatus')
foreach ($service in @($serviceDocument.records)) {
    Assert-H1SSObjectFields -InputObject $service -Fields $serviceFields -Context "Serviço $($service.RecordId)"
    if ($service.ServiceDll -and -not $service.ServiceDllMetadata) { throw "Serviço $($service.RecordId) possui ServiceDll sem metadata normalizado." }
}

$taskDocument = Get-Content -Raw -LiteralPath (Join-Path -Path $resolved -ChildPath 'scheduled_tasks.json') -Encoding UTF8 | ConvertFrom-Json
$taskFields = @('TaskName','TaskPath','State','Enabled','Author','Description','PrincipalUserId','PrincipalLogonType','PrincipalRunLevel','Actions','Arguments','WorkingDirectory','Triggers','LastRunTime','NextRunTime','LastTaskResult','NumberOfMissedRuns','Hidden','XML','XmlSHA256','ActionFileMetadata','DetectionEnrichmentStatus','DetectionEnrichmentErrors')
foreach ($task in @($taskDocument.records)) {
    Assert-H1SSObjectFields -InputObject $task -Fields $taskFields -Context "Scheduled Task $($task.RecordId)"
    if ($task.XML -and $task.XmlSHA256 -ne (Get-H1SSValidatorStringSha256 -Value ([string]$task.XML))) { throw "XmlSHA256 divergente em $($task.RecordId)." }
    foreach ($actionMetadata in @($task.ActionFileMetadata)) {
        Assert-H1SSObjectFields -InputObject $actionMetadata -Fields @('Execute','ResolvedPath','ResolutionStatus','MetadataStatus','Arguments','WorkingDirectory','FileExists','SHA256','HashStatus','SignatureStatus','SignerSubject','CompanyName','OriginalFileName','FileVersion','Metadata') -Context "Action metadata de $($task.RecordId)"
    }
}

$expectedManifestHash = ((Get-Content -Raw -LiteralPath $manifestHashPath -Encoding ASCII) -split '\s+')[0]
$actualManifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256 -ErrorAction Stop).Hash
if ($expectedManifestHash -ne $actualManifestHash) { throw 'Hash do manifesto divergente.' }

[PSCustomObject]@{
    ReportPath=$resolved
    OverallStatus=$manifest.overallStatus
    CollectorCount=@($manifest.collectors).Count
    OutputCount=@($manifest.outputFiles).Count
    FindingCount=$findings.Count
    ProcessCount=@($processDocument.records).Count
    ServiceCount=@($serviceDocument.records).Count
    ScheduledTaskCount=@($taskDocument.records).Count
    Integrity='Valid'
}
