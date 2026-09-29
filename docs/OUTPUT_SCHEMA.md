# Output Schema 1.0

## Manifest

Contém identidade da ferramenta/host/coletor, tempo UTC/local, timezone, PowerShell, bitness, `collectionMode`, `collectionParameters`, `overallStatus`, capabilities, `collectors[]` e `outputFiles[]`.

`collectionMode` registra diretamente `Quick`, `Standard` ou `Deep`. `collectionParameters` registra os valores efetivos, inclusive defaults, que influenciam cobertura e limites:

```json
{
  "collectionMode": "Quick",
  "collectionParameters": {
    "eventLogHours": 24,
    "recentFileHours": 24,
    "maxRecentFiles": 200,
    "maxScanDurationSeconds": 30
  }
}
```

Esses campos são uma extensão aditiva compatível do schema `1.0`; nenhum campo existente foi removido ou reinterpretado. O Sprint 2 mantém o schema `1.0` porque os campos de finding já existiam. `ruleSetVersion` agora é `2.0`, pois a semântica global de classificação mudou.

## Collector state

```json
{
  "CollectorName": "Processes",
  "Status": "Success",
  "StartedAtUtc": "2026-09-25T20:00:00Z",
  "FinishedAtUtc": "2026-09-25T20:00:01Z",
  "DurationMs": 1000,
  "RecordCount": 123,
  "ErrorType": "",
  "ErrorMessage": "",
  "Required": true
}
```

## Finding

Campos: `FindingId`, `RuleId`, `RuleVersion`, `Severity`, `Confidence`, `EvidenceStrength`, `ObservedAtUtc`, `Collector`, `CollectorStatus`, `EntityType`, `EntityId`, `Score`, `Signals`, `Why`, `Recommendation`, `ValidationSteps`, `SourceRecordIds`, `SourceFiles` e `Bucket`.

No ruleset `2.0`, `Score` é somente a contagem determinística de signals: `Score MUST equal Signals.Count`. O construtor e o validador de integração impõem esse contrato. Score não controla Severity, Confidence ou EvidenceStrength e não é “AI score”.

Valores permitidos para `EvidenceStrength`: `Confirmed`, `Strong`, `Heuristic` e `Contextual`. `Confirmed` é reservado a fatos diretamente comprovados, como cobertura incompleta registrada no manifesto; correlação heurística não recebe esse valor automaticamente. Valores brutos permanecem no JSON; CSV é uma projeção segura para planilha.

Process records podem incluir `TrustLevel`, `TrustReason`, `PathExpected`, `PublisherExpected`, `SignatureValid`, `OriginalFileNameExpected`, `CompanyExpected`, `HashKnown` e `TrustSignals`. Valores desconhecidos permanecem `null`/`Unknown`; não são inferidos por substring.

Scheduled Task records incluem `ActionFileMetadata`, `DetectionEnrichmentStatus` e `DetectionEnrichmentErrors`. Metadata necessário à detecção é produzido antes das rules. `SHA256` pode ser preenchido seletivamente depois dos findings; um SHA-256 calculado não implica `HashKnown=true`.

## Enrichment fields

Process records incluem `RawExecutablePath`, owner/SID e status, `ParentResolutionStatus`, `ParentResolutionReason`, metadata de arquivo e estados separados de metadata/hash. Service records mantêm metadata do executável no record principal e `ServiceDllMetadata` separado. Scheduled Task actions incluem `RawExecute`, path resolvido, argumentos, diretório de trabalho e `ActionFileMetadata`; o record mantém `Xml` e `XmlSHA256`.

Estados comuns de metadata: `Success`, `Partial`, `Missing` e `Unavailable`. Estados de hash: `NotRequested`, `Pending`, `Success`, `Failed`, `FileMissing` e `Unavailable`. Campos adicionais são compatíveis de forma aditiva; por isso `SchemaVersion` permanece `1.0`.
