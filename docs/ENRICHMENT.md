# Enrichment Architecture

## Pipeline

```text
Collector
→ normalized records
→ detection-required enrichment
→ rules
→ findings
→ selective post-rule hashing
→ export
```

Enrichment adiciona propriedades aos registros normalizados sem remover valores brutos. Rules recebem somente snapshots/enrichment e não consultam o host.

## File metadata contract

`Get-H1SSFileMetadata` é o provider comum para processos, serviços e Scheduled Tasks. O contrato inclui:

- `FileExists`, `MetadataStatus`, `MetadataError`;
- `SHA256`, `HashStatus`;
- `SignatureStatus`, `SignerSubject`, `SignerIssuer`, `SignerThumbprint`;
- `CompanyName`, `ProductName`, `OriginalFileName`, `FileVersion`;
- `FileCreationTimeUtc`, `FileLastWriteTimeUtc`, `FileSize`.

`MetadataStatus` diferencia `Success`, `Partial`, `Missing` e `Unavailable`. `HashStatus` diferencia `NotRequested`, `Success`, `Failed`, `FileMissing` e `Unavailable`. `SHA256` é digest calculado localmente; não altera `HashKnown`.

## Per-run cache

`New-H1SSFileMetadataCache` cria cache vazio para cada `Invoke-H1SSTriage`. Chaves usam path expandido, normalizado e case-insensitive. Metadata equivalente é reutilizado entre processos, serviços e tasks; hashes seletivos também são reutilizados. O cache não é persistido e não atravessa hosts/runs.

Uma solicitação mais rica pode promover uma entrada que continha apenas verificação de existência. Dados de execução anterior nunca são reutilizados.

## Process metadata and tree

Processos preservam path bruto/resolvido, command line, creation time, sessão, owner/SID e metadata de arquivo. `OwnerResolutionStatus` diferencia `Resolved`, `Partial`, `Unavailable` e `ExitedOrUnavailable`.

`Resolve-H1SSProcessParents` agrupa candidatos por PID e exige evidência temporal:

- parent creation deve ser anterior ou igual à criação do child;
- em PID reuse, vence apenas o candidato único de criação plausível mais recente;
- empate retorna `Ambiguous`;
- parent ausente no snapshot retorna `ExitedOrUnavailable`;
- creation time insuficiente retorna `Unresolved`.

O vínculo nunca é inferido apenas por PID/PPID.

## Hashing policy

- Quick/Standard: hash somente entidades com findings `Alert`, incluindo processos referenciados por findings de rede, e persistência relevante suportada.
- Deep: amplia hashing para processos, executáveis/ServiceDll de serviços e actions de tasks coletados.
- O provider usa `LiteralPath`, não executa o arquivo e registra falha/arquivo desaparecido separadamente.
- Run keys e Startup com finding recebem campos pós-regra de hash quando o executable/target é resolvível.

## Services

O valor bruto (`PathName`/`RawImagePath`) é preservado. O parser expande variáveis e separa `ExecutablePath`/`Arguments` para caminhos quoted, unquoted e binários `.exe`, `.com` ou `.sys`. `ServiceDllMetadata` é separado do metadata do executável principal. Falhas de ACL mantêm `WritableExecutable`/`WritableDirectory` nulos e propagam `Partial`.

`UnquotedServicePath` continua sendo fraqueza de configuração/hardening, não veredito de malware.

## Scheduled Tasks

Enabled e Disabled, principal, todas as actions/triggers, runtime info, XML e `XmlSHA256` permanecem no JSON. `Add-H1SSDetectionEnrichment` resolve actions e preenche `ActionFileMetadata` antes das rules. Cada item preserva raw execute, path resolvido, argumentos, working directory, metadata, assinatura e status. Hashes são adicionados depois das rules quando selecionados ou em Deep.

## Failure semantics

Ausência esperada não é erro. Access denied, provider failure, assinatura indisponível, ACL failure e hashing failure permanecem explícitos e podem propagar `Partial`. Valor desconhecido não é convertido silenciosamente em `false`, `Valid` ou benigno.
