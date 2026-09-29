# Collector Matrix

| Coletor | Required | Quick | Standard | Deep | Elevação melhora |
|---|---:|---:|---:|---:|---:|
| System | sim | sim | sim | sim | às vezes |
| Users | sim | sim | sim | sim | não normalmente |
| Administrators | sim | sim | sim | sim | ambiente dependente |
| Processes | sim | sim | sim | sim | sim |
| Services | sim | sim | sim | sim | sim |
| Network | sim | sim | sim | sim | sim |
| ScheduledTasks | sim | sim | sim | sim | sim |
| RunKeys | sim | sim | sim | sim | sim para HKLM/HKU |
| Startup | sim | sim | sim | sim | sim para outros perfis |
| DNS | não | sim | sim | sim | ambiente dependente |
| AdvancedPersistence | não | não | sim | sim | sim |
| Events | não | não | sim | sim | sim, especialmente Security |
| Defender | não | não | sim | sim | sim |
| RecentFiles | não | não | não | sim | sim para Windows Temp |

Cada estado inclui início/fim UTC, duração, contagem, erro, obrigatoriedade e metadata específica. Zero registros com `Success` é diferente de falha.

Chaves, propriedades e arquivos opcionais inexistentes são ausência normal. `AccessDenied`, falha de provider, dados inválidos e exceções inesperadas são registrados no coletor; quando ainda há dados úteis, o estado é `Partial`.

`Administrators.PrincipalSource` é normalizado para `Local`, `Domain`, `BuiltIn` ou `Unknown`. Authority/SID inconclusivo nunca é presumido como `Local`.

Network records reutilizam o snapshot de processos e incluem, quando disponíveis, `ProcessRecordId`, `ProcessPath`, `ProcessSignatureStatus` e `ProcessTrustLevel`. Rules não consultam o host novamente.

Após a coleta normalizada, `Add-H1SSDetectionEnrichment` resolve actions de Scheduled Tasks e popula `ActionFileMetadata` antes de `Invoke-H1SSRules`. Erros de resolução ou metadata propagam `Partial`. Depois dos findings, `Add-H1SSSelectiveFileHashes` calcula somente hashes selecionados e reutiliza o metadata já adquirido; `SHA256` calculado não transforma `HashKnown` em verdadeiro.

## Enrichment do Sprint 3

- Processes preservam path bruto/resolvido, owner/SID e status de resolução. A árvore usa PID/PPID e `CreationTimeUtc`; PID duplicado nunca é sobrescrito silenciosamente.
- Services separam o metadata do executável principal de `ServiceDllMetadata`. Parser, existência, assinatura, versão e ACL têm estados/erros próprios.
- Scheduled Tasks incluem tarefas habilitadas e desabilitadas, todas as actions/triggers, XML e `XmlSHA256`; cada action recebe metadata antes das rules.
- Um cache case-insensitive por execução evita repetir aquisição de metadata e hash para o mesmo path normalizado. O cache não persiste entre execuções.
- Quick prioriza existência e metadata necessária à detecção; Standard amplia metadata; Deep inclui hashing mais abrangente. Findings podem selecionar hashes adicionais após as rules.
