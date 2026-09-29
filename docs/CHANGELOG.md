# Changelog

## 9.1.0 — Sprint 3 Enrichment

- `ToolVersion` e `ModuleVersion` alterados para `9.1.0`; `SchemaVersion 1.0` e `RuleSetVersion 2.0` permanecem inalterados;
- contrato comum de file metadata ganhou estados explícitos de metadata/hash, assinatura, identidade do signer, versão, timestamps e tamanho;
- cache case-insensitive por execução reutiliza metadata e hashes sem cruzar execuções;
- árvore de processos passou a correlacionar PID/PPID com tempo de criação e estados explícitos para saída, ambiguidade e evidência temporal insuficiente;
- metadata do executável de serviço e de `ServiceDll` passou a ser coletado separadamente, com parser de `ImagePath` e estados de ACL explícitos;
- Scheduled Tasks preservam Enabled/Disabled, todas as actions/triggers, XML, hash do XML e metadata pré-regra por action;
- hashing seletivo pós-regra inclui entidades e `SourceRecordIds`, além de persistências relevantes, sem alterar `HashKnown`;
- validador de integração verifica os contratos enriquecidos de processos, serviços e tarefas;
- 21 testes de enrichment adicionados aos 48 testes existentes, totalizando 69.

## 9.0.0 — Sprint 2.1 Detection Pipeline Closure

- pipeline corrigido para executar enrichment obrigatório de Scheduled Tasks antes das rules;
- enrichment de detecção separado do hashing seletivo pós-regra, sem duplicar aquisição de metadata;
- falhas de resolução/metadata de actions propagam `Partial` e permanecem visíveis à avaliação de trust;
- `Score == Signals.Count` imposto pelo construtor e pelo validador de integração em todos os findings;
- `EvidenceStrength` alinhado ao contrato `Confirmed`, `Strong`, `Heuristic`, `Contextual`;
- CGNAT permanece classificado como `CGNAT`, mas não é presumido como rede privada corporativa;
- `NET.INTERNAL_ADMIN_CONNECTION.001` alterado para `RuleVersion 2.1` por mudança semântica de CGNAT;
- 7 testes de pipeline closure adicionados aos 41 testes existentes; `RuleSetVersion` permanece `2.0`.

## 9.0.0 — Sprint 2 Detection Correctness

- `RuleSetVersion` alterado de `1.0` para `2.0`; ToolVersion e SchemaVersion permanecem `9.0.0` e `1.0`;
- trust baseado em atributos explícitos, sem allowlist por substring;
- signal engine determinística substitui severity derivada de score genérico;
- `Severity`, `Confidence` e `EvidenceStrength` têm decisões independentes;
- Scheduled Tasks avaliam todas as actions/triggers, preservam Disabled e não confiam no namespace Microsoft;
- processos correlacionam path, assinatura, parent, rede e persistência sem consultar o host nas rules;
- rede trata porta como contexto e correlaciona assinatura/path do snapshot de processo;
- ADSI normaliza `Local`, `Domain`, `BuiltIn` e `Unknown`, sem presumir unresolved como Local;
- 17 testes de Detection Correctness adicionados aos 24 testes de Reliability.

## 9.0.0 — Sprint 1.1 Reliability Closure

- falhas de Registry, CIM, ACL, metadata e hash deixam de ser convertidas silenciosamente em ausência;
- ausência normal de chaves/propriedades opcionais permanece `Success` com zero resultado;
- falhas não fatais de `Winlogon`, `SilentProcessExit`, `ServiceDll` e enriquecimentos propagam `Partial`;
- manifesto registra `collectionMode` e `collectionParameters` efetivos sem alterar `SchemaVersion` ou `RuleSetVersion`;
- validador confere campos de contexto, conjunto físico de outputs, tamanho e SHA-256;
- pacote de release exclui relatórios reais e outputs de integração gerados;
- testes de ausência normal, AccessDenied, exceção inesperada, hash e manifesto adicionados.

## 9.0.0

- estados explícitos por coletor e `overallStatus`;
- `00_MANIFEST.json` obrigatório e SHA-256 dos outputs;
- RunId e diretório sem colisão;
- JSON canônico e CSV spreadsheet-safe;
- modos Quick, Standard e Deep;
- processos com owner/session/tree/file metadata e hash seletivo;
- tarefas Enabled/Disabled, principal, actions, triggers, info, XML e hash do XML;
- serviços com parsing de ImagePath, ServiceDll, assinatura, ACL e unquoted path;
- rede com IPv4/IPv6/mapped/CGNAT e contexto para administração interna;
- Run keys ampliadas, Startup de perfis, WMI, PowerShell profiles, Winlogon e IFEO;
- Event Logs e Defender opcionais;
- regras multi-sinal com Severity, Confidence e EvidenceStrength;
- fallback ADSI corrigido para usar `Unknown` quando a origem não pode ser provada;
- exclusão de relatórios com canonicalização, descendência direta e bloqueio de reparse point;
- Pester e validador de integridade de relatório.

### New finding corrigido durante a implementação

- **Root cause:** Windows PowerShell 5.1 interpreta scripts UTF-8 sem BOM como ANSI.
- **Impacto:** mensagens PT-BR eram gravadas com caracteres corrompidos.
- **Fix:** arquivos PowerShell distribuídos com UTF-8 BOM.
- **Teste:** execução Quick em Windows PowerShell 5.1 e validação de encoding.
