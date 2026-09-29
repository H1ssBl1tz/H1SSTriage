# Audit Resolution Matrix

| Audit ID | Status | Arquivos principais | Correção/Teste |
|---|---|---|---|
| H1SS-001 | Fixed | Core, Collectors, Rules, Public, Output, Tests | ausência opcional distinta de AccessDenied/provider failure; `Partial` propagado; testes zero vs falha e falhas de subfonte |
| H1SS-002 | Fixed | Rules, Tests | namespace Microsoft é apenas signal contextual; masquerade e cenário legítimo testados |
| H1SS-003 | Fixed | Rules, Collectors, Tests | trust por seis atributos explícitos; substrings não geram trust; raw evidence preservada |
| H1SS-004 | Fixed | Rules, Tests, DETECTION_MODEL | Severity/Confidence/EvidenceStrength decididos separadamente por condições explícitas; Score é só signal count |
| H1SS-005 | Partially Fixed | Collectors | HKU carregado, perfis, WMI, Winlogon, IFEO; hives offline/RunOnceEx completos adiados |
| H1SS-006 | Fixed | Collectors | todas as tarefas, info, principal, actions, triggers, XML/hash e erro por item |
| H1SS-007 | Partially Fixed | Core, Collectors, Rules, Tests | IPv4/IPv6/mapped/CGNAT/link-local e contexto de processo testados; reputação/ASN/baseline adiados |
| H1SS-008 | Partially Fixed | Collectors | timestamps e ProcessRecordId; validação pós-socket de PID+creation ainda pode evoluir |
| H1SS-009 | Partially Fixed | Collectors, Rules | parsing, ServiceDll, ACL, assinatura, unquoted path; SDDL/failure actions adiados |
| H1SS-010 | Fixed | Output, Public | proveniência, hashes dos outputs e sidecar do manifesto |
| H1SS-011 | Fixed | Core, Output | RunId exclusivo, criação sem Force, paths literais/canônicos |
| H1SS-012 | Partially Fixed | Core, docs | preflight e paths de módulos registrados; import explícito/assinatura de módulos ainda pendente |
| H1SS-013 | Fixed | Collectors | janela, quantidade, duração e estado Partial ao atingir limite |
| H1SS-014 | Fixed | Public | snapshots armazenados e reutilizados por regra/output/sumário |
| H1SS-015 | Fixed | Collectors, Tests | ADSI distingue Local/Domain/BuiltIn/Unknown; unresolved e SID S-1-5-21 sem authority permanecem Unknown |
| H1SS-016 | Partially Fixed | Core, docs | preflight, bitness e matriz; Win10/Server e auto-reexec 64-bit não testados |
| H1SS-017 | Fixed | script principal | canonicalização, descendência direta, revalidação e bloqueio de reparse point |
| H1SS-018 | Fixed | README/docs/script | versão 9 única, `05b` realmente gerado e documentação sincronizada |
| H1SS-019 | Fixed | módulo Public/Private | aquisição, rules e output separados; funções puras testáveis |
| H1SS-020 | Fixed | Core, Output | sanitização só na projeção CSV; JSON bruto preservado |
| H1SS-021 | Fixed | Public, Enrichment, Rules, Tests | `ActionFileMetadata` e assinatura produzidos antes das rules; hashing seletivo pós-regra separado; pipeline real testado |
| H1SS-022 | Fixed | Rules, Integration Tests | construtor e validador impõem `Score == Signals.Count` em todos os domínios |
| H1SS-023 | Fixed | Core, Rules, Tests, docs | CGNAT preservado como classe própria e removido da presunção de rede privada administrativa |
| H1SS-024 | Fixed | Rules, docs | contrato de EvidenceStrength alinhado a Confirmed/Strong/Heuristic/Contextual; Confirmed reservado a fato de cobertura |
| H1SS-025 | Fixed | Core, Enrichment, Collectors, Tests | contrato comum de metadata e cache por execução com estados explícitos e hash independente |
| H1SS-026 | Fixed | Enrichment, Collectors, Tests | árvore de processos temporalmente consistente, sem sobrescrever candidatos de PID reutilizado |
| H1SS-027 | Fixed | Collectors, Tests | executável de serviço e ServiceDll enriquecidos separadamente; parser e ACL falham de forma observável |
| H1SS-028 | Fixed | Collectors, Enrichment, Integration Tests | tasks completas e hashing seletivo alcançam EntityId/SourceRecordIds sem host I/O nas rules |

“Partially Fixed” não significa que o comportamento restante é oculto: as limitações estão documentadas e estados de coleta permanecem explícitos.
