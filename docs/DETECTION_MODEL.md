# Detection Model 2.0

H1SSTriage produz indicadores de triagem para revisão humana. Um finding é uma hipótese explicável derivada de evidência bruta; não é um veredito de malware ou comprometimento.

## Lifecycle

```text
Collection -> normalized raw record -> detection-required enrichment -> rules -> findings -> selective post-rule hashing -> export
```

Rules operam somente sobre snapshots já coletados e enriquecidos. Elas não consultam Registry, CIM, rede ou filesystem. Metadata de actions de Scheduled Tasks é resolvido antes de `Invoke-H1SSRules`; hashing seletivo que não participa da decisão pode ocorrer depois dos findings. Registros brutos continuam nos JSON/CSV mesmo quando trust reduz a prioridade de um finding.

## Trust

O modelo considera, quando disponíveis:

- `PathExpected`;
- `PublisherExpected`;
- `SignatureValid`;
- `OriginalFileNameExpected`;
- `CompanyExpected`;
- `HashKnown`.

Resultados: `Trusted`, `LikelyTrusted`, `Unknown` e `Suspicious`.

`Trusted` exige correspondência explícita de todos os atributos fortes. Path protegido + assinatura válida pode produzir somente `LikelyTrusted`. Nome de produto, substring no path ou namespace Microsoft nunca estabelecem trust. Trust pode reduzir Severity/Confidence de uma hipótese, mas não remove raw evidence.

## Signals

Signals são strings estáveis, determinísticas e auditáveis. Principais grupos:

| Namespace | Exemplos | Significado |
|---|---|---|
| `PROC.*` | `USER_WRITABLE_PATH`, `UNSIGNED`, `INVALID_SIGNATURE`, `SUSPICIOUS_PARENT`, `EXTERNAL_CONNECTION`, `PERSISTENCE_REFERENCE` | contexto do processo |
| `TASK.*` | `SUSPICIOUS_ARGUMENTS`, `USER_WRITABLE_PATH`, `HIDDEN`, `DISABLED`, `MULTIPLE_ACTIONS`, `NAMESPACE_MASQUERADE` | contexto de scheduled task |
| `SVC.*` | `MISSING_BINARY`, `WRITABLE_BY_COLLECTOR`, `UNSIGNED`, `USER_WRITABLE_SERVICE_DLL` | contexto de serviço |
| `NET.*` | `EXTERNAL_CONNECTION`, `INTERNAL_ADMIN_CONNECTION`, `LISTENING_SOCKET` | contexto de socket/destino |
| `PERSIST.*` | `USER_WRITABLE_PATH`, `SUSPICIOUS_COMMAND`, `INTERPRETER_OR_LOLBIN` | contexto de persistência |
| `TRUST.*` | `PATH_EXPECTED`, `SIGNATURE_VALID`, `PUBLISHER_EXPECTED`, `HASH_KNOWN` | explicação da avaliação de trust |

## Severity, Confidence e EvidenceStrength

- `Severity`: prioridade/impacto potencial se a hipótese for verdadeira.
- `Confidence`: confiança da ferramenta na interpretação.
- `EvidenceStrength`: força objetiva da combinação observada.

Eles são decididos separadamente. Um path Temp, AppData, PowerShell, unsigned ou porta isolada não produz `High`. Combinações explícitas independentes podem elevar prioridade, por exemplo user-writable + unsigned + conexão externa, ou persistência + unsigned + user-writable.

`Confirmed` é reservado a fatos que a ferramenta realmente confirma, como estado de cobertura, e não é usado para declarar comprometimento em regras heurísticas.

## Deterministic decisions

Cada família usa condições explícitas sobre o conjunto de signals. A ordem do input, relógio atual, hash table order e ambiente não participam da classificação. `PROC.RECENT_FILE` usa `ObservedAtUtc` do próprio snapshot, não o relógio durante a regra.

O campo legado `Score` é mantido por compatibilidade e contém sempre `Signals.Count`. O construtor de findings impõe esse invariante; pesos legados não são aceitos como score. Ele não determina Severity, Confidence ou EvidenceStrength.

## Scheduled Tasks

`TaskPath=\Microsoft\Windows\*` adiciona somente `TASK.MICROSOFT_NAMESPACE_CONTEXT`. Se combinado com action em user profile ou argumentos suspeitos, a regra adiciona `TASK.NAMESPACE_MASQUERADE`. Todas as actions e triggers disponíveis são avaliadas. Tarefas Disabled continuam nos raw records e continuam elegíveis à análise.

`Add-H1SSDetectionEnrichment` resolve cada action e popula `ActionFileMetadata`, `SignatureStatus` e atributos de expectativa disponíveis antes das rules. Falhas ficam em `DetectionEnrichmentStatus=Partial`, são propagadas ao estado do coletor e resultam em trust inconclusivo, nunca em uma suposição benigna. `SHA256` seletivo é pós-regra; possuir um digest não altera `HashKnown`.

## Network

Porta é contexto, nunca veredito. Conexões externas só geram finding de processo/rede quando combinadas com contexto como path gravável ou assinatura ausente/inválida. SMB, RDP, WinRM e RPC em endereços `Private` são `Informational/Contextual`. `CGNAT` (`100.64.0.0/10`) permanece uma classe separada e não é presumida como LAN corporativa nem marcada como maliciosa. IPv4, IPv6, mapped IPv4, loopback, private, link-local e CGNAT têm classificação determinística.

## Limitations

- Não existe reputação online, ASN, certificate chain pinning ou baseline corporativo embutido.
- `HashKnown` só pode ser verdadeiro quando uma fonte autorizada fornece essa expectativa; possuir um SHA-256 não significa hash conhecido/benigno.
- Signature válida reduz incerteza, mas não prova benignidade.
- Metadata de action de scheduled task pode falhar ou estar ausente; nesse caso o enrichment/coletor fica `Partial` quando houver erro e trust permanece `Unknown`.
- Findings dependem da cobertura registrada no manifesto e requerem validação humana.

## Enrichment e estabilidade das regras

O Sprint 3 amplia o snapshot consumido pelas rules sem alterar a semântica do ruleset `2.0`. Resolução de parent, cache e hashing seletivo não executam dentro das rules. Parent metadata é contexto temporal: estados `Ambiguous`, `Unresolved` e `ExitedOrUnavailable` não são convertidos em uma relação afirmativa. Nenhuma `RuleVersion` mudou nesta entrega.
