# H1SSTriage 9.1.0

H1SSTriage é uma ferramenta defensiva de Windows Live Response / triagem inicial para SOC, Incident Response e DFIR. Ela coleta snapshots do sistema, registra explicitamente falhas e limitações, aplica regras determinísticas e produz dados estruturados com metadados de integridade. Findings são indicadores de triagem que exigem validação humana.

Ela não é antivírus, EDR, aquisição forense bit a bit ou prova de ausência de comprometimento. Não detecta rootkits ou adulteração de kernel/API/WMI de forma confiável.

## Mudança central da v9

Cada coletor termina com um estado distinto:

- `Success`: executou, inclusive quando retornou zero registros;
- `Partial`: retornou dados, mas houve perda ou limite;
- `Failed`: tentou executar e falhou;
- `Unavailable`: recurso/cmdlet/log não disponível;
- `Unsupported`: plataforma/versão não suportada;
- `Skipped`: não selecionado pelo modo.

`00_MANIFEST.json` é a fonte de verdade sobre cobertura. O relatório nunca chama o endpoint de limpo.

## Detection model

O ruleset `2.0` combina signals explícitos sem AI/ML score. `Severity`, `Confidence` e `EvidenceStrength` têm significados independentes. Path, assinatura, nome conhecido, namespace Microsoft, PowerShell ou porta isolados não estabelecem legitimidade ou comprometimento.

Trust usa atributos disponíveis (`PathExpected`, publisher, assinatura, original filename, company e hash conhecido). Ele pode reduzir prioridade, mas nunca remove registros brutos. Consulte [docs/DETECTION_MODEL.md](docs/DETECTION_MODEL.md).

O pipeline executa `Collection → Detection-required enrichment → Rules → Findings → Selective post-rule hashing → Export`. Toda informação consumida por uma regra é adquirida antes da decisão. `Score` existe somente para compatibilidade e é sempre igual a `Signals.Count`.

O enrichment 9.1 preserva metadata de processos, owner/SID, relações pai-filho com validação temporal, assinatura e versão de arquivos, contexto separado de executáveis/ServiceDll e todas as actions/triggers de Scheduled Tasks. Metadata é reutilizado por cache case-insensitive por execução; hashes permanecem seletivos. Consulte [docs/ENRICHMENT.md](docs/ENRICHMENT.md).

Exemplo sanitizado:

```json
{
  "RuleId": "PROC.MULTI_SIGNAL.001",
  "RuleVersion": "2.0",
  "Severity": "High",
  "Confidence": "Medium",
  "EvidenceStrength": "Strong",
  "Signals": [
    "PROC.USER_WRITABLE_PATH",
    "PROC.UNSIGNED",
    "PROC.EXTERNAL_CONNECTION"
  ],
  "Why": "Combinação observável que exige investigação e não confirma comprometimento."
}
```

## Uso rápido

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\H1SSTriage.ps1 -OutputPath E:\IR -NoMenu -Mode Quick
```

Modos:

- `Quick`: sistema, usuários, processos, serviços, rede e persistência básica;
- `Standard` (padrão): Quick + persistência avançada, Event Logs e Defender;
- `Deep`: Standard + hashes adicionais e arquivos recentes limitados.

Parâmetros de volume:

```powershell
-EventLogHours 24
-RecentFileHours 24
-MaxRecentFiles 200
-MaxScanDurationSeconds 30
```

## Ordem de análise

1. `00_MANIFEST.json`: confirme `overallStatus` e estados dos coletores.
2. `00_SUMARIO.txt`: leia limitações e top findings.
3. `findings.json` ou `16_alertas.csv`: revise sinais, confiança e validação.
4. Cruze `processes.json`, `network.json`, `services.json`, `scheduled_tasks.json` e `persistence.json`.

## Formatos

JSON é a representação canônica e preserva valores brutos. CSV continua disponível para compatibilidade, com proteção contra células iniciadas por `=`, `+`, `-` ou `@`. TXT é somente um resumo humano.

Todos os outputs, exceto o próprio manifesto e seu sidecar, têm SHA-256 e tamanho em `00_MANIFEST.json`. `00_MANIFEST.sha256` contém o hash do manifesto. Isso é metadata de integridade, não cadeia de custódia formal.

## Compatibilidade

Consulte [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md). Nesta entrega foram realmente testados:

- Windows 10 + Windows PowerShell 5.1: 69 testes Pester e coletas Quick/Standard/Deep não elevadas no sandbox;
- Windows 10 + PowerShell 7.6.5: 69 testes Pester e coleta Quick não elevada no sandbox.

As quatro execuções produziram manifestos íntegros, com 38 outputs registrados e 40 arquivos físicos. O sandbox negou várias fontes do sistema; por isso `overallStatus=Partial` é o resultado correto, não uma coleta limpa. Windows Server não foi testado nesta entrega.

## Segurança e impacto forense

O coletor não cria persistência, não mata processos, não executa conteúdo encontrado e não altera Defender/firewall. A execução cria arquivos, processos e telemetria. Leia [docs/FORENSIC_IMPACT.md](docs/FORENSIC_IMPACT.md) e [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md).

## Desenvolvimento e testes

```powershell
Invoke-Pester .\Tests\Unit
```

Estrutura e contratos estão documentados em [docs/COLLECTORS.md](docs/COLLECTORS.md) e [docs/OUTPUT_SCHEMA.md](docs/OUTPUT_SCHEMA.md).
