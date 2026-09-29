# Estrutura dos relatórios

Cada execução cria um diretório exclusivo:

```text
triage_YYYY-MM-DD_HH-mm-ss-fff_RUNID
```

Arquivos principais:

| Arquivo | Uso |
|---|---|
| `00_MANIFEST.json` | proveniência, status, cobertura e hashes |
| `00_MANIFEST.sha256` | hash do manifesto |
| `00_SUMARIO.txt` | resumo humano e limitações |
| `findings.json` | findings estruturados |
| `processes.json` | processos, owner, metadata e parent correlacionado por tempo |
| `services.json` | serviços, executável e ServiceDll com metadata separado |
| `network.json` | configuração, sockets e DNS |
| `scheduled_tasks.json` | todas as tarefas, actions/triggers, XML e enrichment por action |
| `persistence.json` | Run keys, Startup e persistência avançada |
| `events.json` | eventos da janela selecionada |
| `defender.json` | estado, preferências e detecções disponíveis |

Os CSVs `01_...` a `19_...` foram preservados. `12_tarefas_agendadas_ativas.csv` mantém o nome legado, mas agora contém tarefas habilitadas e desabilitadas; consulte a coluna `Enabled`.

Arquivos vazios podem conter somente BOM/quebra de linha. O estado da fonte está no manifesto; não inferir falha ou ausência somente pelo tamanho do CSV.

No conjunto de outputs atual, `outputFiles[]` registra 38 arquivos de relatório. O diretório contém 40 arquivos físicos: os 38 registrados, `00_MANIFEST.json` e `00_MANIFEST.sha256`. O manifesto e seu sidecar não podem ser autorreferenciados em `outputFiles[]`. A validação de integração compara nomes, existência, tamanho e SHA-256, em vez de depender apenas desses números.
