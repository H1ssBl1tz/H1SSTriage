# Exemplo de análise sem dados reais

```text
overallStatus: Partial
Processes: Success, 142 registros
Services: Success, 318 registros
ScheduledTasks: Failed, AccessDenied
```

Conclusão correta:

> Processos e serviços foram coletados; Scheduled Tasks não foram avaliadas. Dois findings heurísticos exigem validação. A ausência de finding de tarefa não pode ser interpretada como ausência de persistência.

Exemplo de finding:

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
    "PROC.EXTERNAL_CONNECTION",
    "PROC.PERSISTENCE_REFERENCE"
  ],
  "ValidationSteps": [
    "Confirmar caminho e assinatura em fonte confiável.",
    "Revisar parent/child e command line.",
    "Correlacionar com rede, persistência e eventos."
  ]
}
```
