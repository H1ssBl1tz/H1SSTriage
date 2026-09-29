# Guia de interpretação

## 1. Cobertura antes de findings

Abra `00_MANIFEST.json`. Diferencie:

- `Success` + zero registros: coleta executada sem itens;
- `Partial`: há dados, mas a cobertura é incompleta;
- `Failed/Unavailable/Unsupported`: a fonte não sustenta conclusão de ausência;
- `Skipped`: o modo não solicitou a fonte.

## 2. Leia cada finding

- `Severity`: impacto/prioridade se o comportamento for relevante;
- `Confidence`: confiança da correlação;
- `EvidenceStrength`: confirmado, forte, heurístico ou contextual;
- `Signals`: motivos determinísticos;
- `Why`: explicação humana;
- `ValidationSteps`: próximos passos sem alterar evidência.

Path, nome, porta comum ou PowerShell isoladamente não provam legitimidade nem malícia.

## 3. Cruze entidades

Use `EntityId` e `SourceRecordIds` para cruzar processo, rede, serviço, tarefa e persistência. Valide hash/assinatura, owner, parent e tempo. `ParentResolutionStatus=Unresolved`, `Ambiguous` ou `ExitedOrUnavailable` significa que a relação não foi inventada.

## 4. Conclusão adequada

Prefira: “nenhuma regra disparou nas fontes coletadas com sucesso; a coleta foi Partial por X”. Nunca escreva “máquina limpa” com base nesta ferramenta.
