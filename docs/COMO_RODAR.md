# Como rodar

## Antes de executar

1. Obtenha o pacote por canal confiável.
2. Verifique o SHA-256 publicado antes de usar `Unblock-File` ou bypass de ExecutionPolicy.
3. Prefira PowerShell 64-bit com `-NoProfile`.
4. Durante incidente, prefira output em mídia externa controlada ou share IR protegido.
5. Execute uma única vez quando isso for suficiente.

## Execução sem menu

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\H1SSTriage.ps1 `
  -OutputPath E:\IR `
  -NoMenu `
  -Mode Standard
```

## Execução com menu

```powershell
.\H1SSTriage.ps1 -OutputPath E:\IR -Mode Quick
```

Admin não é obrigatório. Sem elevação, alguns coletores podem ficar `Partial`, `Failed` ou `Unavailable`; isso aparecerá no manifesto. Não repita automaticamente a coleta: avalie o impacto operacional.

Abra primeiro `00_MANIFEST.json`. `Complete` exige `Success` em todos os coletores obrigatórios.
