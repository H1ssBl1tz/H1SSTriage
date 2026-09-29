# Forensic Impact

H1SSTriage é live response e modifica o ambiente observado de maneiras esperadas:

- cria processo PowerShell e carrega módulos;
- cria diretório, JSON, CSV, TXT e hashes;
- gera MFT/USN/timestamps no volume de output;
- pode gerar PowerShell logs, WMI activity e telemetria EDR/Defender;
- pode criar Prefetch/Amcache e atividade de providers;
- altera naturalmente CPU, memória, processos e timing das conexões.

Minimização recomendada:

- verificar hash do pacote antes de executar;
- usar `powershell.exe -NoProfile`, `-NoMenu` e uma única execução;
- preferir mídia externa controlada ou share IR protegido;
- evitar menu de exclusão durante incidente;
- preservar `00_MANIFEST.json` e `00_MANIFEST.sha256` junto dos outputs;
- usar aquisição de memória/disco e ferramentas offline quando necessárias.

Os hashes fornecem metadata de integridade, não cadeia de custódia formal.
