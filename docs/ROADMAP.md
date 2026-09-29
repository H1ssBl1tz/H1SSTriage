# Roadmap

## Próximo patch

- ampliar fixtures e testes de mocks de cmdlets indisponíveis/acesso negado;
- validar Windows 10 e versões suportadas de Windows Server;
- melhorar parser de command lines de serviço além das extensões comuns;
- coletar Registry View 32/64 explicitamente via API .NET;
- melhorar timeout/cancelamento de CIM e Event Logs.

## Próxima versão menor

- firewall, sessões e shares em módulos opcionais;
- baseline/suppressions configuráveis e auditáveis;
- JSONL para eventos de alto volume;
- comparação entre duas coletas.

## Fora de escopo

- credential dumping, LSASS, token theft;
- execução de payload, exploit, evasão ou criação de persistência;
- remoção automática de malware;
- alteração de Defender/firewall;
- promessa de resistência a rootkit/kernel tampering.
