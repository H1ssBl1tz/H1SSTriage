# Fixtures

Os testes unitários usam objetos PowerShell inertes que representam processos, tarefas,
serviços, persistências e conexões. Nenhum fixture executa comandos encontrados, cria
persistência ou altera configuração de segurança.

Os cenários cobrem resultado vazio, falha, caminhos especiais, CSV injection, IP público,
privado, loopback, CGNAT, IPv4-mapped IPv6, tarefa Microsoft mascarada, PowerShell legítimo,
PowerShell com sinais correlacionados, serviço quoted/unquoted e conexão administrativa interna.

Sprint 2 adiciona fixtures inertes para trust por atributos, Microsoft task legítima/mascarada,
task Disabled, múltiplas actions/triggers, Temp/AppData legítimos, browser em 443, SMB/RDP,
processo unsigned correlacionado com rede/persistência e ADSI Local/Domain/BuiltIn/Unknown.

Sprint 2.1 adiciona fixtures do fluxo raw task → detection enrichment → rules, metadata trusted
e unsigned, falha de enrichment `Partial`, separação entre `SHA256` e `HashKnown`, contrato global
de Score e distinção operacional entre endereço privado, CGNAT e público.

Sprint 3 adiciona fixtures para metadata existente/ausente/inacessível, assinatura válida/unsigned,
cache por path normalizado, owner/SID, árvore normal e PID reuse, serviço com executável e ServiceDll
separados, falha de ACL, tasks Disabled com múltiplas actions/triggers/XML e hashing seletivo dirigido
por findings e `SourceRecordIds`.
