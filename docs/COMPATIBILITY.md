# Compatibility Matrix

| Plataforma | Categoria | Evidência desta entrega |
|---|---|---|
| Windows 10 + Windows PowerShell 5.1 | Tested em sandbox | 69 testes Pester e Quick/Standard/Deep; manifestos, enrichment, finding model, score e hashes válidos; fontes protegidas retornaram `Partial`/`Failed` |
| Windows 10 + PowerShell 7.6.5 | Tested parcialmente em sandbox | 69 testes Pester e Quick; manifesto, enrichment, finding model, score e hashes válidos; fontes protegidas retornaram `Partial`/`Failed` |
| Windows 11 | Evidência anterior, não revalidada | não executado no fechamento Sprint 1.1 |
| Windows Server | Expected to work | módulos/logs variam; não testado nesta entrega |
| PowerShell < 5.1 | Unsupported | `#requires -Version 5.1` |
| PowerShell 32-bit em Windows 64-bit | Expected to work parcialmente | aviso/bitness no manifesto; Registry View pode divergir |
| Linux/macOS | Unsupported | coletores dependem de Windows |

“Supported” só deverá ser usado após CI/laboratório cobrir a combinação regularmente.
