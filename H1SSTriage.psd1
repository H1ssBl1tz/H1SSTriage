@{
    RootModule        = 'H1SSTriage.psm1'
    ModuleVersion     = '9.1.0'
    GUID              = 'fbbf19cd-2bb7-48c0-98f4-e91e3b94f78f'
    Author            = 'H1SS'
    CompanyName       = 'H1SS'
    Copyright         = '(c) H1SS. Defensive use only.'
    Description       = 'Windows live-response and triage collection with explicit collector status, integrity metadata, and explainable findings.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-H1SSTriage')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags = @('Windows', 'BlueTeam', 'DFIR', 'IncidentResponse', 'Triage')
        }
    }
}
