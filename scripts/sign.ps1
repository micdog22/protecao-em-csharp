\
Param(
    [Parameter(Mandatory=$true)][string]$ExePath,
    [string]$CertPfx = "$PSScriptRoot\..\certs\cert.pfx",
    [string]$CertPassword = ""
)
if (!(Test-Path $ExePath)) { Write-Error "Arquivo não encontrado: $ExePath"; exit 1 }

$timestampUrl = "http://timestamp.digicert.com"
& signtool sign /fd SHA256 /td SHA256 /tr $timestampUrl /f $CertPfx /p $CertPassword $ExePath
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "Assinado com sucesso: $ExePath"
