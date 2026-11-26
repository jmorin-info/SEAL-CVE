<#
.SYNOPSIS
  Signe les scripts du projet SEAL CVE avec le certificat de signature de code « ADM - Julien Morin » stocké sur le
  contrôleur de domaine. À lancer après toute modification d'un script (une modification invalide la signature).

.DESCRIPTION
  1. copie les scripts dans un dossier temporaire du serveur de signature (session WinRM) ;
  2. les signe avec le certificat (la clé privée ne quitte pas le serveur) ;
  3. les rapatrie dans un dossier intermédiaire, vérifie la signature, puis remplace les originaux ;
  4. conserve les versions précédentes dans Sauvegardes\signature_<date> et supprime le dossier temporaire distant.
  Aucun mot de passe n'est enregistré : sans -Credential, une fenêtre Windows le demande.

.EXAMPLE
  .\Signer-SealProjet.ps1
.EXAMPLE
  .\Signer-SealProjet.ps1 -Credential (Get-Credential 'SECURITY\adm-jmorin') -Fichiers 'Get-SealCveReport.ps1'
#>
[CmdletBinding()]
param(
  [pscredential]$Credential,
  [string[]]$Fichiers = @('Get-SealCveReport.ps1', 'New-SealCvePresentation.ps1', 'Invoke-SealCvePlanifie.ps1', 'Signer-SealProjet.ps1'),
  [string]$Serveur = 'BX-AD-01-IT-VM',
  [ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$Empreinte = '05D07192E5128A0F3ECB1C94A6279C121B477D28'
)
$ErrorActionPreference = 'Stop'
$projet = $PSScriptRoot
foreach ($f in $Fichiers) {
  $p = Join-Path $projet $f
  if (-not (Test-Path $p)) { throw "Script absent : $f" }
  $err = $null; [void][Management.Automation.Language.Parser]::ParseFile($p, [ref]$null, [ref]$err)
  if ($err.Count) { throw "Syntaxe invalide dans $f (ligne $($err[0].Extent.StartLineNumber)) : $($err[0].Message)" }
}
if (-not $Credential) { $Credential = Get-Credential -Message "Compte autorisé à utiliser le certificat sur $Serveur" }

$session = New-PSSession -ComputerName $Serveur -Credential $Credential
$distant = $null
$local = Join-Path $env:TEMP ('seal-signature-' + [guid]::NewGuid().ToString('N'))
try {
  $distant = Invoke-Command -Session $session { $t = Join-Path $env:TEMP ('seal-signature-' + [guid]::NewGuid().ToString('N')); New-Item -ItemType Directory $t | Out-Null; $t }
  foreach ($f in $Fichiers) { Copy-Item (Join-Path $projet $f) -Destination $distant -ToSession $session }
  $etats = Invoke-Command -Session $session -ArgumentList $distant, $Empreinte {
    param($dossier, $empreinte)
    $cert = Get-Item "Cert:\CurrentUser\My\$empreinte"
    if (-not $cert.HasPrivateKey -or $cert.NotAfter -le (Get-Date)) { throw 'Certificat absent, expiré ou sans clé privée.' }
    Get-ChildItem $dossier -Filter *.ps1 | ForEach-Object { $s = Set-AuthenticodeSignature -FilePath $_.FullName -Certificate $cert -HashAlgorithm SHA256; "$($_.Name)|$($s.Status)" }
  }
  $echecs = @($etats | Where-Object { $_ -notlike '*|Valid' }); if ($echecs.Count) { throw "Signature refusée : $($echecs -join ', ')" }
  New-Item -ItemType Directory $local | Out-Null
  foreach ($f in $Fichiers) { Copy-Item (Join-Path $distant $f) -Destination $local -FromSession $session }
  foreach ($f in $Fichiers) { $s = Get-AuthenticodeSignature (Join-Path $local $f); if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Thumbprint -ne $Empreinte) { throw "Signature invalide après transfert : $f ($($s.Status))" } }
  $sauvegarde = Join-Path $projet ('Sauvegardes\signature_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
  New-Item -ItemType Directory -Force $sauvegarde | Out-Null
  foreach ($f in $Fichiers) { Copy-Item (Join-Path $projet $f) -Destination $sauvegarde; Copy-Item (Join-Path $local $f) -Destination (Join-Path $projet $f) -Force }
  foreach ($f in $Fichiers) { $s = Get-AuthenticodeSignature (Join-Path $projet $f); Write-Host ('{0,-32} {1}' -f $f, $s.Status) }
  Write-Host "Versions précédentes : $sauvegarde"
}
finally {
  if ($distant) { Invoke-Command -Session $session -ArgumentList $distant { param($d) Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue } }
  Remove-PSSession $session
  if (Test-Path $local) { Remove-Item $local -Recurse -Force }
}


# SIG # Begin signature block
# MIIJXQYJKoZIhvcNAQcCoIIJTjCCCUoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDyGpJ31rUeSEfy
# fPH4FbS+TOvwIYGHT07+4CZgQzHgdaCCBpIwggaOMIIFdqADAgECAhNVAABq4hV6
# 9PdbzYf+AAAAAGriMA0GCSqGSIb3DQEBCwUAMFgxGDAWBgoJkiaJk/IsZAEZFghz
# ZWN1cml0eTEYMBYGCgmSJomT8ixkARkWCG9tbml0ZWNoMSIwIAYDVQQDExlSb290
# IENBIE9NTklURUNIIFNFQ1VSSVRZMB4XDTI2MDcwMjA5MjkxNloXDTI4MDcwMjA5
# MzkxNlowgZMxGDAWBgoJkiaJk/IsZAEZFghzZWN1cml0eTEYMBYGCgmSJomT8ixk
# ARkWCG9tbml0ZWNoMRMwEQYDVQQLEwpFbnRyZXByaXNlMREwDwYDVQQLDAhfU3Vw
# cG9ydDEYMBYGA1UECxMPQWRtaW5pc3RyYXRldXJzMRswGQYDVQQDExJBRE0gLSBK
# dWxpZW4gTW9yaW4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDNTqiC
# lleDYCFP6Sh1zjPVLnqURBY41S5OOewZpUzVfQYHJZNSq+KNqn/hS8qtUY5ax+rO
# 0+HP48us+mlnpvzPhBkD/dk+/Yey/dl3fXirZTc2QKmI5bj0Tsjek3KYZcWWkY0A
# 04kpiWA6gC4bNA0FuzbKz+8ynQ0TO21nsh+bu2dPOrWty1fjqPSX0ZluDVc4LtYu
# j2xbvRwtpqC0MMXXKxA7dV1kXCr34oVBlZSM0X6bPeZeqKYqaHMsmiFMsDUQjShS
# Jw1MUR7/ZyDjYSnvcJJsttm9h0Z/xA93QCS5f5Nq978UO3ftW3SzrXFuMyuXF03G
# j4D/NqXlZvXX3yMVAgMBAAGjggMTMIIDDzA7BgkrBgEEAYI3FQcELjAsBiQrBgEE
# AYI3FQiEmaUi/qY4hYGLPcfRJ4ecwxpOhLzfD4G1nnoCAWQCAQcwEwYDVR0lBAww
# CgYIKwYBBQUHAwMwDgYDVR0PAQH/BAQDAgeAMBsGCSsGAQQBgjcVCgQOMAwwCgYI
# KwYBBQUHAwMwHQYDVR0OBBYEFAHDPsIfDPh14t17u3NDI5fAWnLTMB8GA1UdIwQY
# MBaAFBOYCxQt4bufkHK3BbNmR+LwopFkMIHmBgNVHR8Egd4wgdswgdiggdWggdKG
# gc9sZGFwOi8vL0NOPVJvb3QlMjBDQSUyME9NTklURUNIJTIwU0VDVVJJVFksQ049
# QlgtUEtJMjAyMixDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049
# U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1vbW5pdGVjaCxEQz1zZWN1cml0
# eT9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JM
# RGlzdHJpYnV0aW9uUG9pbnQwgdcGCCsGAQUFBwEBBIHKMIHHMIHEBggrBgEFBQcw
# AoaBt2xkYXA6Ly8vQ049Um9vdCUyMENBJTIwT01OSVRFQ0glMjBTRUNVUklUWSxD
# Tj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049
# Q29uZmlndXJhdGlvbixEQz1vbW5pdGVjaCxEQz1zZWN1cml0eT9jQUNlcnRpZmlj
# YXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTA6BgNV
# HREEMzAxoC8GCisGAQQBgjcUAgOgIQwfYWRtLWptb3JpbkBvbW5pdGVjaC1zZWN1
# cml0eS5mcjBPBgkrBgEEAYI3GQIEQjBAoD4GCisGAQQBgjcZAgGgMAQuUy0xLTUt
# MjEtMjc1MDQyNjIxNy0yNjk4ODQzMjYzLTM3ODA2MjE2MzktODA3NjANBgkqhkiG
# 9w0BAQsFAAOCAQEACT/VUUQAY2SvufHwXu2DQmQSzO5KaKYG0FThiARAKZeArg4m
# a2/I9/OqMdgMzqxSW1ipXJ+Z6cHs+VNSSnuZrmS8rr3WvLkvp0xs10sZLSQZ1Su5
# kQJCx8Czph9x/QXvS/CXaGvKGPFqoWK4M4L13FD3f7aXOoILpPT75odytPJQeAcL
# KCaYPrMV0fOfSr70eSKDGFZlBxuNI/1zjkQ5nPl4CzkOZ9y623nKvwPZyiMwZ+kT
# DNsshhkIDyJLftVmMDsuf3bM8kETqJDfGIOu+v7gLqFjooXVixty3alACVl9+4hH
# RMS+6vh5pwcc/5lqw5KnzrtGnCs7XorbHFV32zGCAiEwggIdAgEBMG8wWDEYMBYG
# CgmSJomT8ixkARkWCHNlY3VyaXR5MRgwFgYKCZImiZPyLGQBGRYIb21uaXRlY2gx
# IjAgBgNVBAMTGVJvb3QgQ0EgT01OSVRFQ0ggU0VDVVJJVFkCE1UAAGriFXr091vN
# h/4AAAAAauIwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAA
# oQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4w
# DAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgLqABHrMd7lvGD8KSF0Zp1pBK
# CEetfRhWqeo2R+C+jAswDQYJKoZIhvcNAQEBBQAEggEADVBMvWxuIFc3xPmlOwdx
# elrKlCtr5bA8RaLlHQJh/sFBGsL7zSwbu13DI0pXkxP+YlbL0wlRiebK38BwkAMG
# aLLMulEGx5G3YLJLkQG1oaYTnQKNeNCosNWbc2C0Uk1LX5WxSyIWRY86gSlKPM+y
# NHIKAVdtL1oTptNsvwfhuNJxoGniUyOM+yO8pwlgGOnq6yPKA/XaQcTTL+ngXAz/
# yXmmo7w2gmUJKknLtdR4W6GYnsItZ9Z75uXf5y88dA8zl/b/nvkBoxJJKiLOvqde
# G2bcEDHBRrgU4gW452IjNWWBuHQhoTXnaFrYcoC02OBjayoXrnpBq8OFJmcuqtf3
# xg==
# SIG # End signature block
