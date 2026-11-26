<#
.SYNOPSIS
  Tests de non-régression du projet SEAL CVE.

.DESCRIPTION
  1. Lecture d'une livraison fictive (sans réseau) : Get-SealCveReport.ps1 -Artefacts … -InventaireSeul sur des exports
     construits pour l'occasion (UTF-16, export vide, licences npm et NuGet, format AutoDetected/Static, binaires C++,
     paquets internes et de test, diagnostic de build) ; vérifie l'inventaire, la couverture et le dépôt (-Depot).
  2. Cohérence des rapports existants (-Rapports) : compteurs du résumé = CSV, mois = date de publication, catégories
     connues, aucun constat en double, CVSS jamais égal à 0, contrôles du moteur au vert.
  Code de sortie = nombre d'échecs.

.EXAMPLE
  .\Tests\Test-SealCve.ps1
.EXAMPLE
  .\Tests\Test-SealCve.ps1 -Rapports 'C:\DC\Applications\SEAL-CVE\Rapports'
#>
[CmdletBinding()]
param([string]$Rapports)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$projet = Split-Path $PSScriptRoot -Parent
if (-not $Rapports) { $Rapports = Join-Path $projet 'Rapports' }
$script:ok = 0; $script:ko = 0
function Verifier([string]$nom, [bool]$condition, [string]$detail = '') {
  if ($condition) { $script:ok++; Write-Host "  OK    $nom" -ForegroundColor Green }
  else { $script:ko++; Write-Host "  ÉCHEC $nom $(if ($detail) { "($detail)" })" -ForegroundColor Red }
}

# =========================================================================================== 1. livraison fictive
Write-Host '== 1. Lecture d''une livraison fictive (sans réseau)'
$tmp = Join-Path $env:TEMP ('seal-cve-test-' + [guid]::NewGuid().ToString('N'))
$liv = Join-Path $tmp 'Livraison'; $dep = Join-Path $tmp 'dep'; $lic = Join-Path $tmp 'lic'
New-Item -ItemType Directory -Force $liv, $dep, $lic | Out-Null
try {
  $utf16 = New-Object Text.UnicodeEncoding($false, $true); $utf8 = New-Object Text.UTF8Encoding($true)
  # graphe NuGet en UTF-16 (comme les exports SEAL) : paquet interne et paquet de test à exclure
  [IO.File]::WriteAllText("$dep\Dependencies.SealToTest.json", '[{"Name":"Seal.Services","Version":"1.0.0","Dependencies":{"Newtonsoft.Json":"12.0.1","xunit":"2.4.1"}},{"Name":"Newtonsoft.Json","Version":"12.0.1","Dependencies":null}]', $utf16)
  [IO.File]::WriteAllText("$dep\Dependencies.Seal.Back.Api.json", '', $utf8)                     # export vide
  [IO.File]::WriteAllText("$dep\Dependencies.Services.Exemple.json", '', $utf8)                  # export vide sans licences dédiées
  [IO.File]::WriteAllText("$dep\Dependencies.AllBinaries.json", "log4cxx.dll, Licence : `"Apache License Version 2`", Version : 1.2.0.0`r`nzlib, Licence : `"zlib license`", Version : 1.2.1.1429`r`nmlins_sec.dll, Licence : `"Propriétaire`", Version : 2.8.216", $utf8)
  [IO.File]::WriteAllText("$lic\Licences.Back.Api.json", '[{"PackageName":"System.Text.Json","PackageVersion":"7.0.3","LicenseType":"MIT"}]', $utf8)
  [IO.File]::WriteAllText("$lic\Licences.SealWebFront.json", '[{"self":true,"name":"seal-front","version":"1.0.0"},{"self":false,"name":"axios","version":"1.11.0","license":"MIT"}]', $utf8)
  [IO.File]::WriteAllText("$lic\Licences.NetBinaries.json", '{"AutoDetectedLicences":[{"PackageName":"Autofac","PackageVersion":"9.1.0","LicenseType":"MIT"}],"StaticLicences":[{"PackageName":"CDK64.dll","PackageVersion":"1.5.1.0","Authors":"Survision"}]}', $utf8)
  [IO.File]::WriteAllText("$lic\SealWebBackProjectVersionMismatch.json", '{"value":[{"PackageName":"log4net","PackageVersion":"2.0.12.0"}]}', $utf8)
  [IO.Compression.ZipFile]::CreateFromDirectory($dep, "$liv\Dependencies.zip"); [IO.Compression.ZipFile]::CreateFromDirectory($lic, "$liv\Licences.zip")
  $sortie = Join-Path $tmp 'Rapports'; $depot = Join-Path $tmp 'Depot'
  $ErrorActionPreference = 'Continue'   # un échec du moteur doit être compté, pas interrompre les tests
  $res = & powershell.exe -NoProfile -NonInteractive -File (Join-Path $projet 'Get-SealCveReport.ps1') -Artefacts $liv -VersionSeal '99.0.12345' -InventaireSeul -Sortie $sortie -Cache (Join-Path $tmp 'Cache') -Depot $depot 2>&1
  $ErrorActionPreference = 'Stop'
  Verifier 'exécution du moteur (-Artefacts -InventaireSeul)' ($LASTEXITCODE -eq 0) ($res | Select-Object -Last 3 | Out-String)
  $invF = Get-ChildItem $sortie -Recurse -Filter 'inventaire.json' | Select-Object -First 1
  Verifier 'inventaire.json produit' ([bool]$invF)
  if ($invF) {
    $inv = Get-Content $invF.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    $c = @($inv.Composants)
    # , @() : une fonction renvoyant un seul objet perd .Count sous PowerShell 5.1
    function A([string]$eco, [string]$nom, [string]$ver) { , @($c | Where-Object { $_.Ecosysteme -eq $eco -and $_.Composant -eq $nom -and (-not $ver -or $_.Version -eq $ver) }) }
    Verifier 'export UTF-16 lu (Newtonsoft.Json 12.0.1)' ((A 'NuGet' 'Newtonsoft.Json' '12.0.1').Count -gt 0)
    Verifier 'paquet interne exclu (Seal.Services)' (-not (A 'NuGet' 'Seal.Services').Count)
    Verifier 'paquet de test exclu (xunit)' (-not (A 'NuGet' 'xunit').Count)
    Verifier 'npm reconnu (axios, « name » ≠ « Name »)' ((A 'npm' 'axios' '1.11.0').Count -gt 0)
    Verifier 'npm « self » exclu' (-not (A 'npm' 'seal-front').Count)
    Verifier 'format AutoDetectedLicences lu (Autofac)' ((A 'NuGet' 'Autofac' '9.1.0').Count -gt 0)
    Verifier 'licence statique = Binaire à confirmer (CDK64)' (@((A 'Binaire' 'CDK64') | Where-Object Identite -eq 'À confirmer').Count -gt 0)
    Verifier 'diagnostic de build exclu (log4net 2.0.12.0)' (-not (A 'NuGet' 'log4net').Count)
    Verifier 'binaires C++ lus (log4cxx, zlib, mlins_sec)' ((A 'Natif' 'log4cxx').Count -and (A 'Natif' 'zlib').Count -and (A 'Natif' 'mlins_sec').Count)
    $vide = @($inv.Exports | Where-Object { $_.Fichier -eq 'Dependencies.Seal.Back.Api.json' })
    Verifier 'export vide détecté' ($vide.Count -and $vide[0].Etat -eq 'Vide')
    Verifier 'couverture partielle par licences dédiées' ($vide.Count -and $vide[0].Couverture -like 'Partielle*Licences.Back.Api.json*')
    $vide2 = @($inv.Exports | Where-Object { $_.Fichier -eq 'Dependencies.Services.Exemple.json' })
    Verifier 'couverture non démontrée sans licences dédiées' ($vide2.Count -and $vide2[0].Couverture -like 'Non démontrée*')
    Verifier 'version SEAL retenue' ($inv.VersionSeal -eq '99.0.12345')
    Verifier 'mode livraison sans hôte' ($inv.Meta.Mode -eq 'Livraison' -and -not $inv.Meta.Hote)
    Verifier 'dépôt de l''inventaire (-Depot)' (@(Get-ChildItem $depot -Recurse -Filter 'inventaire_*.json').Count -eq 1)
  }
} finally { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }

# =========================================================================================== 2. cohérence des rapports
Write-Host "== 2. Cohérence des rapports ($Rapports)"
$cats = 'Dépendance SEAL', 'Environnement', 'À confirmer', 'Corrigée / non applicable'
$dossiers = @(Get-ChildItem $Rapports -Directory -ErrorAction SilentlyContinue | ForEach-Object { Get-ChildItem $_.FullName -Directory | Where-Object { Test-Path (Join-Path $_.FullName 'resume.json') } | Sort-Object Name | Select-Object -Last 1 })
if (-not $dossiers.Count) { Write-Host '  (aucun rapport)' }
foreach ($d in $dossiers) {
  $r = Get-Content (Join-Path $d.FullName 'resume.json') -Raw -Encoding UTF8 | ConvertFrom-Json
  $nom = "$(Split-Path $d.Parent.FullName -Leaf)\$($d.Name)"
  if ("$($r.VersionMoteur)" -notmatch '^3\.') { Write-Host "  --    $nom : moteur $($r.VersionMoteur) ignoré"; continue }
  $l = @(Import-Csv (Join-Path $d.FullName 'cve-detail.csv') -Delimiter ';' -Encoding UTF8)
  $k = @(Import-Csv (Join-Path $d.FullName 'controles.csv') -Delimiter ';' -Encoding UTF8)
  Verifier "$nom : contrôles du moteur" (-not @($k | Where-Object { $_.OK -ne 'True' }).Count)
  Verifier "$nom : total des constats" ($l.Count -eq [int]$r.Constats) "$($l.Count) / $($r.Constats)"
  $ecart = @(foreach ($cat in $cats) { $n = @($l | Where-Object { $_.'Catégorie' -eq $cat }); $cve = @($n.CVE | Where-Object { $_ -like 'CVE-*' } | Sort-Object -Unique).Count; if ($n.Count -ne [int]$r.ParCategorie.$cat.Constats -or $cve -ne [int]$r.ParCategorie.$cat.CVE) { $cat } })
  Verifier "$nom : compteurs par catégorie = CSV" (-not $ecart.Count) ($ecart -join ', ')
  Verifier "$nom : catégories connues" (-not @($l | Where-Object { $_.'Catégorie' -notin $cats }).Count)
  $dup = @($l | Group-Object { "$($_.CVE)|$($_.'Écosystème')|$($_.Composant)|$($_.'Version installée')|$($_.'Périmètre')" } | Where-Object Count -gt 1)
  Verifier "$nom : aucun constat en double" (-not $dup.Count) "$($dup.Count) doublon(s)"
  Verifier "$nom : mois = date de publication" (-not @($l | Where-Object { $_.Mois -ne $_.'Publiée'.Substring(0, 7) }).Count)
  Verifier "$nom : CVSS jamais égal à 0" (-not @($l | Where-Object { $_.CVSS -match '^0([.,]0)?$' }).Count)
  Verifier "$nom : gravité renseignée ou « Non renseignée »" (-not @($l | Where-Object { $_.'Gravité' -notin 'Critique', 'Haute', 'Moyenne', 'Basse', 'Non renseignée' }).Count)
}
Write-Host ("== Résultat : {0} réussi(s), {1} échec(s)" -f $script:ok, $script:ko) -ForegroundColor $(if ($script:ko) { 'Red' } else { 'Green' })
exit $script:ko




# SIG # Begin signature block
# MIIJXQYJKoZIhvcNAQcCoIIJTjCCCUoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAx90Qlr5Y/ZGZy
# pPpkeqiKTQdNWawJdIjHgpEBJNSO5KCCBpIwggaOMIIFdqADAgECAhNVAABq4hV6
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
# DAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgcuEzsqAW3CEF/zlw6I/u/WKs
# 92+G+FAwyj9hqPXLHeIwDQYJKoZIhvcNAQEBBQAEggEAZbU3aJiRJznxTDtjuohj
# J9p9S6R2wRqj6A11Ev/Di1v3hchDyBLlUbZhVoeriGddRl7qqbPjhLX8gLJ6TbiA
# Q4tKuAiERi1tpqRYFbrQjP1xm5ssmdAsQ0M9tZFGiyA5b9HnOyhXjzHnkPussi7N
# Fk6KT41P5VA4wa+keObPa2vdWbFfWTVxzhBpnIImtBcOFJhbBsor3xNDDP/IIlW9
# qoWw0d46e57N6Pv1fex92HjIOfF3QoZ434rYxgGm+JCWBnUczi4d/4X8qJExDhjD
# NUNlpcOVS0aXaDYBbjmaRQPglLMSmY2n30QyUcNvPlswEmbKenxPTxU/yiecmAp7
# Fg==
# SIG # End signature block
