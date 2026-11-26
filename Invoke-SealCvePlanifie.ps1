<#
.SYNOPSIS
  Orchestration planifiée du rapport SEAL CVE sur le contrôleur de domaine (tâches « OMS - SEAL CVE … »).

.DESCRIPTION
  Les serveurs SEAL collectent eux-mêmes leur inventaire chaque jour (tâche locale, compte Système) :
    Get-SealCveReport.ps1 -Installation -InventaireSeul -Depot \\<DC>\OMS-Postes$\SEAL-CVE
  Ce script, sur le DC :
    -Mode Quotidien : analyse chaque nouvel inventaire déposé (CVE, KB .NET Framework via MSRC) et n'envoie un mail
                      d'alerte que si un nouveau constat critique ou exploité (KEV) apparaît (rapport comparable).
    -Mode Hebdo     : génère la synthèse et les annexes PowerPoint du dernier rapport de chaque serveur et les envoie
                      avec un résumé HTML (charte OMS) aux destinataires de planification.json.
  Les inventaires non reçus depuis plus de 48 h et les serveurs désactivés sont signalés dans le mail hebdomadaire.
  Configuration : planification.json (à côté du script). Fichier SUSPENDRE-MAILS présent = aucun mail.

.EXAMPLE
  .\Invoke-SealCvePlanifie.ps1 -Mode Quotidien
.EXAMPLE
  .\Invoke-SealCvePlanifie.ps1 -Mode Hebdo -SansMail      # génère et archive sans envoyer
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('Quotidien', 'Hebdo')][string]$Mode,
  [string]$Config,                             # défaut : planification.json à côté du script
  [switch]$SansMail,
  [string[]]$Destinataires = @()
)
$ErrorActionPreference = 'Stop'
$RacineProjet = $PSScriptRoot
if (-not $Config) { $Config = Join-Path $RacineProjet 'planification.json' }   # $PSScriptRoot est vide dans les valeurs par défaut (PowerShell 5.1)
$cfg = Get-Content $Config -Raw -Encoding UTF8 | ConvertFrom-Json
$Rapports = Join-Path $RacineProjet 'Rapports'; $CacheDir = Join-Path $RacineProjet 'Cache'; $Journaux = Join-Path $RacineProjet 'Journaux'
foreach ($d in $Rapports, $CacheDir, $Journaux) { New-Item -ItemType Directory -Force $d | Out-Null }
$journal = Join-Path $Journaux ("{0}_{1}.log" -f $Mode, (Get-Date -Format 'yyyyMMdd_HHmm'))
function JL([string]$m) { $l = "[{0:yyyy-MM-dd HH:mm:ss}] {1}" -f (Get-Date), $m; Add-Content -Path $journal -Value $l -Encoding UTF8; Write-Host $l }
Get-ChildItem $Journaux -Filter '*.log' | Where-Object LastWriteTime -lt (Get-Date).AddDays(-90) | Remove-Item -Force
$dest = if ($Destinataires.Count) { $Destinataires } else { @($cfg.Destinataires) }
$suspendu = Test-Path (Join-Path $RacineProjet 'SUSPENDRE-MAILS')
$etatF = Join-Path $RacineProjet 'etat.json'
$etat = @{}; if (Test-Path $etatF) { (Get-Content $etatF -Raw -Encoding UTF8 | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $etat[$_.Name] = $_.Value } }
. 'C:\DC\Scripts\_Commun\OMS-ReportCommon.ps1'

# Clé NVD de la veille Dev (DPAPI machine), transmise au moteur par variable d'environnement, jamais écrite
try {
  Add-Type -AssemblyName System.Security
  $f = 'C:\DC\Secrets\Veille-Dev\nvd-api.bin'
  if (Test-Path $f) { $env:NVD_API_KEY = [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($f), [Text.Encoding]::UTF8.GetBytes('OMNITECH-VEILLE-DEV'), 'LocalMachine')).Trim() }
} catch { JL 'clé NVD illisible : analyse sans clé' }

# Exécute un script du projet dans un processus séparé (isolement, journal) ; renvoie la dernière ligne (chemin produit)
function Lancer([string]$script, [string[]]$arguments) {
  $sortie = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File (Join-Path $RacineProjet $script) @arguments 2>&1
  $sortie | ForEach-Object { Add-Content -Path $journal -Value "    $_" -Encoding UTF8 }
  if ($LASTEXITCODE) { throw "$script a échoué (code $LASTEXITCODE)" }
  "$(@($sortie | Where-Object { "$_" -match '^[A-Z]:\\' })[-1])".Trim()
}
function Dernier-Rapport([string]$machine) {
  Get-ChildItem $Rapports -Directory -Filter "SEAL_*_$machine" -ErrorAction SilentlyContinue | ForEach-Object { Get-ChildItem $_.FullName -Directory | Where-Object { Test-Path (Join-Path $_.FullName 'resume.json') } } | Sort-Object Name | Select-Object -Last 1
}
function Lire-Csv([string]$f) { if (Test-Path $f) { @(Import-Csv $f -Delimiter ';' -Encoding UTF8) } else { @() } }

trap { JL "ERREUR : $($_.Exception.Message) $($_.InvocationInfo.PositionMessage -replace '\s+', ' ')"; break }
JL "=== SEAL CVE : passage $Mode ($(if ($SansMail) { 'sans mail' } elseif ($suspendu) { 'mails suspendus' } else { "mail : $($dest -join ', ')" }))"
$etatServeurs = New-Object Collections.Generic.List[object]

foreach ($srv in @($cfg.Serveurs)) {
  $nom = $srv.Nom
  if (-not $srv.Actif) { $etatServeurs.Add([pscustomobject]@{ Serveur = $nom; Etat = "Désactivé : $($srv.Note)"; Rapport = $null }); JL "$nom : désactivé ($($srv.Note))"; continue }
  $depot = Join-Path $cfg.Depot $nom
  $inv = Get-ChildItem $depot -Filter 'inventaire_*.json' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
  if (-not $inv) { $etatServeurs.Add([pscustomobject]@{ Serveur = $nom; Etat = 'Aucun inventaire reçu (tâche de collecte absente ou en échec)'; Rapport = (Dernier-Rapport $nom) }); JL "$nom : aucun inventaire dans $depot"; continue }
  $age = ((Get-Date) - $inv.LastWriteTime).TotalHours
  $etatTxt = if ($age -gt 48) { "Inventaire ancien : dernier reçu le $($inv.LastWriteTime.ToString('dd/MM/yyyy HH:mm'))" } else { "Inventaire du $($inv.LastWriteTime.ToString('dd/MM/yyyy HH:mm'))" }
  # ---- analyse de chaque nouvel inventaire (quotidien ; l'hebdomadaire rattrape un passage manqué)
  if ("$($etat[$nom])" -ne $inv.Name) {
    try {
      JL "$nom : analyse de $($inv.Name)"
      $dossier = Lancer 'Get-SealCveReport.ps1' @('-Inventaire', $inv.FullName, '-Sortie', $Rapports, '-Cache', $CacheDir, '-ConserverJours', "$($cfg.ConserverJours)")
      $etat[$nom] = $inv.Name
      $r = Get-Content (Join-Path $dossier 'resume.json') -Raw -Encoding UTF8 | ConvertFrom-Json
      JL "$nom : SEAL $($r.VersionSeal), dépendances SEAL $($r.ParCategorie.'Dépendance SEAL'.CVE) CVE, environnement $($r.ParCategorie.'Environnement'.Constats) constats, contrôles $(if ($r.ControlesOK) { 'OK' } else { 'EN ÉCHEC' })"
      # ---- alerte quotidienne : nouveau constat critique ou KEV (uniquement si comparable au rapport précédent)
      if ($Mode -eq 'Quotidien' -and $cfg.AlerteQuotidienne -and $r.HistoriqueComparable) {
        $nouv = @(Lire-Csv (Join-Path $dossier 'cve-detail.csv') | Where-Object { $_.Nouveau -eq 'OUI' -and $_.'Catégorie' -in 'Dépendance SEAL', 'Environnement' -and ($_.'Gravité' -eq 'Critique' -or $_.KEV -eq 'OUI') })
        if ($nouv.Count) {
          $corps = New-OmsSection "Nouveaux constats critiques ou exploités ($($nouv.Count))" (New-OmsTable @($nouv | Select-Object CVE, 'Catégorie', 'Gravité', CVSS, KEV, Composant, 'Version installée', 'Version corrigée') @('CVE', 'Catégorie', 'Gravité', 'CVSS', 'KEV', 'Composant', 'Version installée', 'Version corrigée')) 'Détail complet : rapport.html joint.'
          $html = New-OmsReportHtml -Title "SEAL CVE - alerte $nom" -Subtitle "Analyse du $((Get-Date).ToString('dd/MM/yyyy'))" -Status 'CRITIQUE' -Summary "$($nouv.Count) nouveau(x) constat(s) critique(s) ou exploité(s) sur $nom (SEAL $($r.VersionSeal))." -Body $corps -Footer 'SEAL CVE - analyse quotidienne'
          [void](Save-OmsReportArchive "SEAL-CVE_alerte_$nom" $html)
          if (-not $SansMail -and -not $suspendu) { Send-OmsReport -Subject "[SEAL CVE] $nom : $($nouv.Count) nouveau(x) constat(s) critique(s)" -HtmlBody $html -Attachments @(Join-Path $dossier 'rapport.html') -Destinataires $dest -Distribution Immediat; JL "$nom : alerte envoyée" }
        }
      }
    } catch { JL "$nom : ÉCHEC de l'analyse : $($_.Exception.Message)"; $etatTxt += ' · ÉCHEC de la dernière analyse' }
  } else { JL "$nom : inventaire $($inv.Name) déjà analysé" }
  $etatServeurs.Add([pscustomobject]@{ Serveur = $nom; Etat = $etatTxt; Rapport = (Dernier-Rapport $nom) })
}
($etat | ConvertTo-Json) | Set-Content $etatF -Encoding UTF8

# ---- hebdomadaire : présentations + mail récapitulatif
if ($Mode -eq 'Hebdo') {
  $pj = New-Object Collections.Generic.List[string]
  $lignes = New-Object Collections.Generic.List[object]; $sections = ''; $statut = 'OK'
  foreach ($e in $etatServeurs) {
    if (-not $e.Rapport) { $lignes.Add([pscustomobject]@{ Serveur = $e.Serveur; 'Version SEAL' = ''; 'CVE SEAL' = ''; 'Critiques' = ''; 'Environnement' = ''; 'À confirmer' = ''; 'Inventaire' = $e.Etat }); if ($statut -eq 'OK') { $statut = 'ATTENTION' }; continue }
    $d = $e.Rapport.FullName
    $r = Get-Content (Join-Path $d 'resume.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    try { [void](Lancer 'New-SealCvePresentation.ps1' @('-Rapport', $d)); Get-ChildItem $d -Filter '*.pptx' | Sort-Object LastWriteTime -Descending | Select-Object -First 2 | ForEach-Object { $pj.Add($_.FullName) } } catch { JL "$($e.Serveur) : présentation non générée : $($_.Exception.Message)"; $statut = 'ATTENTION' }
    $s = $r.ParCategorie
    $lignes.Add([pscustomobject]@{ Serveur = $e.Serveur; 'Version SEAL' = $r.VersionSeal; 'CVE SEAL' = $s.'Dépendance SEAL'.CVE; 'Critiques' = $s.'Dépendance SEAL'.Critique; 'Environnement' = $s.'Environnement'.Constats; 'À confirmer' = $s.'À confirmer'.Constats; 'Inventaire' = "$($e.Etat)$(if (-not $r.InventaireComplet) { ' · incomplet' })" })
    if ($s.'Dépendance SEAL'.Critique -or $s.'Dépendance SEAL'.KEV -or $s.'Environnement'.KEV) { $statut = 'CRITIQUE' } elseif (($s.'Dépendance SEAL'.Constats -or $s.'Environnement'.Constats) -and $statut -eq 'OK') { $statut = 'ATTENTION' }
    $prio = @(Lire-Csv (Join-Path $d 'inventaire.csv') | Where-Object { $_.'Catégorie' -eq 'Dépendance SEAL' } | Sort-Object @{ e = { @{ 'Critique' = 4; 'Haute' = 3; 'Moyenne' = 2; 'Basse' = 1 }[$_.'Gravité max'] }; Descending = $true }, @{ e = { [int]$_.CVE }; Descending = $true } | Select-Object -First 8)
    $eol = @(Lire-Csv (Join-Path $d 'dotnet.csv') | Where-Object HorsSupport -eq 'OUI')
    $sections += New-OmsSection "$($e.Serveur) : dépendances SEAL à mettre à jour" (New-OmsTable @($prio | Select-Object Composant, Version, CVE, 'Gravité max', 'Version cible', 'Modules SEAL') @('Composant', 'Version', 'CVE', 'Gravité max', 'Version cible', 'Modules SEAL') 'Aucune dépendance SEAL concernée.') "Collecte du $($r.DateCollecte) · analyse du $($r.Genere)$(if ($eol.Count) { " · runtimes .NET hors support : $((@($eol | ForEach-Object { "$($_.Runtime -replace '^Microsoft\.', '') $($_.Version)" }) | Select-Object -Unique) -join ', ')" })"
  }
  $corps = (New-OmsSection 'Synthèse par serveur' (New-OmsTable $lignes.ToArray() @('Serveur', 'Version SEAL', 'CVE SEAL', 'Critiques', 'Environnement', 'À confirmer', 'Inventaire')) 'CVE SEAL : dépendances livrées par SEAL. Environnement : runtimes .NET et .NET Framework du serveur (KB vérifiés via MSRC). Détail : synthèse et annexes PowerPoint jointes.') + $sections
  $html = New-OmsReportHtml -Title 'SEAL CVE - rapport hebdomadaire' -Subtitle "Semaine du $((Get-Date).AddDays(-6).ToString('dd/MM')) au $((Get-Date).ToString('dd/MM/yyyy'))" -Status $statut -Summary "$(@($lignes | Where-Object { $_.'Version SEAL' }).Count) serveur(s) analysé(s) · $(@($etatServeurs | Where-Object { -not $_.Rapport }).Count) sans rapport." -Body $corps -Footer 'SEAL CVE - moteur 3.0 (OSV, NVD, MSRC, CISA KEV)'
  $archive = Save-OmsReportArchive 'SEAL-CVE_hebdo' $html
  JL "Rapport hebdomadaire archivé : $archive ($($pj.Count) pièce(s) jointe(s))"
  if (-not $SansMail -and -not $suspendu) {
    Send-OmsReport -Subject "[SEAL CVE] Rapport hebdomadaire $((Get-Date).ToString('dd/MM/yyyy'))" -HtmlBody $html -Attachments $pj.ToArray() -Destinataires $dest -Distribution Immediat
    JL "Mail envoyé à $($dest -join ', ')"
  } else { JL "Mail non envoyé ($(if ($SansMail) { '-SansMail' } else { 'SUSPENDRE-MAILS' }))" }
}
JL "=== fin du passage $Mode"




# SIG # Begin signature block
# MIIJXQYJKoZIhvcNAQcCoIIJTjCCCUoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDy9XuL7Wmw/IOS
# u43orqEAXBedRLdEmqR2UuLD2CEKVaCCBpIwggaOMIIFdqADAgECAhNVAABq4hV6
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
# DAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgcVhup5cB8WzVNUSyBflVfJC0
# f+zz7pw6Ug36R0zeW04wDQYJKoZIhvcNAQEBBQAEggEAkrAiJlXaCf0+UPx6xX3+
# iWDD1om8YU4h4iO9+MvNlN0MxxM4BC0oyJDK98lUzhhgGdD37LnBAjs/RKlYBcaq
# e33J/g/uCN3/VbVVf+KKSKb9xGPRce5HZMCyVQsNPd4J/9DG76MUrlMmjbm3FMxB
# YmE9K0NboFtYSFNrtp/adRvPsvO3GaOT9LS4/JTmsCXhb8XK+G40Yxd+s9FGZjOT
# CoTlEo1Fw/YnTxn3FE9sJHAhQLpiyTM25KknI//6Wu9lIJUWXIalaVB19ljrBNH/
# 9ypwP+ARXjLIWRK2AOSnoZ0vCds4L7C8gpR5P1VxbABmlVv+Z6h+KnTTImTfFpZk
# Gw==
# SIG # End signature block
