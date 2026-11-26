<#
.SYNOPSIS
  Inventaire des dépendances d'une version de SEAL et rapport des CVE associées, classées par mois (CSV, JSON, HTML,
  PowerPoint en option). Moteur 3.0.

.DESCRIPTION
  Sources d'inventaire :
    -Artefacts    : dossier de livraison (Dependencies.zip / Licences.zip, directs ou dans *_artifacts.zip).
    -Installation : serveur ou poste SEAL (découverte automatique sur tous les disques, services, IIS, registre ;
                    ou -RacineInstallation pour imposer les chemins). -InventaireSeul : collecte sans Internet.
    -Inventaire   : réanalyse d'un inventaire.json produit hors ligne.
    -Consolider   : regroupe le dernier rapport de chaque version / source.

  Règles d'analyse (identiques pour toutes les versions, voir README.md) :
    Périmètre   SEAL = dépendances livrées ou déployées par SEAL ; Environnement = runtimes .NET et .NET Framework de l'hôte.
    Catégories  1. Dépendance SEAL      : composant SEAL d'identité exacte associé à un avis publié pour sa version.
                2. Environnement        : runtime .NET de l'hôte, ou CVE .NET Framework dont le KB requis est absent.
                3. À confirmer          : identité ou applicabilité non démontrée (version de fichier, KB non vérifiable…).
                4. Non couvert          : composant sans référentiel public exploitable (inventaire uniquement).
                Les CVE .NET Framework corrigées par un KB installé ou non applicables à l'OS sont listées à part
                (catégorie « Corrigée / non applicable ») et ne sont pas comptées comme ouvertes.
    Constat     = une CVE (ou un avis sans CVE) × un composant × une version.
    CVSS        : inconnu = « Non renseigné » (jamais 0) ; la gravité vient alors de l'avis (GitHub).

  Sources : OSV.dev (NuGet, npm, runtimes .NET), NVD (bibliothèques C++, .NET Framework), MSRC (KB .NET Framework),
  CISA KEV, endoflife.date. Clé NVD facultative : -NvdApiKey ou variable NVD_API_KEY.
  Compatible Windows PowerShell 5.1 et PowerShell 7. Script signé : toute modification impose de le re-signer.

.EXAMPLE
  .\Get-SealCveReport.ps1 -Artefacts 'C:\SEAL\Livraison\45.0' -Presentation
.EXAMPLE
  .\Get-SealCveReport.ps1 -Installation -InventaireSeul           # sur un serveur sans Internet
  .\Get-SealCveReport.ps1 -Inventaire '.\inventaire.json' -Presentation
.EXAMPLE
  .\Get-SealCveReport.ps1 -Consolider
.EXAMPLE
  # tâche planifiée d'un serveur SEAL : collecte seule et dépôt sur le partage de collecte du DC
  .\Get-SealCveReport.ps1 -Installation -InventaireSeul -Depot '\\BX-AD-01-IT-VM\OMS-Postes$\SEAL-CVE' -ConserverJours 30
#>
[CmdletBinding(DefaultParameterSetName = 'Installation')]
param(
  [Parameter(ParameterSetName = 'Installation')][switch]$Installation,
  [Parameter(ParameterSetName = 'Installation')][string[]]$RacineInstallation = @(),
  [Parameter(ParameterSetName = 'Installation')][string[]]$DossiersSupplementaires = @(),
  [Parameter(ParameterSetName = 'Installation')][switch]$InventaireSeul,
  [Parameter(ParameterSetName = 'Artefacts', Mandatory)][string]$Artefacts,
  [Parameter(ParameterSetName = 'Inventaire', Mandatory)][string]$Inventaire,
  [Parameter(ParameterSetName = 'Consolider', Mandatory)][switch]$Consolider,
  [string]$VersionSeal,
  [string[]]$Runtimes = @(),                   # « Microsoft.NETCore.App 8.0.32 » : runtimes relevés à part (déclaration)
  [string]$NetFramework,                       # « 4.8.03761 » : déclaration (sans KB : CVE « À confirmer »)
  [switch]$InclureTests,
  [switch]$Presentation,
  [string]$Sortie,
  [string]$Cache,
  [string]$NvdApiKey,
  [string]$Depot,                              # copie l'inventaire.json dans <Depot>\<MACHINE>\ (collecte planifiée vers le DC)
  [int]$ConserverJours = 0,                    # supprime les rapports datés plus anciens (0 = tout conserver)
  [string]$MotifDossiers = '^(SEAL|Omnitech)',
  [switch]$SansRechercheDisques,
  [string]$ExclureDossiers = '\\(SealInstaller|Backups?|Updates?|Tmp|Temp|Installation|Logs?|Sauvegardes|Rapports|Cache)\\'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression.FileSystem
$MoteurVersion = '3.0'
trap { Write-Host "ERREUR : $($_.Exception.Message)" -ForegroundColor Red; Write-Host $_.ScriptStackTrace; break }
if (-not $Sortie) { $Sortie = Join-Path $PSScriptRoot 'Rapports' }
if (-not $Cache) { $Cache = Join-Path $PSScriptRoot 'Cache' }
foreach ($d in $Sortie, $Cache, "$Cache\osv", "$Cache\nvd", "$Cache\msrc") { New-Item -ItemType Directory -Force $d | Out-Null }
$CultureFr = [Globalization.CultureInfo]::GetCultureInfo('fr-FR')
$Invariant = [Globalization.CultureInfo]::InvariantCulture

# ============================================================================================ outils
function Log([string]$m) { Write-Host ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $m) }
function Lire-Texte([string]$f) { [IO.File]::ReadAllText($f) }   # détecte la BOM (exports SEAL en UTF-16)
function Lire-JsonFichier([string]$f) { $t = Lire-Texte $f; if ($t.Trim().Length -eq 0) { return $null }; $t | ConvertFrom-Json }
function Ecrire-Json([string]$f, $o) { [IO.File]::WriteAllText($f, (ConvertTo-Json -InputObject $o -Depth 20), [Text.UTF8Encoding]::new($false)) }
function Age-Heures([string]$f) { if (Test-Path -LiteralPath $f) { ((Get-Date) - (Get-Item -LiteralPath $f).LastWriteTime).TotalHours } else { [double]::MaxValue } }
function Nom-Fichier([string]$s) { $s -replace '[:\\/*?"<>|\s'']', '_' }
function Version-Propre([string]$v) { $m = [regex]::Match("$v", '\d+(\.\d+){0,3}'); if ($m.Success) { $m.Value } else { '' } }
function Cle-Version([string]$v) { $p = @((Version-Propre $v).Split('.') | Where-Object { $_ -ne '' }); while ($p.Count -lt 4) { $p += '0' }; try { [version](($p[0..3]) -join '.') } catch { [version]'0.0.0.0' } }
function Comparer-Version([string]$a, [string]$b) { $x = Cle-Version $a; $y = Cle-Version $b; if ($x -lt $y) { -1 } elseif ($x -gt $y) { 1 } else { 0 } }
function Nombre($v) { $r = 0.0; if ([double]::TryParse(("$v" -replace ',', '.'), [Globalization.NumberStyles]::Float, $Invariant, [ref]$r)) { $r } else { $null } }
function Score-Cvss3([string]$vec) {
  if ($vec -notmatch '^CVSS:3\.[01]/') { return $null }
  $v = @{}; foreach ($p in $vec.Split('/') | Select-Object -Skip 1) { $k, $x = $p.Split(':'); $v[$k] = $x }
  $sc = $v['S'] -eq 'C'
  $av = @{ N = 0.85; A = 0.62; L = 0.55; P = 0.2 }[$v['AV']]; $ac = @{ L = 0.77; H = 0.44 }[$v['AC']]; $ui = @{ N = 0.85; R = 0.62 }[$v['UI']]
  $pr = if ($sc) { @{ N = 0.85; L = 0.68; H = 0.5 }[$v['PR']] } else { @{ N = 0.85; L = 0.62; H = 0.27 }[$v['PR']] }
  $cia = @{ H = 0.56; L = 0.22; N = 0 }
  if ($null -in $av, $ac, $ui, $pr) { return $null }
  $iss = 1 - (1 - $cia[$v['C']]) * (1 - $cia[$v['I']]) * (1 - $cia[$v['A']])
  $imp = if ($sc) { 7.52 * ($iss - 0.029) - 3.25 * [math]::Pow($iss - 0.02, 15) } else { 6.42 * $iss }
  if ($imp -le 0) { return 0.0 }
  $ex = 8.22 * $av * $ac * $pr * $ui
  $b = if ($sc) { [math]::Min(1.08 * ($imp + $ex), 10) } else { [math]::Min($imp + $ex, 10) }
  [math]::Ceiling($b * 10 - 1e-9) / 10
}
# Gravité : depuis le score CVSS s'il est connu, sinon depuis la gravité publiée par l'avis (GitHub : LOW/MODERATE/HIGH/CRITICAL)
function Gravite($score, [string]$txt) {
  if ($null -ne $score -and $score -gt 0) { if ($score -ge 9) { return 'Critique' } elseif ($score -ge 7) { return 'Haute' } elseif ($score -ge 4) { return 'Moyenne' } else { return 'Basse' } }
  switch -Regex ($txt) { 'CRITICAL' { 'Critique' } 'HIGH' { 'Haute' } 'MODERATE|MEDIUM' { 'Moyenne' } 'LOW' { 'Basse' } default { 'Non renseignée' } }
}
$RangGravite = @{ 'Critique' = 4; 'Haute' = 3; 'Moyenne' = 2; 'Basse' = 1; 'Non renseignée' = 0 }
function Texte-Cvss($s) { if ($null -eq $s -or "$s" -eq '') { '' } else { ([double]$s).ToString('0.0', $Invariant) } }

# ============================================================================================ référentiels
$PrefixesInternes = '^(Seal|Agrid|Traka|Common|Resources|SealTo|LapiRemoteControl|RelayApbSeal|SealAdSync|SealJobManager|BillboardTranslation|SendAxisLoudspeaker|Omnitech|Mlins|DomBox|STDDiff|ObjectTestsManager)(\.|$)'
$PaquetsTests = '^(xunit|xunit\..*|Moq|NUnit.*|MSTest\..*|FluentAssertions|AwesomeAssertions|coverlet\..*|Microsoft\.NET\.Test\.Sdk|Microsoft\.TestPlatform\..*|Microsoft\.CodeCoverage|AutoFixture.*|NSubstitute|Shouldly|Bogus|vitest|@vitest/.*|jest|@testing-library/.*)$'
# Bibliothèques C++ : nom -> CPE NVD. Les autres binaires natifs n'ont pas de référentiel CVE public : « Non couvert ».
$CpeNatifs = [ordered]@{ 'log4cxx' = 'apache:log4cxx'; 'boost' = 'boost:boost'; 'zlib' = 'zlib:zlib'; 'tinyxml' = 'tinyxml_project:tinyxml' }
$NonCouverts = @{ 'msado15' = 'Composant Windows (corrigé par Windows Update)'; 'winhttp' = 'Composant Windows (corrigé par Windows Update)'
  'mlins_xfr' = 'Propriétaire Omnitech'; 'mlins_dba' = 'Propriétaire Omnitech'; 'mlins_sec' = 'Propriétaire Omnitech'; 'mlins_utl' = 'Propriétaire Omnitech'
  'hwgapi' = 'Éditeur HW group : pas de référentiel CVE public'; 'SDK UltraView' = 'Éditeur UTC Fire & Security : pas de référentiel CVE public' }
$PaquetsRuntime = @{ 'Microsoft.NETCore.App' = 'Microsoft.NETCore.App.Runtime.win-x64'; 'Microsoft.AspNetCore.App' = 'Microsoft.AspNetCore.App.Runtime.win-x64'; 'Microsoft.WindowsDesktop.App' = 'Microsoft.WindowsDesktop.App.Runtime.win-x64' }

# ============================================================================================ collecte
$Inv = New-Object Collections.Generic.List[object]          # entrées d'inventaire (une par preuve)
$Exports = New-Object Collections.Generic.List[object]      # exports Dependencies / Licences lus, vides ou invalides
$Diagnostics = New-Object Collections.Generic.List[object]
$RuntimesRequis = New-Object Collections.Generic.List[object]   # exigences runtimeconfig.json des applications SEAL
function Diag([string]$niveau, [string]$source, [string]$message) {
  $Diagnostics.Add([pscustomobject]@{ Niveau = $niveau; Source = $source; Message = $message })
  if ($niveau -ne 'Information') { Log "  $niveau : $message" }
}
# Identite : « Exacte » (manifeste / export de paquets) ou « À confirmer » (version de fichier, ProductVersion…)
function Ajouter {
  param([string]$Eco, [string]$Nom, [string]$Ver, [string]$Module, [string]$Perimetre = 'SEAL', [string]$Identite = 'Exacte',
    [string]$Methode = '', [string]$Fichier = '', [string]$Licence = '', [string]$Note = '')
  if (-not $Nom -or -not $Ver -or $Ver -eq 'notDefined') { return }
  $Nom = $Nom.Trim(); $Ver = "$Ver".Trim()
  if ($Eco -eq 'NuGet' -and $Nom -match $PrefixesInternes) { return }
  if ($Eco -in 'NuGet', 'npm' -and -not $InclureTests -and $Nom -match $PaquetsTests) { return }
  $Inv.Add([pscustomobject]@{ Ecosysteme = $Eco; Composant = $Nom; Version = $Ver; Perimetre = $Perimetre; Identite = $Identite; Source = $Module; Methode = $Methode; Fichier = $Fichier; Licence = $Licence; Note = $Note })
}

# ---- exports Dependencies / Licences (livraison, ou livrés avec l'installation)
function Lire-ExportsSeal([string]$dossier, [switch]$Filtrer) {
  foreach ($f in Get-ChildItem $dossier -Recurse -File -Include 'Dependencies*.json', 'Dependencies*.txt', 'Licen[cs]es*.json', 'Licen[cs]es*.txt', 'SealWebBack*.json' -ErrorAction SilentlyContinue | Where-Object { -not $Filtrer -or $_.FullName -notmatch $ExclureDossiers }) {
    if ($f.Name -match 'VersionMismatch|UnreferencedLicences') { continue }   # diagnostics de build : versions d'assembly, pas de paquet
    $type = if ($f.Name -like 'Dependencies*') { 'Dependencies' } else { 'Licences' }
    $module = $f.BaseName -replace '^(Dependencies|Licen[cs]es)\.?', ''; if (-not $module) { $module = $f.BaseName }
    $avant = $Inv.Count
    $etat = 'Lu'
    $t = Lire-Texte $f.FullName
    if (-not $t.Trim() -or $t.Trim() -eq 'null' -or $t.Trim() -eq '[]') { $etat = 'Vide' }
    elseif ($f.Name -match 'AllBinaries') {
      foreach ($l in $t -split "`r?`n" | Where-Object { $_.Trim() }) {
        $nom = (($l.Split(',')[0]).Trim()) -replace '\.(dll|lib)$', ''
        $ver = if ($l -match 'Version\s*:\s*([\d\.]+)') { $Matches[1] } else { '' }
        $lic = if ($l -match 'Licence\s*:\s*"?([^",]+)"?') { $Matches[1].Trim() } else { '' }
        Ajouter -Eco 'Natif' -Nom $nom -Ver $ver -Module 'Binaires C++' -Methode 'Export binaires' -Fichier $f.Name -Licence $lic
      }
    }
    elseif ($f.Name -match 'NugetsSealWeb') {
      foreach ($m in [regex]::Matches($t, 'Dependencies for NuGet package:\s*(\S+?)\.(\d+(?:\.\d+){1,3}(?:-[\w\.]+)?)\s')) { Ajouter -Eco 'NuGet' -Nom $m.Groups[1].Value -Ver $m.Groups[2].Value -Module 'SealWeb' -Methode 'Graphe NuGet' -Fichier $f.Name }
    }
    elseif ($f.Extension -eq '.txt') {   # LWRC : « log4net.dll, Version : 2.0.9 » ou « PackageName: log4net, PackageVersion : 2.0.9, … »
      foreach ($l in $t -split "`r?`n" | Where-Object { $_.Trim() }) {
        if ($l -match 'PackageName:\s*([^,]+),\s*PackageVersion\s*:\s*([^,\s]+)') { Ajouter -Eco 'NuGet' -Nom $Matches[1] -Ver $Matches[2] -Module $module -Methode 'Export licences' -Fichier $f.Name -Licence $(if ($l -match 'LicenseType\s*:\s*(\S+)') { $Matches[1] }) }
        elseif ($l -match '^\s*([\w\.\-]+?)(\.dll)?,\s*Version\s*:\s*([\d\.]+)') { Ajouter -Eco 'NuGet' -Nom $Matches[1] -Ver $Matches[3] -Module $module -Methode 'Export dépendances' -Fichier $f.Name }
      }
    }
    else {
      $j = $null; try { $j = $t | ConvertFrom-Json } catch { $etat = 'Invalide' }
      if ($etat -eq 'Lu') {
        if ($j.PSObject.Properties['value']) { $j = $j.value }
        if ($j.PSObject.Properties['AutoDetectedLicences']) {   # format 44.0+ : paquets détectés + licences statiques (DLL tierces)
          foreach ($e in @($j.StaticLicences)) { Ajouter -Eco 'Binaire' -Nom ($e.PackageName -replace '\.dll$', '') -Ver $e.PackageVersion -Module $module -Identite 'À confirmer' -Methode 'Licence statique (version de fichier)' -Fichier $f.Name -Note "$($e.Authors)" }
          $j = $j.AutoDetectedLicences
        }
        foreach ($e in @($j)) {
          if ($null -eq $e) { continue }
          $props = @($e.PSObject.Properties.Name)   # -ccontains : PowerShell confond « name » (npm) et « Name » (NuGet)
          if ($props -ccontains 'PackageName') { Ajouter -Eco 'NuGet' -Nom $e.PackageName -Ver $e.PackageVersion -Module $module -Methode 'Export licences' -Fichier $f.Name -Licence "$($e.LicenseType)" }
          elseif ($props -ccontains 'name' -and $props -ccontains 'version') { if ($e.self -ne $true) { Ajouter -Eco 'npm' -Nom $e.name -Ver $e.version -Module $module -Methode 'Export licences npm' -Fichier $f.Name -Licence $(if ($e.license -is [string]) { $e.license } else { "$($e.license.type)" }) } }
          elseif ($props -ccontains 'Name' -and $props -ccontains 'Version') {
            Ajouter -Eco 'NuGet' -Nom $e.Name -Ver $e.Version -Module $module -Methode 'Graphe de dépendances' -Fichier $f.Name
            if ($e.Dependencies) { foreach ($p in $e.Dependencies.PSObject.Properties) { Ajouter -Eco 'NuGet' -Nom $p.Name -Ver "$($p.Value)" -Module $module -Methode 'Graphe de dépendances' -Fichier $f.Name } }
          }
        }
        if ($Inv.Count -eq $avant) { $etat = 'Non reconnu' }
      }
    }
    $Exports.Add([pscustomobject]@{ Fichier = $f.Name; Type = $type; Module = $module; Etat = $etat; Entrees = $Inv.Count - $avant; Couverture = '' })
  }
}
# Couverture des modules dont l'export de dépendances est vide ou invalide : une liste de licences dédiée donne une
# couverture partielle (paquets sans graphe) ; sinon la couverture du module n'est pas démontrée.
function Evaluer-Couverture {
  $licences = @($Exports | Where-Object { $_.Type -eq 'Licences' -and $_.Etat -eq 'Lu' })
  foreach ($e in $Exports | Where-Object { $_.Etat -ne 'Lu' }) {
    if ($e.Type -eq 'Dependencies') {
      $cle = $e.Module -replace '^(Seal\.|Services\.)+', ''
      $lic = @($licences | Where-Object { $_.Module -eq $cle -or $e.Module -like "*.$($_.Module)" -or $_.Module -like "*$cle" }) | Select-Object -First 1
      $e.Couverture = if ($lic) { "Partielle : paquets de $($lic.Fichier), sans graphe de dépendances" } else { 'Non démontrée : aucune liste de licences dédiée (une liste globale peut couvrir le module)' }
    } else { $e.Couverture = 'Non démontrée : liste de licences inexploitable' }
    Diag 'Attention' $e.Fichier "Export $($e.Etat.ToLower()) : $($e.Couverture)"
  }
}

function Extraire-Exports([string]$dossierLivraison, [string]$dest) {
  New-Item -ItemType Directory -Force $dest | Out-Null
  $direct = @(Get-ChildItem $dossierLivraison -File -Filter '*.zip' | Where-Object { $_.Name -match '^(Dependencies|Licen[cs]es)\.zip$' })
  foreach ($z in $direct) { $d = Join-Path $dest $z.BaseName; if (Test-Path $d) { Remove-Item $d -Recurse -Force }; [IO.Compression.ZipFile]::ExtractToDirectory($z.FullName, $d) }
  if ($direct.Count -ge 2) { return }
  foreach ($a in Get-ChildItem $dossierLivraison -File -Filter '*artifacts*.zip') {   # zips imbriqués dans l'archive TeamCity
    $zip = [IO.Compression.ZipFile]::OpenRead($a.FullName)
    try {
      foreach ($en in $zip.Entries | Where-Object { $_.Name -match '^(Dependencies|Licen[cs]es)\.zip$' }) {
        $tmp = Join-Path $dest $en.Name; [IO.Compression.ZipFileExtensions]::ExtractToFile($en, $tmp, $true)
        $d = Join-Path $dest ([IO.Path]::GetFileNameWithoutExtension($en.Name)); if (Test-Path $d) { Remove-Item $d -Recurse -Force }
        [IO.Compression.ZipFile]::ExtractToDirectory($tmp, $d); Remove-Item $tmp
      }
    } finally { $zip.Dispose() }
  }
}

# ---- installation : découverte des dossiers puis lecture des manifestes et des DLL
function Inventorier-Installation {
  $cles = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
  $produits = @(Get-ItemProperty $cles -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match '\bSEAL\b' -or $_.Publisher -match 'Omnitech' })
  $ver = $VersionSeal
  # version du registre : repli seulement (des composants annexes y figurent, ex. « SEAL Millefeuille 24.0.0 »)
  $verRegistre = ($produits | Where-Object DisplayName -match '^SEAL$|\bSEAL (Server|Serveur|Client|System)\b' | Sort-Object { Cle-Version $_.DisplayVersion } | Select-Object -Last 1).DisplayVersion
  $dossiers = @($RacineInstallation)
  if (-not $RacineInstallation.Count) {
    $dossiers += @($produits | ForEach-Object { $_.InstallLocation } | Where-Object { $_ })
    if (-not $SansRechercheDisques) {   # tous les disques fixes : dossiers SEAL / Omnitech à la racine ou au 2e niveau
      $ignores = '^(Windows|\$Recycle\.Bin|System Volume Information|Recovery|PerfLogs|ProgramData|Users|Documents and Settings|Config\.Msi)$'
      foreach ($r in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue | ForEach-Object { $_.DeviceID + '\' })) {
        $n1 = @(Get-ChildItem $r -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch $ignores })
        $dossiers += @($n1 | Where-Object Name -match $MotifDossiers | ForEach-Object FullName)
        $dossiers += @($n1 | Where-Object Name -notmatch $MotifDossiers | ForEach-Object { Get-ChildItem $_.FullName -Directory -Force -ErrorAction SilentlyContinue | Where-Object Name -match $MotifDossiers | ForEach-Object FullName })
      }
    }
    # services Windows SEAL
    $dossiers += @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -match 'SEAL|Omnitech' } | ForEach-Object {
        $m = [regex]::Match($_.PathName, '^\s*(?:"([^"]+\.exe)"|(\S+\.exe))'); if ($m.Success) { Split-Path ([Environment]::ExpandEnvironmentVariables($(if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }))) -Parent } })
    # sites, applications et répertoires virtuels IIS (lecture directe de la configuration, sans module)
    $iis = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
    if (Test-Path $iis) { try { [xml]$x = Lire-Texte $iis; foreach ($n in $x.SelectNodes('//virtualDirectory[@physicalPath]')) { $p = [Environment]::ExpandEnvironmentVariables($n.physicalPath); if ($p -match 'SEAL|Omnitech') { $dossiers += $p } } } catch { Diag 'Attention' 'IIS' 'Configuration IIS illisible' } }
  }
  $dossiers += $DossiersSupplementaires
  $dossiers = @($dossiers | Where-Object { $_ -and (Test-Path $_) } | ForEach-Object { (Resolve-Path $_).Path.TrimEnd('\') } | Sort-Object -Unique)
  $dossiers = @($dossiers | Where-Object { $d = $_; -not ($dossiers | Where-Object { $_ -ne $d -and $d.StartsWith($_ + '\', [StringComparison]::OrdinalIgnoreCase) }) })
  if (-not $dossiers.Count) { throw 'Aucun dossier SEAL trouvé : utiliser -RacineInstallation avec les chemins exacts.' }
  Log "Dossiers analysés : $($dossiers.Count)"; $dossiers | ForEach-Object { Log "  $_" }

  $fichiers = @(foreach ($d in $dossiers) { Get-ChildItem $d -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch $ExclureDossiers } })
  Log "  $($fichiers.Count) fichiers retenus (exclusions : installateurs, sauvegardes, mises à jour, journaux)"
  if (-not $ver) {   # version la plus fréquente des exécutables Omnitech installés (45,0,25468,x -> 45.0.25468), puis registre
    $vs = @($fichiers | Where-Object { $_.Extension -eq '.exe' -and $_.VersionInfo.CompanyName -match 'Omnitech' } | ForEach-Object { [regex]::Match(("$($_.VersionInfo.ProductVersion)" -replace ',', '.' -replace '\s', ''), '^\d{2}\.\d+\.\d{4,6}').Value } | Where-Object { $_ })
    if ($vs.Count) { $ver = ($vs | Group-Object | Sort-Object Count -Descending | Select-Object -First 1).Name; Log "  version SEAL déduite des exécutables Omnitech : $ver" }
    elseif ($verRegistre) { $ver = $verRegistre; Log "  version SEAL lue dans le registre : $ver" }
    if ($verRegistre -and $ver -and $verRegistre -ne $ver) { Diag 'Information' 'Version' "Registre : $verRegistre ; exécutables : $ver (version des exécutables retenue)" }
  }
  $dossiersPaquets = @{}
  foreach ($f in $fichiers | Where-Object { $_.Name -like '*.deps.json' }) {
    try { $j = Lire-JsonFichier $f.FullName } catch { Diag 'Attention' $f.FullName 'deps.json illisible'; continue }
    $app = $f.Name -replace '\.deps\.json$', ''; $dossiersPaquets[$f.DirectoryName] = $true
    foreach ($p in $j.libraries.PSObject.Properties) { if ($p.Value.type -eq 'package') { $n, $v = $p.Name.Split('/', 2); Ajouter -Eco 'NuGet' -Nom $n -Ver $v -Module $app -Methode 'deps.json' -Fichier $f.FullName } }
  }
  foreach ($f in $fichiers | Where-Object { $_.Name -like '*.runtimeconfig.json' }) {
    try {
      $j = Lire-JsonFichier $f.FullName; $app = $f.Name -replace '\.runtimeconfig\.json$', ''
      foreach ($fw in @($j.runtimeOptions.framework) + @($j.runtimeOptions.frameworks)) { if ($fw.name) { $RuntimesRequis.Add([pscustomobject]@{ Application = $app; Runtime = $fw.name; Version = "$($fw.version)" }) } }
      foreach ($fw in @($j.runtimeOptions.includedFrameworks)) { if ($fw.name) { Ajouter -Eco 'Runtime .NET' -Nom $fw.name -Ver $fw.version -Module "$app (autonome)" -Methode 'Runtime inclus (déploiement autonome)' -Fichier $f.FullName } }
    } catch { Diag 'Attention' $f.FullName 'runtimeconfig.json illisible' }
  }
  foreach ($f in $fichiers | Where-Object { $_.Name -eq 'packages.config' }) {
    try { [xml]$x = Lire-Texte $f.FullName; foreach ($p in $x.packages.package) { Ajouter -Eco 'NuGet' -Nom $p.id -Ver $p.version -Module (Split-Path $f.DirectoryName -Leaf) -Methode 'packages.config' -Fichier $f.FullName }; $dossiersPaquets[$f.DirectoryName] = $true; $dossiersPaquets[(Join-Path $f.DirectoryName 'bin')] = $true } catch { Diag 'Attention' $f.FullName 'packages.config illisible' }
  }
  foreach ($f in $fichiers | Where-Object { $_.Name -eq 'package.json' -and $_.FullName -match '\\node_modules\\' } | Select-Object -First 5000) {
    try { $j = Lire-JsonFichier $f.FullName; if ($j.name -and $j.version) { Ajouter -Eco 'npm' -Nom $j.name -Ver $j.version -Module 'Front web (node_modules)' -Methode 'package.json' -Fichier $f.FullName -Licence "$($j.license)" } } catch {}
  }
  foreach ($d in $dossiers) { Lire-ExportsSeal $d -Filtrer }
  # DLL : natives connues (CPE) ; DLL tierces non Microsoft hors dossiers décrits par un manifeste. Leur ProductVersion
  # n'établit pas une version de paquet : identité « À confirmer ».
  foreach ($f in $fichiers | Where-Object { $_.Extension -eq '.dll' -and $_.FullName -notmatch '\\(refs|ref)\\' }) {
    $vi = $f.VersionInfo; $base = $f.BaseName
    if ("$($vi.CompanyName)" -match 'Omnitech' -or $base -match $PrefixesInternes) { continue }
    $cle = @($CpeNatifs.Keys + $NonCouverts.Keys | Where-Object { $base -like "$_*" }) | Select-Object -First 1
    if ($cle) { Ajouter -Eco 'Natif' -Nom $cle -Ver (Version-Propre $vi.FileVersion) -Module "DLL $($f.Name)" -Methode 'Version de fichier DLL' -Fichier $f.FullName; continue }
    if ($dossiersPaquets.ContainsKey($f.DirectoryName) -or "$($vi.CompanyName)" -match '^Microsoft' -or $base -match '^(System|Microsoft|mscorlib|netstandard|api-ms|ucrtbase|vcruntime|msvcp|concrt)[\.\-_]') { continue }
    $v = Version-Propre ("$($vi.ProductVersion)" -split '[\+ ]')[0]; if ($v -match '^(\d+\.\d+\.\d+)\.0$') { $v = $Matches[1] }
    if ($v -match '^\d+(\.\d+){1,3}$') { Ajouter -Eco 'NuGet' -Nom $base -Ver $v -Module "DLL $(Split-Path $f.DirectoryName -Leaf)" -Identite 'À confirmer' -Methode 'ProductVersion DLL' -Fichier $f.FullName -Note 'Version lue dans la DLL : version de paquet non démontrée' }
  }

  # ---- hôte : runtimes .NET, .NET Framework, système et correctifs installés
  foreach ($b in 'C:\Program Files\dotnet\shared', 'C:\Program Files (x86)\dotnet\shared') {
    if (Test-Path $b) { foreach ($fw in Get-ChildItem $b -Directory) { foreach ($rv in Get-ChildItem $fw.FullName -Directory) { Ajouter -Eco 'Runtime .NET' -Nom $fw.Name -Ver $rv.Name -Module 'Hôte' -Perimetre 'Environnement' -Methode 'Dossier runtime installé' -Fichier $rv.FullName } } }
  }
  $ndp = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue
  if ($ndp) { Ajouter -Eco '.NET Framework' -Nom '.NET Framework' -Ver "$($ndp.Version)" -Module 'Hôte' -Perimetre 'Environnement' -Methode 'Registre NDP' -Note "Release $($ndp.Release)" }
  $nt = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
  $correctifs = @(Get-HotFix -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ KB = "$($_.HotFixID)"; Installe = $(if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { '' }); Type = "$($_.Description)" } })
  $hote = [pscustomobject]@{ ProduitOS = "$($nt.ProductName)"; TypeInstallation = "$($nt.InstallationType)"; VersionAffichee = "$($nt.DisplayVersion)"; Build = "$($nt.CurrentBuild).$($nt.UBR)"
    Architecture = $(if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }); NetFrameworkRelease = $(if ($ndp) { [int]$ndp.Release } else { 0 }); Correctifs = $correctifs }
  $dernier = $correctifs | Where-Object Installe | Sort-Object Installe | Select-Object -Last 1
  [pscustomobject]@{ Version = $ver; Racines = $dossiers; Hote = $hote; DernierCorrectif = $(if ($dernier) { "$($dernier.KB) du $($dernier.Installe)" } else { '' }) }
}

# ============================================================================================ sources de vulnérabilités
$script:NvdCle = if ($NvdApiKey) { $NvdApiKey } elseif ($env:NVD_API_KEY) { $env:NVD_API_KEY } else { $null }
$script:NvdDernier = [datetime]::MinValue
$Sources = New-Object Collections.Generic.List[object]
function Source([string]$nom, [string]$etat) { if (-not ($Sources | Where-Object { $_.Source -eq $nom -and $_.Etat -eq $etat })) { $Sources.Add([pscustomobject]@{ Source = $nom; Etat = $etat }) } }
function Invoke-Json([string]$url, [string]$methode = 'Get', $corps = $null, [hashtable]$entetes = @{}) {
  for ($e = 1; $e -le 3; $e++) {
    try {
      if ($corps) { return Invoke-RestMethod $url -Method $methode -Body $corps -ContentType 'application/json' -Headers $entetes -TimeoutSec 180 -UseBasicParsing }
      return Invoke-RestMethod $url -Method $methode -Headers $entetes -TimeoutSec 180 -UseBasicParsing
    } catch {
      $code = try { [int]$_.Exception.Response.StatusCode } catch { 0 }
      if ($code -eq 404) { throw }
      if ($code -in 403 -and $entetes.ContainsKey('apiKey') -and $e -eq 1) { Log 'clé NVD refusée, passage sans clé'; $script:NvdCle = $null; $entetes.Remove('apiKey') }
      if ($e -eq 3) { throw }
      Start-Sleep -Seconds (10 * $e)
    }
  }
}
function Get-OsvIds([object[]]$requetes) {
  $res = New-Object Collections.Generic.List[object]
  for ($i = 0; $i -lt $requetes.Count; $i += 500) {
    $lot = @($requetes[$i..([math]::Min($i + 499, $requetes.Count - 1))])
    $r = Invoke-Json 'https://api.osv.dev/v1/querybatch' 'Post' (@{ queries = $lot } | ConvertTo-Json -Depth 6 -Compress)
    foreach ($x in $r.results) { $res.Add(@($x.vulns | ForEach-Object { $_.id })) }
  }
  Source 'OSV.dev' 'Interrogée en ligne'
  , $res
}
function Get-OsvDetail([string]$id) {
  $f = Join-Path "$Cache\osv" ((Nom-Fichier $id) + '.json')
  if ((Age-Heures $f) -lt 72) { try { return Lire-JsonFichier $f } catch {} }
  try { $j = Invoke-Json "https://api.osv.dev/v1/vulns/$id"; Ecrire-Json $f $j; $j } catch { Diag 'Attention' 'OSV' "fiche $id indisponible"; $null }
}
function Get-NvdCpe([string]$cpe) {
  $f = Join-Path "$Cache\nvd" ((Nom-Fichier $cpe) + '.json')
  if ((Age-Heures $f) -lt 72) { try { return @(Lire-JsonFichier $f) } catch {} }
  $esp = if ($script:NvdCle) { 0.7 } else { 6.5 }
  $att = $esp - ((Get-Date) - $script:NvdDernier).TotalSeconds; if ($att -gt 0) { Start-Sleep -Milliseconds ([int]($att * 1000)) }
  $script:NvdDernier = Get-Date
  $h = @{}; if ($script:NvdCle) { $h['apiKey'] = $script:NvdCle }
  $prefixe = ($cpe.Split(':')[0..4] -join ':') + ':'
  try { $j = Invoke-Json "https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=$([uri]::EscapeDataString($cpe))&resultsPerPage=2000" 'Get' $null $h } catch { Diag 'Attention' 'NVD' "indisponible pour $cpe"; Source 'NVD' 'Indisponible (partiel)'; return $null } finally { $h = $null }
  Source 'NVD' 'Interrogée en ligne'
  $l = @(foreach ($v in $j.vulnerabilities.cve) {
      if ($v.vulnStatus -eq 'Rejected') { continue }
      # seules les CVE où le produit est lui-même vulnérable (pas simple plateforme d'exécution)
      $vuln = @($v.configurations.nodes.cpeMatch | Where-Object { $_.vulnerable -and "$($_.criteria)".StartsWith($prefixe, [StringComparison]::OrdinalIgnoreCase) })
      if ($v.configurations -and -not $vuln.Count) { continue }
      $mt = @($v.metrics.cvssMetricV31) + @($v.metrics.cvssMetricV30) + @($v.metrics.cvssMetricV40) + @($v.metrics.cvssMetricV2) | Where-Object { $_ } | Select-Object -First 1
      [pscustomobject]@{ Id = $v.id; Score = $(if ($mt) { [double]$mt.cvssData.baseScore } else { $null }); Publie = ([datetime]$v.published).ToString('yyyy-MM-dd')
        Resume = "$(($v.descriptions | Where-Object lang -eq 'en' | Select-Object -First 1).value)"; Corrige = (@($vuln | ForEach-Object { $_.versionEndExcluding } | Where-Object { $_ } | Sort-Object -Unique) -join ' / ') }
    })
  Ecrire-Json $f @($l)
  $l
}
function Get-Kev {
  $f = "$Cache\kev.json"
  if ((Age-Heures $f) -gt 24) { try { Invoke-WebRequest 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' -OutFile $f -UseBasicParsing -TimeoutSec 120; Source 'CISA KEV' 'Actualisée' } catch { Source 'CISA KEV' 'Indisponible (cache)' } }
  $h = @{}; if (Test-Path $f) { foreach ($v in (Lire-JsonFichier $f).vulnerabilities) { $h[$v.cveID] = "$($v.dueDate)" } }; $h
}
function Get-EolDotnet {
  $f = "$Cache\eol-dotnet.json"
  if ((Age-Heures $f) -gt 24) { try { Invoke-WebRequest 'https://endoflife.date/api/dotnet.json' -OutFile $f -UseBasicParsing -TimeoutSec 60; Source 'endoflife.date' 'Actualisée' } catch { Source 'endoflife.date' 'Indisponible (cache)' } }
  if (Test-Path $f) { @(Lire-JsonFichier $f) } else { @() }
}

# ---- MSRC : KB requis par CVE .NET Framework pour l'OS et la version .NET de l'hôte
# Chaque bulletin mensuel (≈ 2 Mo) est réduit à un index compact (produits .NET Framework, KB par CVE) mis en cache.
$MoisEn = 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
function Prop($o, [string]$n) { if ($o -is [Collections.IDictionary]) { $o[$n] } else { $o.$n } }
function Lire-JsonVolumineux([string]$texte) {
  if ($PSVersionTable.PSVersion.Major -ge 6) { return ($texte | ConvertFrom-Json) }
  Add-Type -AssemblyName System.Web.Extensions
  $s = New-Object Web.Script.Serialization.JavaScriptSerializer; $s.MaxJsonLength = [int]::MaxValue; $s.RecursionLimit = 200
  $s.DeserializeObject($texte)
}
function Get-MsrcBulletinCve([string]$cve) {
  $f = Join-Path "$Cache\msrc" "cve_$cve.json"
  if ((Age-Heures $f) -lt 720) { return "$((Lire-JsonFichier $f).Bulletin)" }
  try { $r = Invoke-Json "https://api.msrc.microsoft.com/cvrf/v3.0/updates('$cve')"; $id = "$(@($r.value)[0].ID)" } catch { $id = '' }
  Ecrire-Json $f ([pscustomobject]@{ Bulletin = $id }); $id
}
function Get-MsrcIndex([string]$id) {
  $f = Join-Path "$Cache\msrc" "index_$id.json"
  if ((Age-Heures $f) -lt 168) { return (Lire-JsonFichier $f) }
  try {
    $brut = (Invoke-WebRequest "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/$id" -Headers @{ Accept = 'application/json' } -UseBasicParsing -TimeoutSec 300).Content
    if ($brut -is [byte[]]) { $brut = [Text.Encoding]::UTF8.GetString($brut) }
    $d = Lire-JsonVolumineux $brut
  } catch { Diag 'Attention' 'MSRC' "bulletin $id indisponible"; Source 'MSRC' 'Indisponible (partiel)'; return $null }
  Source 'MSRC' 'Interrogée en ligne'
  $produits = @{}; foreach ($p in @(Prop (Prop $d 'ProductTree') 'FullProductName')) { $nom = "$(Prop $p 'Value')"; if ($nom -match '\.NET Framework') { $produits["$(Prop $p 'ProductID')"] = $nom } }
  $vulns = @{}
  foreach ($v in @(Prop $d 'Vulnerability')) {
    $kbs = @(foreach ($r in @(Prop $v 'Remediations')) {
        $desc = Prop $r 'Description'; if ([int](Prop $r 'Type') -ne 2 -or -not $desc) { continue }
        $ids = @(@(Prop $r 'ProductID') | Where-Object { $produits.ContainsKey("$_") }); if (-not $ids.Count) { continue }
        [pscustomobject]@{ KB = "$(Prop $desc 'Value')"; Produits = @($ids | ForEach-Object { "$_" }) } })
    if ($kbs.Count) { $vulns["$(Prop $v 'CVE')"] = $kbs }
  }
  $mois = [datetime]::ParseExact($id, 'yyyy-MMM', $Invariant).ToString('yyyy-MM')
  $idx = [pscustomobject]@{ Bulletin = $id; Mois = $mois; Produits = $produits; Vulnerabilites = $vulns }
  Ecrire-Json $f $idx
  Lire-JsonFichier $f
}
function Nom-Bulletin([datetime]$d) { "$($d.Year)-$($MoisEn[$d.Month - 1])" }
# Produits MSRC correspondant à l'hôte : « Microsoft .NET Framework [3.5 AND] 4.8 on Windows Server 2019 [(Server Core installation)] »
function Produits-Hote($idx, $hote) {
  $rel = [int]$hote.NetFrameworkRelease
  $net = if ($rel -ge 533320) { '\b4\.8\.1\b' } elseif ($rel -ge 528040) { '\b4\.8\b(?!\.\d)' } elseif ($rel -ge 461808) { '\b4\.7\.2\b' } else { $null }
  $os = if ($hote.ProduitOS -match 'Windows Server (\d{4}( R2)?)') { [regex]::Escape("on Windows Server $($Matches[1])") }
  elseif ($hote.ProduitOS -match 'Windows (1[01])') { [regex]::Escape("on Windows $($Matches[1]) Version $($hote.VersionAffichee) for $($hote.Architecture)") }
  else { $null }
  if (-not $net -or -not $os) { return [pscustomobject]@{ OK = $false; Ids = @() } }
  $coeur = $hote.TypeInstallation -match 'Core'
  [pscustomobject]@{ OK = $true; Ids = @($idx.Produits.PSObject.Properties | Where-Object { $_.Value -match $net -and $_.Value -match $os -and (($_.Value -match 'Server Core') -eq $coeur) } | ForEach-Object { $_.Name }) }
}
function Qualifier-NetFramework($cves, $hote) {
  $res = @{}
  if (-not $hote -or -not $hote.Correctifs -or -not $hote.ProduitOS) {
    foreach ($c in $cves) { $res[$c] = [pscustomobject]@{ Statut = 'À confirmer : correctifs de l''hôte non relevés (livraison ou inventaire ancien)'; Categorie = 'À confirmer'; KB = '' } }
    return $res
  }
  $installes = @{}; foreach ($k in $hote.Correctifs) { $installes[($k.KB -replace '^KB', '')] = $k.Installe }
  Log ".NET Framework : qualification de $(@($cves).Count) CVE par les bulletins MSRC et les $($installes.Count) correctifs installés"
  $index = @{}
  $bulletinCve = @{}; foreach ($c in $cves) { $b = Get-MsrcBulletinCve $c; $bulletinCve[$c] = $b; if ($b -and -not $index.ContainsKey($b)) { $index[$b] = Get-MsrcIndex $b } }
  # dernier cumulatif .NET installé pour ce produit : on parcourt les mois des correctifs installés, du plus récent au plus ancien
  $cumul = $null
  $moisCorrectifs = @($hote.Correctifs | Where-Object Installe | ForEach-Object { [datetime]::ParseExact($_.Installe, 'yyyy-MM-dd', $Invariant) } | ForEach-Object { $_; $_.AddMonths(-1) } | ForEach-Object { Nom-Bulletin $_ } | Select-Object -Unique)
  $moisCorrectifs = @($moisCorrectifs | Sort-Object { [datetime]::ParseExact($_, 'yyyy-MMM', $Invariant) } -Descending | Select-Object -First 14)
  foreach ($b in $moisCorrectifs) {
    if (-not $index.ContainsKey($b)) { $index[$b] = Get-MsrcIndex $b }
    $idx = $index[$b]; if (-not $idx) { continue }
    $prod = (Produits-Hote $idx $hote).Ids; if (-not $prod.Count) { continue }
    $kbProduit = @($idx.Vulnerabilites.PSObject.Properties.Value | ForEach-Object { $_ } | Where-Object { @($_.Produits | Where-Object { $prod -contains $_ }).Count } | ForEach-Object { $_.KB } | Select-Object -Unique)
    $trouve = @($kbProduit | Where-Object { $installes.ContainsKey($_) }) | Select-Object -First 1
    if ($trouve) { $cumul = [pscustomobject]@{ KB = "KB$trouve"; Mois = $idx.Mois }; break }
  }
  if ($cumul) { Log "  dernier cumulatif .NET Framework installé : $($cumul.KB) (bulletin $($cumul.Mois))" }
  foreach ($c in $cves) {
    $b = $bulletinCve[$c]; $idx = if ($b) { $index[$b] } else { $null }
    if (-not $idx) { $res[$c] = [pscustomobject]@{ Statut = 'À confirmer : CVE absente des bulletins MSRC'; Categorie = 'À confirmer'; KB = '' }; continue }
    $ph = Produits-Hote $idx $hote; $prod = $ph.Ids
    if (-not $ph.OK) { $res[$c] = [pscustomobject]@{ Statut = 'À confirmer : OS ou version .NET non rapprochable des produits MSRC'; Categorie = 'À confirmer'; KB = '' }; continue }
    $kbs = @($idx.Vulnerabilites.$c | Where-Object { @($_.Produits | Where-Object { $prod -contains $_ }).Count } | ForEach-Object { $_.KB } | Select-Object -Unique)
    if (-not $prod.Count -or -not $kbs.Count) { $res[$c] = [pscustomobject]@{ Statut = "Non applicable : .NET Framework de l'hôte absent de l'avis ($b)"; Categorie = 'Corrigée / non applicable'; KB = '' }; continue }
    $ok = @($kbs | Where-Object { $installes.ContainsKey($_) }) | Select-Object -First 1
    if ($ok) { $res[$c] = [pscustomobject]@{ Statut = "Corrigée : KB$ok installé"; Categorie = 'Corrigée / non applicable'; KB = "KB$ok" } }
    elseif ($cumul -and $cumul.Mois -ge $idx.Mois) { $res[$c] = [pscustomobject]@{ Statut = "Corrigée : cumulatif .NET ultérieur $($cumul.KB) ($($cumul.Mois)) installé"; Categorie = 'Corrigée / non applicable'; KB = (@($kbs | ForEach-Object { "KB$_" }) -join ', ') } }
    else { $res[$c] = [pscustomobject]@{ Statut = "Non corrigée : KB requis absent ($(@($kbs | ForEach-Object { "KB$_" }) -join ', '))"; Categorie = 'Environnement'; KB = (@($kbs | ForEach-Object { "KB$_" }) -join ', ') } }
  }
  $res
}

# ============================================================================================ analyse
$Categories = 'Dépendance SEAL', 'Environnement', 'À confirmer', 'Corrigée / non applicable'
$RangCat = @{ 'Dépendance SEAL' = 0; 'Environnement' = 1; 'À confirmer' = 2; 'Corrigée / non applicable' = 3 }
function Analyser([string]$version, [string]$dossierSortie, $meta, [string]$precedent) {
  $kev = Get-Kev
  $uniq = @($Inv | Group-Object Ecosysteme, Composant, Version, Perimetre | ForEach-Object {
      $g = $_.Group
      [pscustomobject]@{ Ecosysteme = $g[0].Ecosysteme; Composant = $g[0].Composant; Version = $g[0].Version; Perimetre = $g[0].Perimetre
        Identite = $(if ($g | Where-Object Identite -eq 'Exacte') { 'Exacte' } else { 'À confirmer' })
        Modules = (@($g.Source | Sort-Object -Unique) -join ', '); Methodes = (@($g.Methode | Where-Object { $_ } | Sort-Object -Unique) -join ', ')
        Licence = (@($g.Licence | Where-Object { $_ } | Sort-Object -Unique) -join ', '); Note = (@($g.Note | Where-Object { $_ } | Sort-Object -Unique) -join ', '); Statut = '' }
    } | Sort-Object Perimetre, Ecosysteme, Composant, { Cle-Version $_.Version })
  Log "Inventaire : $($uniq.Count) couples composant/version ($(@($uniq | Group-Object Ecosysteme | ForEach-Object { "$($_.Name) $($_.Count)" }) -join ', '))"
  $constats = New-Object Collections.Generic.List[object]

  # ---- NuGet, npm, runtimes .NET : OSV (version exacte)
  $osv = @($uniq | Where-Object { $_.Ecosysteme -in 'NuGet', 'npm' -or ($_.Ecosysteme -eq 'Runtime .NET' -and $PaquetsRuntime.ContainsKey($_.Composant)) })
  $req = @($osv | ForEach-Object {
      @{ package = @{ name = $(if ($_.Ecosysteme -eq 'Runtime .NET') { $PaquetsRuntime[$_.Composant] } else { $_.Composant }); ecosystem = $(if ($_.Ecosysteme -eq 'npm') { 'npm' } else { 'NuGet' }) }
        version = (Version-Propre $_.Version) + $(if ($_.Version -match '(-[\w\.]+)$') { $Matches[1] } else { '' }) } })
  Log "OSV : interrogation de $($req.Count) paquets"
  $ids = Get-OsvIds $req
  for ($i = 0; $i -lt $osv.Count; $i++) {
    $c = $osv[$i]; $c.Statut = 'Vérifié (OSV)'; $paquet = $req[$i].package.name
    foreach ($id in @($ids[$i] | Where-Object { $_ })) {
      $d = Get-OsvDetail $id; if (-not $d) { $c.Statut = 'Non vérifié : fiche OSV indisponible'; continue }
      if ($d.withdrawn) { continue }
      $cves = @(@($d.aliases) + @($d.id) | Where-Object { $_ -match '^CVE-\d{4}-\d+$' } | Sort-Object -Unique)
      if (-not $cves.Count -and "$($d.summary)" -match '(CVE-\d{4}-\d+)') { $cves = @($Matches[1]) }   # avis GitHub sans alias mais citant la CVE
      if (-not $cves.Count) { $cves = @($d.id) }
      $vec = @(@($d.severity) + @($d.affected | ForEach-Object { $_.severity }) | Where-Object { $_.type -like 'CVSS_V3*' } | ForEach-Object { $_.score }) | Select-Object -First 1
      $sc = if ($vec) { Score-Cvss3 $vec } else { $null }
      $fix = @(@(foreach ($a in $d.affected) { if ($a.package.name -eq $paquet) { foreach ($rg in $a.ranges) { foreach ($ev in $rg.events) { if ($ev.fixed) { $ev.fixed } } } } }) | Sort-Object -Unique)
      $fixProche = @($fix | Where-Object { (Comparer-Version $_ $c.Version) -gt 0 } | Sort-Object { Cle-Version $_ }) | Select-Object -First 1
      foreach ($cve in $cves) {
        $constats.Add([pscustomobject]@{ CVE = $cve; Avis = $d.id; Publie = ([datetime]$d.published).ToString('yyyy-MM-dd'); CVSS = $sc; GraviteSource = "$($d.database_specific.severity)"
            Comp = $c; Corrige = $(if ($fixProche) { $fixProche } else { '' }); SansCorrection = (-not $fixProche)
            Resume = $(if ($d.summary) { "$($d.summary)" } else { ("$($d.details)" -split "`n")[0] }); StatutKB = '' })
      }
    }
  }
  foreach ($c in $uniq | Where-Object { $_.Ecosysteme -eq 'Runtime .NET' -and -not $PaquetsRuntime.ContainsKey($_.Composant) }) { $c.Statut = 'Non couvert : runtime sans paquet suivi par OSV' }

  # ---- bibliothèques C++ : NVD (CPE)
  foreach ($c in @($uniq | Where-Object Ecosysteme -eq 'Natif')) {
    $cpe = $CpeNatifs[$c.Composant]
    if (-not $cpe) { $c.Statut = "Non couvert : $(if ($NonCouverts[$c.Composant]) { $NonCouverts[$c.Composant] } else { 'pas de CPE connue' })"; continue }
    $v = Version-Propre $c.Version
    if ($v -match '^(\d+\.\d+\.\d+)\.(\d+)$') {
      if ($Matches[2] -eq '0') { $v = $Matches[1] }
      else { $c.Identite = 'À confirmer'; $c.Note = "Version de fichier $($c.Version) interprétée $($Matches[1]) : à confirmer"; $v = $Matches[1] }
    }
    $l = Get-NvdCpe "cpe:2.3:a:$($cpe):$v"
    if ($null -eq $l) { $c.Statut = 'Non vérifié : NVD indisponible'; continue }
    $c.Statut = 'Vérifié (NVD)'
    foreach ($x in @($l | Where-Object { $_ })) { $constats.Add([pscustomobject]@{ CVE = $x.Id; Avis = 'NVD'; Publie = $x.Publie; CVSS = $x.Score; GraviteSource = ''; Comp = $c; Corrige = $x.Corrige; SansCorrection = (-not $x.Corrige); Resume = $x.Resume; StatutKB = '' }) }
  }
  foreach ($c in @($uniq | Where-Object Ecosysteme -eq 'Binaire')) { $c.Statut = 'Non couvert : DLL tierce sans identité de paquet publique' }

  # ---- .NET Framework : NVD pour la liste des CVE, MSRC + correctifs installés pour l'applicabilité
  foreach ($c in @($uniq | Where-Object Ecosysteme -eq '.NET Framework')) {
    $mm = ($c.Version.Split('.')[0..1] -join '.'); if ($meta.Hote.NetFrameworkRelease -ge 533320) { $mm = '4.8.1' }
    $l = Get-NvdCpe "cpe:2.3:a:microsoft:.net_framework:$mm"
    if ($null -eq $l) { $c.Statut = 'Non vérifié : NVD indisponible'; continue }
    $c.Statut = 'Vérifié (NVD + MSRC)'
    $qual = Qualifier-NetFramework @($l | ForEach-Object { $_.Id }) $meta.Hote
    foreach ($x in @($l | Where-Object { $_ })) { $constats.Add([pscustomobject]@{ CVE = $x.Id; Avis = 'NVD / MSRC'; Publie = $x.Publie; CVSS = $x.Score; GraviteSource = ''; Comp = $c; Corrige = $qual[$x.Id].KB; SansCorrection = $false; Resume = $x.Resume; StatutKB = $qual[$x.Id] }) }
  }

  # ---- catégorie et dédoublonnage : un constat = CVE (ou avis sans CVE) × composant × version
  $requis = @($RuntimesRequis | ForEach-Object { "$($_.Runtime)|$((Version-Propre $_.Version).Split('.')[0..1] -join '.')" } | Select-Object -Unique)
  $lignes = @($constats | Group-Object { "$($_.CVE)|$($_.Comp.Ecosysteme)|$($_.Comp.Composant)|$($_.Comp.Version)|$($_.Comp.Perimetre)" } | ForEach-Object {
      $x = $_.Group | Sort-Object { if ($null -ne $_.CVSS) { $_.CVSS } else { -1 } } -Descending | Select-Object -First 1
      $c = $x.Comp
      $cat = if ($x.StatutKB) { $x.StatutKB.Categorie }
      elseif ($c.Perimetre -eq 'Environnement') { 'Environnement' }
      elseif ($c.Identite -ne 'Exacte') { 'À confirmer' }
      else { 'Dépendance SEAL' }
      $etat = if ($x.StatutKB) { $x.StatutKB.Statut }
      elseif ($c.Ecosysteme -eq 'Runtime .NET' -and $c.Perimetre -eq 'Environnement') { if ($requis -contains "$($c.Composant)|$(($c.Version.Split('.')[0..1]) -join '.')") { 'Runtime de l''hôte requis par une application SEAL (runtimeconfig)' } else { 'Runtime présent sur l''hôte ; usage par SEAL non établi' } }
      elseif ($c.Identite -ne 'Exacte') { "Identité à confirmer : $(if ($c.Note) { $c.Note } else { $c.Methodes })" }
      else { 'Version associée à un avis publié ; exploitabilité à qualifier' }
      $grav = Gravite $x.CVSS $x.GraviteSource
      [pscustomobject][ordered]@{
        'Catégorie' = $cat; 'Mois' = $x.Publie.Substring(0, 7); 'CVE' = $x.CVE; 'Publiée' = $x.Publie; 'CVSS' = (Texte-Cvss $x.CVSS); 'Gravité' = $grav
        'KEV' = $(if ($kev.ContainsKey($x.CVE)) { 'OUI' } else { '' }); 'Périmètre' = $c.Perimetre; 'Écosystème' = $c.Ecosysteme; 'Composant' = $c.Composant; 'Version installée' = $c.Version
        'Version corrigée' = $(if ($x.Corrige) { $x.Corrige } elseif ($x.SansCorrection) { 'Aucune correction publiée' } else { '' }); 'État' = $etat; 'Modules SEAL' = $c.Modules
        'Avis' = (@($_.Group.Avis | Sort-Object -Unique) -join ', '); 'Résumé' = $(if ($x.Resume.Length -gt 240) { $x.Resume.Substring(0, 237) + '…' } else { $x.Resume })
        'Lien' = $(if ($x.CVE -like 'CVE-*') { "https://nvd.nist.gov/vuln/detail/$($x.CVE)" } else { "https://osv.dev/vulnerability/$($x.CVE)" }); 'Nouveau' = ''
      }
    } | Sort-Object @{ e = { $RangCat["$($_.'Catégorie')"] } }, @{ e = 'Publiée'; Descending = $true }, @{ e = { $RangGravite[$_.'Gravité'] }; Descending = $true })

  # ---- comparaison avec le rapport précédent : uniquement à moteur et source identiques
  $comparable = $false; $disparues = @(); $prec = $null
  if ($precedent) {
    try { $prec = Lire-JsonFichier (Join-Path $precedent 'resume.json') } catch {}
    $comparable = $prec -and "$($prec.VersionMoteur)" -eq $MoteurVersion -and "$($prec.Source)" -eq "$($meta.Source)"
    if ($comparable) {
      $anc = @{}; foreach ($p in @(Import-Csv (Join-Path $precedent 'cve-detail.csv') -Delimiter ';' -Encoding UTF8)) { $anc["$($p.CVE)|$($p.Composant)|$($p.'Version installée')|$($p.'Catégorie')"] = $p }
      foreach ($l in $lignes) { $k = "$($l.CVE)|$($l.Composant)|$($l.'Version installée')|$($l.'Catégorie')"; if (-not $anc.ContainsKey($k)) { $l.'Nouveau' = 'OUI' }; [void]$anc.Remove($k) }
      $disparues = @($anc.Values)
    } else { Diag 'Information' 'Historique' "Rapport précédent $(Split-Path $precedent -Leaf) produit avec un autre moteur ou une autre source : pas de comparaison (une disparition ne serait pas une correction)" }
  }

  # ---- inventaire enrichi (statut de vérification, catégorie la plus sévère)
  $parCouple = @{}; foreach ($g in @($lignes | Group-Object { "$($_.'Écosystème')|$($_.Composant)|$($_.'Version installée')|$($_.'Périmètre')" })) { $parCouple[$g.Name] = @($g.Group) }
  $invOut = @($uniq | ForEach-Object {
      $c = $_; $k = "$($c.Ecosysteme)|$($c.Composant)|$($c.Version)|$($c.Perimetre)"
      $l = if ($parCouple.ContainsKey($k)) { $parCouple[$k] } else { @() }
      $ouverts = @($l | Where-Object { $_.'Catégorie' -ne 'Corrigée / non applicable' })
      $scores = @($ouverts | Where-Object { $_.CVSS -ne '' } | ForEach-Object { Nombre $_.CVSS })
      $grav = @($ouverts | Sort-Object { $RangGravite[$_.'Gravité'] } -Descending | Select-Object -First 1).'Gravité'
      $cibles = @($ouverts | ForEach-Object { $_.'Version corrigée' } | Where-Object { $_ -match '^\d' })
      $cible = if (-not $ouverts.Count) { '' } elseif (@($ouverts | Where-Object { $_.'Version corrigée' -notmatch '^\d' }).Count) { 'À vérifier : un avis sans correction publiée' } else { @($cibles | Sort-Object { Cle-Version $_ }) | Select-Object -Last 1 }
      $statut = if ($c.Statut) { $c.Statut } elseif ($c.Ecosysteme -eq 'Runtime .NET') { 'Non couvert : runtime non suivi' } else { 'Non couvert' }
      $catTop = ''
      if ($ouverts.Count) { $tries = @($ouverts | ForEach-Object { $_.'Catégorie' } | Sort-Object { $RangCat["$_"] }); $catTop = "$($tries[0])" }
      elseif ($statut -like 'Non couvert*') { $catTop = 'Non couvert' }
      $cvssMax = ''; if ($scores.Count) { $cvssMax = Texte-Cvss (($scores | Measure-Object -Maximum).Maximum) }
      $nbCve = @($ouverts | ForEach-Object { $_.CVE } | Sort-Object -Unique).Count
      $o = New-Object PSObject
      foreach ($paire in @(@('Périmètre', $c.Perimetre), @('Écosystème', $c.Ecosysteme), @('Composant', $c.Composant), @('Version', $c.Version), @('Identité', $c.Identite), @('Catégorie', $catTop),
          @('CVE', $nbCve), @('CVSS max', $cvssMax), @('Gravité max', "$grav"), @('Version cible', "$cible"), @('Statut', $statut), @('Licence', $c.Licence), @('Modules SEAL', $c.Modules), @('Méthodes', $c.Methodes), @('Note', $c.Note))) {
        $o | Add-Member -NotePropertyName $paire[0] -NotePropertyValue $paire[1]
      }
      $o
    })

  # ---- runtimes .NET : fin de support
  $eol = Get-EolDotnet
  $dotnet = @(foreach ($c in @($uniq | Where-Object Ecosysteme -eq 'Runtime .NET')) {
      $br = ($c.Version.Split('.')[0..1] -join '.'); $cy = $eol | Where-Object { "$($_.cycle)" -eq $br -or "$($_.cycle)" -eq $br.Split('.')[0] } | Select-Object -First 1
      $fin = if ($cy) { "$($cy.eol)" } else { '' }; $hors = $fin -match '^\d{4}-' -and [datetime]$fin -lt (Get-Date)
      $k = "Runtime .NET|$($c.Composant)|$($c.Version)|$($c.Perimetre)"
      [pscustomobject][ordered]@{ Runtime = $c.Composant; Version = $c.Version; 'Périmètre' = $c.Perimetre
        Usage = $(if ($c.Perimetre -eq 'SEAL') { 'Inclus dans SEAL (autonome)' } elseif ($requis -contains "$($c.Composant)|$br") { 'Requis par SEAL (runtimeconfig)' } elseif ($RuntimesRequis.Count) { 'Non requis par les runtimeconfig SEAL' } else { 'Usage par SEAL non établi' })
        Branche = $br; FinSupport = $fin; HorsSupport = $(if ($hors) { 'OUI' } elseif ($fin) { 'non' } else { 'inconnu' }); DerniereVersion = $(if ($cy) { "$($cy.latest)" } else { '' })
        CVE = $(if ($parCouple.ContainsKey($k)) { @($parCouple[$k].CVE | Sort-Object -Unique).Count } else { 0 })
        Commentaire = $(if ($hors) { "Branche hors support depuis le $fin : CVE postérieures non évaluées. Migrer vers une branche supportée." } elseif ($cy -and (Comparer-Version $c.Version $cy.latest) -lt 0) { "Mettre à jour vers $($cy.latest)" } elseif ($cy) { 'À jour' } else { 'Cycle de vie inconnu' }) }
    })

  # ---- synthèse par catégorie et par mois
  function Stats($l) { [pscustomobject][ordered]@{ Constats = @($l).Count; CVE = @($l.CVE | Where-Object { $_ -like 'CVE-*' } | Sort-Object -Unique).Count; AvisSansCVE = @($l.CVE | Where-Object { $_ -notlike 'CVE-*' } | Sort-Object -Unique).Count
      Composants = @($l | ForEach-Object { "$($_.Composant)|$($_.'Version installée')" } | Sort-Object -Unique).Count; Critique = @($l | Where-Object Gravité -eq 'Critique').Count; Haute = @($l | Where-Object Gravité -eq 'Haute').Count
      Moyenne = @($l | Where-Object Gravité -eq 'Moyenne').Count; Basse = @($l | Where-Object { $_.'Gravité' -in 'Basse', 'Non renseignée' }).Count; KEV = @($l | Where-Object KEV -eq 'OUI' | ForEach-Object CVE | Sort-Object -Unique).Count } }
  $parCategorie = [ordered]@{}; foreach ($cat in $Categories) { $parCategorie[$cat] = Stats @($lignes | Where-Object { $_.'Catégorie' -eq $cat }) }
  $parMois = @($lignes | Group-Object 'Catégorie', Mois | ForEach-Object { $g = $_.Group; $s = Stats $g
      [pscustomobject][ordered]@{ 'Catégorie' = $g[0].'Catégorie'; 'Mois' = $g[0].Mois; 'Constats' = $s.Constats; 'CVE' = $s.CVE; 'Critique' = $s.Critique; 'Haute' = $s.Haute; 'Moyenne' = $s.Moyenne; 'Basse/n.r.' = $s.Basse; 'KEV' = $s.KEV
        'Composants' = (@($g | ForEach-Object { "$($_.Composant) $($_.'Version installée')" } | Sort-Object -Unique) -join ', ') } } | Sort-Object @{ e = { $RangCat["$($_.'Catégorie')"] } }, @{ e = 'Mois'; Descending = $true })

  # ---- contrôles de cohérence des compteurs (repris par la présentation)
  $controles = @(
    [pscustomobject]@{ Controle = 'Somme des constats par catégorie = total'; Attendu = $lignes.Count; Obtenu = (@($parCategorie.Values | ForEach-Object Constats) | Measure-Object -Sum).Sum }
    [pscustomobject]@{ Controle = 'Somme des constats par mois = total'; Attendu = $lignes.Count; Obtenu = (@($parMois.Constats) | Measure-Object -Sum).Sum }
    [pscustomobject]@{ Controle = 'Couples avec constat ouvert (inventaire) = couples distincts des constats ouverts'; Attendu = @($lignes | Where-Object { $_.'Catégorie' -ne 'Corrigée / non applicable' } | ForEach-Object { "$($_.'Écosystème')|$($_.Composant)|$($_.'Version installée')|$($_.'Périmètre')" } | Sort-Object -Unique).Count; Obtenu = @($invOut | Where-Object { $_.CVE -gt 0 -or $_.'Catégorie' -in $Categories }).Count }
    [pscustomobject]@{ Controle = 'Aucun constat sans catégorie'; Attendu = 0; Obtenu = @($lignes | Where-Object { $_.'Catégorie' -notin $Categories }).Count }
  ) | ForEach-Object { $_ | Add-Member -NotePropertyName OK -NotePropertyValue ([int]$_.Attendu -eq [int]$_.Obtenu) -PassThru }
  foreach ($k in $controles | Where-Object { -not $_.OK }) { Diag 'Erreur' 'Contrôle' "$($k.Controle) : attendu $($k.Attendu), obtenu $($k.Obtenu)" }

  # ---- résumé
  $vides = @($Exports | Where-Object { $_.Etat -ne 'Lu' })
  $ouvertes = @($lignes | Where-Object { $_.'Catégorie' -ne 'Corrigée / non applicable' })
  $resume = [pscustomobject][ordered]@{
    VersionMoteur = $MoteurVersion; VersionSeal = $version; Genere = (Get-Date).ToString('yyyy-MM-dd HH:mm'); DateCollecte = "$($meta.DateCollecte)"
    Mode = $meta.Mode; Source = $meta.Source; Machine = $meta.Machine; OS = $meta.OS; DernierCorrectif = $meta.DernierCorrectif
    Composants = $uniq.Count; ComposantsSEAL = @($uniq | Where-Object Perimetre -eq 'SEAL').Count; ComposantsEnvironnement = @($uniq | Where-Object Perimetre -eq 'Environnement').Count
    NonCouverts = @($invOut | Where-Object { $_.'Statut' -like 'Non couvert*' }).Count; NonVerifies = @($invOut | Where-Object { $_.'Statut' -like 'Non vérifié*' }).Count
    Constats = $lignes.Count; ConstatsOuverts = $ouvertes.Count; CVE = @($ouvertes.CVE | Where-Object { $_ -like 'CVE-*' } | Sort-Object -Unique).Count
    ParCategorie = $parCategorie
    ExportsLus = @($Exports | Where-Object Etat -eq 'Lu').Count; ExportsVides = $vides.Count; ModulesCouverturePartielle = @($vides | ForEach-Object { "$($_.Module) ($($_.Couverture))" })
    InventaireComplet = (-not $vides.Count -and -not @($Diagnostics | Where-Object { $_.Niveau -eq 'Attention' -and $_.Source -ne 'Historique' -and $_.Message -like '*illisible*' }).Count)
    RapportPrecedent = $(if ($precedent) { Split-Path $precedent -Leaf } else { '' }); HistoriqueComparable = [bool]$comparable
    Nouvelles = $(if ($comparable) { @($lignes | Where-Object Nouveau -eq 'OUI').Count } else { $null }); Disparues = $(if ($comparable) { $disparues.Count } else { $null })
    ControlesOK = -not @($controles | Where-Object { -not $_.OK }).Count
  }

  # ---- écriture
  $csv = @{ Delimiter = ';'; NoTypeInformation = $true; Encoding = 'UTF8' }
  function Ecrire-Csv([string]$nom, $rows, [string[]]$colonnes) {
    $p = Join-Path $dossierSortie $nom
    $tab = if ($rows -is [Collections.Generic.List[object]]) { $rows.ToArray() } else { @($rows) }   # @() sur une List<object> échoue sous PowerShell 5.1
    if ($tab.Count) { $tab | Select-Object $colonnes | Export-Csv $p @csv } else { [IO.File]::WriteAllText($p, ((@($colonnes | ForEach-Object { '"' + $_ + '"' }) -join ';') + "`r`n"), [Text.UTF8Encoding]::new($true)) } }
  $colsCve = @('Catégorie', 'Mois', 'CVE', 'Publiée', 'CVSS', 'Gravité', 'KEV', 'Périmètre', 'Écosystème', 'Composant', 'Version installée', 'Version corrigée', 'État', 'Modules SEAL', 'Avis', 'Résumé', 'Lien', 'Nouveau')
  Ecrire-Csv 'cve-detail.csv' $lignes $colsCve
  Ecrire-Csv 'cve-par-mois.csv' $parMois @('Catégorie', 'Mois', 'Constats', 'CVE', 'Critique', 'Haute', 'Moyenne', 'Basse/n.r.', 'KEV', 'Composants')
  Ecrire-Csv 'inventaire.csv' $invOut @('Périmètre', 'Écosystème', 'Composant', 'Version', 'Identité', 'Catégorie', 'CVE', 'CVSS max', 'Gravité max', 'Version cible', 'Statut', 'Licence', 'Modules SEAL', 'Méthodes', 'Note')
  Ecrire-Csv 'dotnet.csv' $dotnet @('Runtime', 'Version', 'Périmètre', 'Usage', 'Branche', 'FinSupport', 'HorsSupport', 'DerniereVersion', 'CVE', 'Commentaire')
  Ecrire-Csv 'exports.csv' $Exports @('Fichier', 'Type', 'Module', 'Etat', 'Entrees', 'Couverture')
  Ecrire-Csv 'diagnostic.csv' $Diagnostics @('Niveau', 'Source', 'Message')
  Ecrire-Csv 'sources.csv' $Sources @('Source', 'Etat')
  Ecrire-Csv 'controles.csv' $controles @('Controle', 'Attendu', 'Obtenu', 'OK')
  if ($comparable) { Ecrire-Csv 'cve-disparues.csv' $disparues $colsCve }
  Ecrire-Json (Join-Path $dossierSortie 'resume.json') $resume
  Ecrire-Html $resume $lignes $invOut $dotnet $disparues (Join-Path $dossierSortie 'rapport.html')
  $s = $parCategorie['Dépendance SEAL']
  Log "Dépendances SEAL : $($s.CVE) CVE, $($s.Constats) constats sur $($s.Composants) composants (critiques $($s.Critique), hautes $($s.Haute), KEV $($s.KEV))"
  foreach ($cat in 'Environnement', 'À confirmer', 'Corrigée / non applicable') { $s = $parCategorie[$cat]; if ($s.Constats) { Log "$cat : $($s.CVE) CVE, $($s.Constats) constats" } }
  if (-not $resume.InventaireComplet) { Log "ATTENTION : inventaire incomplet ($($vides.Count) export(s) vide(s) ou invalide(s), voir exports.csv)" }
  if (-not $resume.ControlesOK) { Log 'ATTENTION : contrôles de cohérence en échec (controles.csv)' }
  Log "Rapport : $dossierSortie"
  $resume
}

# ============================================================================================ rapport HTML
function Html([string]$s) { [Net.WebUtility]::HtmlEncode("$s") }
function Ecrire-Html($r, $lignes, $inv, $dotnet, $disparues, [string]$f) {
  $cls = @{ 'Critique' = 'c'; 'Haute' = 'h'; 'Moyenne' = 'm'; 'Basse' = 'b'; 'Non renseignée' = 'n' }
  $sb = New-Object Text.StringBuilder
  $src = if ($r.Machine) { "serveur $($r.Machine) · $($r.OS) · dernier correctif $($r.DernierCorrectif)" } else { 'livraison (exports de build)' }
  [void]$sb.Append(@"
<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>SEAL $(Html $r.VersionSeal) - CVE des dépendances</title>
<style>body{font:13px Segoe UI,Arial,sans-serif;margin:24px;color:#1d2530}h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px;border-bottom:2px solid #14213D;padding-bottom:4px}
h3{font-size:14px;margin:18px 0 6px;color:#14213D}.meta{color:#5b6573}.k{display:inline-block;min-width:120px;margin:8px 8px 0 0;padding:10px 12px;border-radius:6px;background:#eef1f5;vertical-align:top}.k b{display:block;font-size:22px}
table{border-collapse:collapse;width:100%;margin:6px 0}th,td{border:1px solid #d5dbe3;padding:4px 6px;text-align:left;vertical-align:top}th{background:#14213D;color:#fff;position:sticky;top:0}
tr:nth-child(even) td{background:#f8fafc}.g{font-weight:600;padding:1px 6px;border-radius:3px;color:#fff}.c{background:#B3261E}.h{background:#D9480F}.m{background:#E6A100}.b{background:#5C8A2D}.n{background:#8A94A0}
.kev{background:#000;color:#fff;padding:1px 5px;border-radius:3px}.warn{background:#fff4e5;border-left:4px solid #D9480F;padding:8px 12px;margin:8px 0}a{color:#1F5FA8}input{padding:6px;width:340px}</style></head><body>
<h1>SEAL $(Html $r.VersionSeal) : CVE des dépendances et de l'environnement .NET</h1>
<div class="meta">Analyse du $($r.Genere) · moteur $($r.VersionMoteur) · collecte du $(Html $r.DateCollecte) · source : $(Html $src)<br>Sources : OSV.dev (GitHub Advisory), NVD, MSRC, CISA KEV, endoflife.date</div>
"@)
  if (-not $r.InventaireComplet) { [void]$sb.Append("<p class=""warn""><b>Inventaire incomplet</b> : $($r.ExportsVides) export(s) vide(s) ou invalide(s). $(Html (@($r.ModulesCouverturePartielle) -join ' ; '))</p>") }
  if (-not $r.ControlesOK) { [void]$sb.Append('<p class="warn"><b>Contrôles de cohérence en échec</b> : voir controles.csv. Ne pas diffuser ce rapport.</p>') }
  [void]$sb.Append('<h2>Synthèse par catégorie</h2><table><tr><th>Catégorie</th><th>CVE distinctes</th><th>Constats</th><th>Composants</th><th>Critique</th><th>Haute</th><th>Moyenne</th><th>Basse / n.r.</th><th>KEV</th></tr>')
  foreach ($cat in $r.ParCategorie.Keys) { $s = $r.ParCategorie[$cat]; [void]$sb.Append("<tr><td><b>$(Html $cat)</b></td><td>$($s.CVE)</td><td>$($s.Constats)</td><td>$($s.Composants)</td><td>$($s.Critique)</td><td>$($s.Haute)</td><td>$($s.Moyenne)</td><td>$($s.Basse)</td><td>$($s.KEV)</td></tr>") }
  [void]$sb.Append("<tr><td><b>Non couvert</b> (inventaire)</td><td colspan=""8"">$($r.NonCouverts) composant(s) sans référentiel public exploitable</td></tr></table>")
  if ($r.RapportPrecedent) { [void]$sb.Append($(if ($r.HistoriqueComparable) { "<p>Depuis le rapport $(Html $r.RapportPrecedent) : $($r.Nouvelles) nouveau(x) constat(s), $($r.Disparues) disparu(s).</p>" } else { "<p>Rapport précédent $(Html $r.RapportPrecedent) produit avec un autre moteur ou une autre source : comparaison non effectuée.</p>" })) }
  if (@($dotnet).Count) {
    [void]$sb.Append('<h2>Runtimes .NET</h2><table><tr><th>Runtime</th><th>Version</th><th>Usage</th><th>Fin de support</th><th>Hors support</th><th>Dernière version</th><th>CVE</th><th>Commentaire</th></tr>')
    foreach ($d in $dotnet) { [void]$sb.Append("<tr><td>$(Html $d.Runtime)</td><td>$(Html $d.Version)</td><td>$(Html $d.Usage)</td><td>$(Html $d.FinSupport)</td><td>$(if ($d.HorsSupport -eq 'OUI') { '<span class="g c">OUI</span>' } else { Html $d.HorsSupport })</td><td>$(Html $d.DerniereVersion)</td><td>$($d.CVE)</td><td>$(Html $d.Commentaire)</td></tr>") }
    [void]$sb.Append('</table>')
  }
  [void]$sb.Append('<h2>Détail par catégorie et par mois</h2><p><input id="q" placeholder="Filtrer : CVE, composant, module…" oninput="var q=this.value.toLowerCase();document.querySelectorAll(''tr.f'').forEach(function(t){t.style.display=t.textContent.toLowerCase().indexOf(q)<0?''none'':''''})"></p>')
  foreach ($cat in $Categories) {
    $lc = @($lignes | Where-Object { $_.'Catégorie' -eq $cat }); if (-not $lc.Count) { continue }
    [void]$sb.Append("<h3>$(Html $cat) : $($lc.Count) constat(s)</h3><table><tr><th>Mois</th><th>CVE</th><th>Gravité</th><th>CVSS</th><th>Composant</th><th>Version</th><th>Corrigée en</th><th>État</th><th>Modules SEAL</th><th>Résumé</th></tr>")
    foreach ($l in $lc) { [void]$sb.Append("<tr class=""f""><td>$($l.Mois)</td><td><a href=""$($l.Lien)"">$(Html $l.CVE)</a>$(if ($l.KEV) { ' <span class="kev">KEV</span>' })$(if ($l.Nouveau) { ' <span class="g h">NOUVEAU</span>' })</td><td><span class=""g $($cls[$l.'Gravité'])"">$(Html $l.'Gravité')</span></td><td>$(if ($l.CVSS) { $l.CVSS } else { 'Non renseigné' })</td><td>$(Html $l.Composant)</td><td>$(Html $l.'Version installée')</td><td>$(Html $l.'Version corrigée')</td><td>$(Html $l.'État')</td><td>$(Html $l.'Modules SEAL')</td><td>$(Html $l.'Résumé')</td></tr>") }
    [void]$sb.Append('</table>')
  }
  if (@($disparues).Count) {
    [void]$sb.Append('<h2>Constats disparus depuis le rapport précédent</h2><table><tr><th>CVE</th><th>Composant</th><th>Version</th><th>Catégorie</th></tr>')
    foreach ($d in $disparues) { [void]$sb.Append("<tr><td>$(Html $d.CVE)</td><td>$(Html $d.Composant)</td><td>$(Html $d.'Version installée')</td><td>$(Html $d.'Catégorie')</td></tr>") }
    [void]$sb.Append('</table>')
  }
  [void]$sb.Append('<h2>Inventaire</h2><table><tr><th>Périmètre</th><th>Écosystème</th><th>Composant</th><th>Version</th><th>Catégorie</th><th>CVE</th><th>CVSS max</th><th>Gravité max</th><th>Version cible</th><th>Statut</th><th>Modules SEAL</th></tr>')
  foreach ($c in $inv | Sort-Object @{ e = { $_.CVE }; Descending = $true }, 'Périmètre', 'Écosystème', Composant) { [void]$sb.Append("<tr class=""f""><td>$(Html $c.'Périmètre')</td><td>$(Html $c.'Écosystème')</td><td>$(Html $c.Composant)</td><td>$(Html $c.Version)</td><td>$(Html $c.'Catégorie')</td><td>$(if ($c.CVE) { "<b>$($c.CVE)</b>" } else { 0 })</td><td>$(if ($c.CVE -and -not $c.'CVSS max') { 'Non renseigné' } else { $c.'CVSS max' })</td><td>$(Html $c.'Gravité max')</td><td>$(Html $c.'Version cible')</td><td>$(Html $c.Statut)</td><td>$(Html $c.'Modules SEAL')</td></tr>") }
  [void]$sb.Append('</table><h2>Couverture des exports</h2><table><tr><th>Fichier</th><th>Type</th><th>État</th><th>Entrées</th><th>Couverture</th></tr>')
  foreach ($e in $Exports) { [void]$sb.Append("<tr><td>$(Html $e.Fichier)</td><td>$(Html $e.Type)</td><td>$(Html $e.Etat)</td><td>$($e.Entrees)</td><td>$(Html $e.Couverture)</td></tr>") }
  [void]$sb.Append('</table><h2>Diagnostics</h2><table><tr><th>Niveau</th><th>Source</th><th>Message</th></tr>')
  foreach ($d in $Diagnostics) { [void]$sb.Append("<tr><td>$(Html $d.Niveau)</td><td>$(Html $d.Source)</td><td>$(Html $d.Message)</td></tr>") }
  [void]$sb.Append('</table></body></html>')
  [IO.File]::WriteAllText($f, $sb.ToString(), [Text.UTF8Encoding]::new($true))
}

# ============================================================================================ consolidation multi-versions
if ($Consolider) {
  $derniers = @(Get-ChildItem $Sortie -Directory | ForEach-Object { Get-ChildItem $_.FullName -Directory | Where-Object { Test-Path (Join-Path $_.FullName 'resume.json') } | Where-Object { "$((Lire-JsonFichier (Join-Path $_.FullName 'resume.json')).VersionMoteur)" -eq $MoteurVersion } | Sort-Object Name | Select-Object -Last 1 })
  $all = foreach ($d in $derniers) { $r = Lire-JsonFichier (Join-Path $d.FullName 'resume.json'); Import-Csv (Join-Path $d.FullName 'cve-detail.csv') -Delimiter ';' -Encoding UTF8 | Select-Object @{ n = 'Version SEAL'; e = { $r.VersionSeal } }, @{ n = 'Source'; e = { $r.Source } }, * }
  @($all) | Export-Csv (Join-Path $Sortie 'SEAL_toutes_versions_cve.csv') -Delimiter ';' -NoTypeInformation -Encoding UTF8
  $syn = foreach ($d in $derniers) { $r = Lire-JsonFichier (Join-Path $d.FullName 'resume.json'); $s = $r.ParCategorie
    [pscustomobject][ordered]@{ 'Version SEAL' = $r.VersionSeal; 'Source' = $r.Source; 'Collecte' = $r.DateCollecte; 'Analyse' = $r.Genere; 'Inventaire complet' = $r.InventaireComplet; 'Composants SEAL' = $r.ComposantsSEAL
      'CVE dépendances SEAL' = $s.'Dépendance SEAL'.CVE; 'Constats dépendances SEAL' = $s.'Dépendance SEAL'.Constats; 'Critiques SEAL' = $s.'Dépendance SEAL'.Critique; 'Hautes SEAL' = $s.'Dépendance SEAL'.Haute
      'Constats environnement' = $s.'Environnement'.Constats; 'Constats à confirmer' = $s.'À confirmer'.Constats; 'Corrigées / non applicables' = $s.'Corrigée / non applicable'.Constats; 'Non couverts' = $r.NonCouverts; 'Dossier' = $d.FullName } }
  @($syn) | Export-Csv (Join-Path $Sortie 'SEAL_toutes_versions_resume.csv') -Delimiter ';' -NoTypeInformation -Encoding UTF8
  Log "Consolidation : $(@($derniers).Count) rapport(s) moteur $MoteurVersion, $(@($all).Count) constats -> $Sortie"
  return
}

# ============================================================================================ programme principal
$meta = [pscustomobject]@{ Mode = ''; Source = ''; Machine = ''; OS = ''; DernierCorrectif = ''; DateCollecte = (Get-Date).ToString('yyyy-MM-dd HH:mm'); Racines = @(); Hote = $null }
if ($Inventaire) {
  $j = Lire-JsonFichier $Inventaire
  foreach ($p in $j.Composants) {
    $per = if ($p.Perimetre) { $p.Perimetre } elseif ($p.Source -match '^(Hôte|Serveur)' -or $p.Ecosysteme -eq '.NET Framework') { 'Environnement' } else { 'SEAL' }
    $idt = if ($p.Identite) { $p.Identite } elseif ($p.Source -like 'DLL *' -and $p.Ecosysteme -eq 'NuGet') { 'À confirmer' } else { 'Exacte' }
    $Inv.Add([pscustomobject]@{ Ecosysteme = $p.Ecosysteme; Composant = $p.Composant; Version = $p.Version; Perimetre = $per; Identite = $idt; Source = $p.Source; Methode = "$($p.Methode)"; Fichier = "$($p.Fichier)"; Licence = "$($p.Licence)"; Note = "$($p.Note)" })
  }
  foreach ($e in @($j.Exports)) { if ($e) { $Exports.Add($e) } }
  foreach ($x in @($j.RuntimesRequis)) { if ($x) { $RuntimesRequis.Add($x) } }
  $ver = if ($VersionSeal) { $VersionSeal } else { $j.VersionSeal }
  $meta = $j.Meta
  if (-not $meta.PSObject.Properties['DateCollecte'] -or -not $meta.DateCollecte) { $meta | Add-Member DateCollecte "inconnue (inventaire antérieur au moteur 3.0)" -Force; Diag 'Attention' 'Inventaire' 'Inventaire antérieur au moteur 3.0 : date de collecte et correctifs absents ; refaire une collecte pour une analyse complète' }
  foreach ($n in 'Mode', 'Hote', 'Racines') { if (-not $meta.PSObject.Properties[$n]) { $meta | Add-Member $n $null } }
  if (-not $meta.Mode) { $meta.Mode = if ($meta.Machine) { 'Installation' } else { 'Livraison' } }
}
else {
  if ($Artefacts) {
    $tmp = Join-Path $Cache ('artefacts_' + (Nom-Fichier (Split-Path $Artefacts -Leaf)))
    Log "Extraction des exports Dependencies / Licences de $Artefacts"
    Extraire-Exports $Artefacts $tmp
    Lire-ExportsSeal $tmp
    $ver = $VersionSeal
    if (-not $ver) { $v = @(Get-ChildItem $Artefacts -File | ForEach-Object { [regex]::Match($_.Name, '(?<!\d)(\d{2}\.\d+\.\d{4,6})(?!\d)') } | Where-Object Success | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique); if ($v.Count -eq 1) { $ver = $v[0] } elseif ($v.Count -gt 1) { throw "Plusieurs versions SEAL dans $Artefacts : préciser -VersionSeal" } }
    $meta.Mode = 'Livraison'; $meta.Source = "Livraison $((Resolve-Path $Artefacts).Path)"; $meta.Racines = @((Resolve-Path $Artefacts).Path)
  }
  else {
    $col = Inventorier-Installation; $ver = $col.Version
    $meta.Mode = 'Installation'; $meta.Source = "Installation $env:COMPUTERNAME"; $meta.Machine = $env:COMPUTERNAME; $meta.Hote = $col.Hote; $meta.Racines = $col.Racines
    $meta.OS = "$($col.Hote.ProduitOS) $($col.Hote.Build)"; $meta.DernierCorrectif = $col.DernierCorrectif
  }
  foreach ($r in $Runtimes) { if ($r -match '^\s*(\S+)\s+(\d[\w\.\-]*)') { Ajouter -Eco 'Runtime .NET' -Nom $Matches[1] -Ver $Matches[2] -Module 'Déclaration' -Perimetre 'Environnement' -Methode 'Déclaration manuelle' } }
  if ($NetFramework) { Ajouter -Eco '.NET Framework' -Nom '.NET Framework' -Ver $NetFramework -Module 'Déclaration' -Perimetre 'Environnement' -Methode 'Déclaration manuelle' }
}
Evaluer-Couverture
if (-not $Inv.Count) { throw 'Aucune dépendance trouvée (vérifier le dossier ou utiliser -RacineInstallation / -DossiersSupplementaires).' }
if (-not $ver) { $ver = 'inconnue'; Diag 'Attention' 'Version' 'Version SEAL non détectée : utiliser -VersionSeal' }
$racine = Join-Path $Sortie (Nom-Fichier ("SEAL_$ver" + $(if ($meta.Machine) { "_$($meta.Machine)" } else { '_livraison' })))
New-Item -ItemType Directory -Force $racine | Out-Null
$precedent = Get-ChildItem $racine -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName 'cve-detail.csv') } | Sort-Object Name | Select-Object -Last 1
$dest = Join-Path $racine (Get-Date -Format 'yyyy-MM-dd_HHmm')
New-Item -ItemType Directory -Force $dest | Out-Null
Ecrire-Json (Join-Path $dest 'inventaire.json') ([pscustomobject]@{ VersionSchema = $MoteurVersion; VersionSeal = $ver; Meta = $meta; Composants = $Inv; Exports = $Exports; RuntimesRequis = $RuntimesRequis })
if ($ConserverJours -gt 0) {   # rétention des rapports datés de cette version / source
  Get-ChildItem $racine -Directory | Where-Object { $_.FullName -ne $dest -and $_.Name -match '^\d{4}-\d{2}-\d{2}_\d{4}$' -and $_.LastWriteTime -lt (Get-Date).AddDays(-$ConserverJours) } | ForEach-Object { Remove-Item $_.FullName -Recurse -Force; Log "  rétention : $($_.Name) supprimé" }
}
if ($Depot) {
  try {
    $cible = Join-Path $Depot $(if ($meta.Machine) { $meta.Machine } else { 'livraison_' + (Nom-Fichier $ver) })
    New-Item -ItemType Directory -Force $cible | Out-Null
    Copy-Item (Join-Path $dest 'inventaire.json') (Join-Path $cible ("inventaire_$(Get-Date -Format 'yyyyMMdd_HHmm').json"))
    Get-ChildItem $cible -Filter 'inventaire_*.json' | Sort-Object Name -Descending | Select-Object -Skip 30 | Remove-Item -Force
    Log "Inventaire déposé : $cible"
  } catch { Log "ÉCHEC du dépôt de l'inventaire vers $Depot : $($_.Exception.Message)"; if ($InventaireSeul) { exit 2 } }
}
if ($InventaireSeul) { Log "Inventaire seul : $(Join-Path $dest 'inventaire.json') ($($Inv.Count) entrées). Analyse : .\Get-SealCveReport.ps1 -Inventaire <ce fichier>"; return }
[void](Analyser $ver $dest $meta $(if ($precedent) { $precedent.FullName } else { '' }))
if ($Presentation) {
  $gen = Join-Path $PSScriptRoot 'New-SealCvePresentation.ps1'
  if (-not (Test-Path $gen)) { Log 'New-SealCvePresentation.ps1 introuvable : présentation non générée' }
  else { try { & $gen -Rapport $dest } catch { Log "Présentation non générée : $($_.Exception.Message)" } }
}
$dest









# SIG # Begin signature block
# MIIJXQYJKoZIhvcNAQcCoIIJTjCCCUoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBbzqzGwBm85Ht4
# rI9c4l37hbF5qbxLhraJRV36XQ38R6CCBpIwggaOMIIFdqADAgECAhNVAABq4hV6
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
# DAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgZrgnDp3k3a+Emx3Mnq8+VlEU
# t4eUFmNJ0YK+2r2CVNQwDQYJKoZIhvcNAQEBBQAEggEAGaxqZdinuxIFHqMvO2pY
# VMI+uc4uIdJzZvD3j//Z0tDOY/OpaztCrgWIlSkiwsZd3hhSnpnCjIIZIfjJVaSV
# 7/WeL3oh01oZps3HMifLPdYBkiEAuAZgITDsNzwWNuwRW3vWWflha4GtzCq4t62O
# yrPcVatLauaJKR5QmzxOeDdqCxh/+TeP42PlsYBDMXXF5f6boxnehUvy41NHwpK+
# yCMbGskn96jkhkWx3e19GBMRcl+gx8U+q1AjP59GJ71smJqRoVXD7FwdhywG3WJr
# RJNduEK0KrHy5B6pwy9VGzZ9T8r3H3OYYyF2EnTiK8LK0kZE+6sPOSDpkjWjrvNe
# fw==
# SIG # End signature block
