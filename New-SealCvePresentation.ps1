<#
.SYNOPSIS
  Génère la synthèse et les annexes PowerPoint « SEAL <version> : CVE des dépendances » à partir d'un rapport de
  Get-SealCveReport.ps1 (moteur 3.x).

.DESCRIPTION
  Écrit directement les fichiers .pptx (Open XML) : aucun Office requis, utilisable sur un serveur ou dans une tâche
  planifiée. Un seul modèle pour toutes les versions :
    <rapport>\SEAL_<version>_CVE_<date>_synthese.pptx   12 à 16 diapositives : synthèse, couverture, dépendances SEAL
                                                         par mois, priorités, environnement, à confirmer, plan d'action
    <rapport>\SEAL_<version>_CVE_<date>_annexes.pptx    tableaux complets : un constat par ligne, corrections KB,
                                                         composants non couverts, couverture des exports, diagnostics
  Les chiffres viennent exclusivement des CSV / JSON du rapport. Avant toute génération, les compteurs sont recontrôlés
  (catégories, mois, inventaire) : en cas d'écart, la génération s'arrête (sauf -Forcer, qui ajoute un avertissement).

.EXAMPLE
  .\New-SealCvePresentation.ps1 -Rapport 'C:\SEAL\Rapports\SEAL_45.0.25468_BX-SEAL-OMEGA'
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$Rapport,       # dossier d'un rapport, ou dossier parent (rapport le plus récent)
  [switch]$Synthese,                            # uniquement la synthèse
  [switch]$Annexes,                             # uniquement les annexes
  [switch]$Forcer,
  [int]$LignesParDiapo = 13
)
$ErrorActionPreference = 'Stop'
function Log([string]$m) { Write-Host ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $m) }
if (-not $Synthese -and -not $Annexes) { $Synthese = $true; $Annexes = $true }

# ------------------------------------------------------------------------------------------- données
if (-not (Test-Path (Join-Path $Rapport 'resume.json'))) {
  $d = Get-ChildItem $Rapport -Directory | Where-Object { Test-Path (Join-Path $_.FullName 'resume.json') } | Sort-Object Name | Select-Object -Last 1
  if (-not $d) { throw "Aucun rapport (resume.json) dans $Rapport" }
  $Rapport = $d.FullName
}
$Inv = [Globalization.CultureInfo]::InvariantCulture
function Num($v) { $s = "$v".Trim() -replace ',', '.'; $r = 0.0; if ($s -and [double]::TryParse($s, [Globalization.NumberStyles]::Float, $Inv, [ref]$r)) { $r } else { $null } }
function CleV([string]$v) { $p = @(([regex]::Match($v, '\d+(\.\d+){0,3}').Value).Split('.') | Where-Object { $_ }); while ($p.Count -lt 4) { $p += '0' }; try { [version]($p[0..3] -join '.') } catch { [version]'0.0.0.0' } }
function Lire([string]$n) { $f = Join-Path $Rapport $n; if (Test-Path $f) { @(Import-Csv $f -Delimiter ';' -Encoding UTF8) } else { @() } }
$Resume = Get-Content (Join-Path $Rapport 'resume.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ("$($Resume.VersionMoteur)" -notmatch '^3\.') { throw "Rapport produit par le moteur $($Resume.VersionMoteur) : relancer Get-SealCveReport.ps1 (moteur 3.x) pour obtenir un rapport comparable." }
$Constats = Lire 'cve-detail.csv'; $Inventaire = Lire 'inventaire.csv'; $Dotnet = Lire 'dotnet.csv'; $Disparus = Lire 'cve-disparues.csv'
$ExportsRap = Lire 'exports.csv'; $Diags = @(Lire 'diagnostic.csv' | Where-Object { $_.Niveau -ne 'Information' })
$Seal = @($Constats | Where-Object { $_.'Catégorie' -eq 'Dépendance SEAL' })
$EnvSrv = @($Constats | Where-Object { $_.'Catégorie' -eq 'Environnement' })
$AConf = @($Constats | Where-Object { $_.'Catégorie' -eq 'À confirmer' })
$Corr = @($Constats | Where-Object { $_.'Catégorie' -eq 'Corrigée / non applicable' })
$Pc = $Resume.ParCategorie
$Sev = [ordered]@{ 'Critique' = 'B3261E'; 'Haute' = 'D9480F'; 'Moyenne' = 'E6A100'; 'Basse' = '5C8A2D'; 'Non renseignée' = '8A94A0' }
$Rang = @{ 'Critique' = 4; 'Haute' = 3; 'Moyenne' = 2; 'Basse' = 1; 'Non renseignée' = 0 }
$moisFr = 'janvier', 'février', 'mars', 'avril', 'mai', 'juin', 'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre'
$moisCourt = 'janv', 'févr', 'mars', 'avr', 'mai', 'juin', 'juil', 'août', 'sept', 'oct', 'nov', 'déc'
function NomMois([string]$m) { "$($moisFr[[int]$m.Substring(5,2) - 1]) $($m.Substring(0,4))" }
function Court([string]$s) { $s -replace '^System\.Security\.Cryptography\.', 'S.S.Cryptography.' -replace '^Microsoft\.', 'MS.' }
function Uniques($l) { @($l | Sort-Object -Unique) }
$genere = [datetime]::ParseExact($Resume.Genere, 'yyyy-MM-dd HH:mm', $Inv)
$sourceTxt = if ($Resume.Machine) { "serveur $($Resume.Machine)" } else { 'livraison (exports de build)' }
$Pied = "SEAL $($Resume.VersionSeal) · $sourceTxt · CVE au $($genere.ToString('dd/MM/yyyy')) · moteur $($Resume.VersionMoteur)"

# ------------------------------------------------------------------------------------------- contrôle des compteurs
$ecarts = New-Object Collections.Generic.List[string]
foreach ($cat in 'Dépendance SEAL', 'Environnement', 'À confirmer', 'Corrigée / non applicable') {
  $l = @($Constats | Where-Object { $_.'Catégorie' -eq $cat }); $s = $Pc.$cat
  if ($l.Count -ne [int]$s.Constats) { $ecarts.Add("$cat : $($l.Count) constats dans le CSV, $($s.Constats) dans le résumé") }
  $nCve = @(Uniques ($l.CVE | Where-Object { $_ -like 'CVE-*' })).Count; if ($nCve -ne [int]$s.CVE) { $ecarts.Add("$cat : $nCve CVE dans le CSV, $($s.CVE) dans le résumé") }
}
if ($Constats.Count -ne [int]$Resume.Constats) { $ecarts.Add("Total : $($Constats.Count) constats dans le CSV, $($Resume.Constats) dans le résumé") }
if (-not $Resume.ControlesOK) { $ecarts.Add('Contrôles du moteur en échec (controles.csv)') }
if ($ecarts.Count) { if ($Forcer) { $ecarts | ForEach-Object { Log "ÉCART : $_" } } else { throw ("Compteurs incohérents, présentation non générée :`n - " + ($ecarts -join "`n - ")) } }

# ------------------------------------------------------------------------------------------- PowerPoint (Open XML, sans Office)
# Le fichier .pptx est écrit directement (ZIP + XML) : aucun Office requis, utilisable sur un serveur ou une tâche planifiée.
# Coordonnées en points (diapositive 960 × 540 pt, 16:9) ; 1 pt = 12 700 EMU.
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.Drawing
$Navy = '14213D'; $CoulTexte = '1B2430'; $Gris = '8A94A0'; $Fond = 'EEF1F5'; $Lien = '1F5FA8'; $Blanc = 'FFFFFF'; $Orange = 'D9480F'; $Rouge = 'B3261E'; $Bleu = '3B5B8C'
function X([string]$s) { [Security.SecurityElement]::Escape(($s -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', '')) }
function Emu($pt) { [long][math]::Round([double]$pt * 12700) }
$script:gfx = [Drawing.Graphics]::FromImage((New-Object Drawing.Bitmap 1, 1)); $script:gfx.PageUnit = [Drawing.GraphicsUnit]::Point
$script:polices = @{}
# Hauteur (pt) occupée par un texte dans une largeur donnée : sert à empiler les blocs comme le faisait l'ajustement automatique
function Mesurer([string]$t, $largeur, $taille, [bool]$gras = $false, [string]$police = 'Calibri') {
  if (-not $t) { return 0 }
  $k = "$police|$taille|$gras"
  if (-not $script:polices.ContainsKey($k)) { $script:polices[$k] = New-Object Drawing.Font($police, [single]$taille, $(if ($gras) { [Drawing.FontStyle]::Bold } else { [Drawing.FontStyle]::Regular }), [Drawing.GraphicsUnit]::Point) }
  $h = 0.0
  foreach ($ligne in ($t -split "`r`n|`r|`n")) { $h += [math]::Max([double]$taille * 1.2, $script:gfx.MeasureString($(if ($ligne) { $ligne } else { ' ' }), $script:polices[$k], [int]$largeur).Height) }
  $h
}
function Nouvelle-Presentation { $script:slides = New-Object Collections.Generic.List[object]; $script:n = 0 }
function Nouvel-Id { $script:idForme++; $script:idForme }
$script:idForme = 1
# Une portion de texte (run) ; un lien ajoute une relation à la diapositive
function Run($sl, [string]$t, $taille, [bool]$gras = $false, [string]$coul = $CoulTexte, [string]$police = 'Calibri', [bool]$ital = $false, [string]$lien = '') {
  $lk = ''; $u = ''
  if ($lien) { $rid = "rIdL$($sl.Liens.Count + 1)"; $sl.Liens.Add([pscustomobject]@{ Id = $rid; Cible = $lien }); $lk = "<a:hlinkClick r:id=""$rid""/>"; $u = ' u="sng"' }
  "<a:r><a:rPr lang=""fr-FR"" sz=""$([int]([double]$taille * 100))""$(if ($gras) { ' b="1"' })$(if ($ital) { ' i="1"' })$u dirty=""0""><a:solidFill><a:srgbClr val=""$coul""/></a:solidFill><a:latin typeface=""$police""/><a:cs typeface=""$police""/>$lk</a:rPr><a:t>$(X $t)</a:t></a:r>"
}
function Para([string]$runs, [string]$algn = 'l', $taille = 12) { "<a:p><a:pPr algn=""$algn""><a:spcBef><a:spcPts val=""0""/></a:spcBef><a:spcAft><a:spcPts val=""0""/></a:spcAft></a:pPr>$runs<a:endParaRPr lang=""fr-FR"" sz=""$([int]([double]$taille * 100))"" dirty=""0""/></a:p>" }
function Algn($a) { switch ([int]$a) { 2 { 'ctr' } 3 { 'r' } default { 'l' } } }
function Xfrm($x, $y, $w, $h) { "<a:xfrm><a:off x=""$(Emu $x)"" y=""$(Emu $y)""/><a:ext cx=""$(Emu $w)"" cy=""$(Emu $h)""/></a:xfrm>" }
# Zone de texte : paragraphes = tableau de @{ T; Taille; Gras; Coul; Police; Ital }
function TexteRiche($sl, $paras, $x, $y, $w, $h, $align = 1, [string]$ancre = 't') {
  $id = Nouvel-Id
  $p = (@($paras | ForEach-Object { $q = $_; Para (Run $sl "$($q.T)" $q.Taille ([bool]$q.Gras) $(if ($q.Coul) { $q.Coul } else { $CoulTexte }) $(if ($q.Police) { $q.Police } else { 'Calibri' }) ([bool]$q.Ital)) (Algn $align) $q.Taille })) -join ''
  [void]$sl.Xml.Append("<p:sp><p:nvSpPr><p:cNvPr id=""$id"" name=""Texte $id""/><p:cNvSpPr txBox=""1""/><p:nvPr/></p:nvSpPr><p:spPr>$(Xfrm $x $y $w $h)<a:prstGeom prst=""rect""><a:avLst/></a:prstGeom><a:noFill/></p:spPr><p:txBody><a:bodyPr wrap=""square"" lIns=""0"" tIns=""0"" rIns=""0"" bIns=""0"" anchor=""$ancre""><a:noAutofit/></a:bodyPr><a:lstStyle/>$p</p:txBody></p:sp>")
}
function Texte($sl, [string]$t, $x, $y, $w, $h, $taille = 14, [switch]$Gras, $coul = $CoulTexte, $align = 1, $police = 'Calibri', [switch]$Italique) {
  $paras = @($t -split "`r`n|`r|`n" | ForEach-Object { @{ T = $_; Taille = $taille; Gras = [bool]$Gras; Coul = $coul; Police = $police; Ital = [bool]$Italique } })
  TexteRiche $sl $paras $x $y $w $h $align
}
# Titre de paragraphe en gras + corps ; renvoie la hauteur occupée
function Bloc($sl, [string]$titre, [string]$corps, $x, $y, $w, $coulTitre = $Navy, $taille = 13) {
  $paras = @(@{ T = $titre; Taille = $taille + 1; Gras = $true; Coul = $coulTitre }) + @(if ($corps) { $corps -split "`r`n|`r|`n" | ForEach-Object { @{ T = $_; Taille = $taille } } })
  $h = (Mesurer $titre $w ($taille + 1) $true) + (Mesurer $corps $w $taille)
  TexteRiche $sl $paras $x $y $w $h
  $h
}
function Forme($sl, [string]$geom, $x, $y, $w, $h, [string]$coul, [string]$texte = '', $taille = 16, [string]$adj = '') {
  $id = Nouvel-Id
  $av = if ($adj) { "<a:avLst><a:gd name=""adj"" fmla=""val $adj""/></a:avLst>" } else { '<a:avLst/>' }
  $tx = if ($texte) { "<p:txBody><a:bodyPr lIns=""0"" tIns=""0"" rIns=""0"" bIns=""0"" anchor=""ctr""/><a:lstStyle/>$(Para (Run $sl $texte $taille $true $Blanc) 'ctr' $taille)</p:txBody>" } else { '' }
  [void]$sl.Xml.Append("<p:sp><p:nvSpPr><p:cNvPr id=""$id"" name=""Forme $id""/><p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:spPr>$(Xfrm $x $y $w $h)<a:prstGeom prst=""$geom"">$av</a:prstGeom><a:solidFill><a:srgbClr val=""$coul""/></a:solidFill><a:ln><a:noFill/></a:ln></p:spPr>$tx</p:sp>")
}
function Boite($sl, $x, $y, $w, $h, $coul = $Fond) { Forme $sl 'roundRect' $x $y $w $h $coul '' 16 '6000' }
function Rect($sl, $x, $y, $w, $h, $coul) { Forme $sl 'rect' $x $y $w $h $coul }
function Pastille($sl, $x, $y, $d, $coul, [string]$texte) { Forme $sl 'ellipse' $x $y $d $d $coul $texte 16 }
function Ligne($sl, $x1, $y1, $x2, $coul) {
  $id = Nouvel-Id
  [void]$sl.Xml.Append("<p:cxnSp><p:nvCxnSpPr><p:cNvPr id=""$id"" name=""Ligne $id""/><p:cNvCxnSpPr/><p:nvPr/></p:nvCxnSpPr><p:spPr>$(Xfrm $x1 $y1 ($x2 - $x1) 0)<a:prstGeom prst=""line""><a:avLst/></a:prstGeom><a:ln w=""9525""><a:solidFill><a:srgbClr val=""$coul""/></a:solidFill></a:ln></p:spPr></p:cxnSp>")
}
function Diapo([string]$titre, [switch]$Sombre) {
  $script:n++
  $sl = [pscustomobject]@{ Xml = New-Object Text.StringBuilder; Liens = New-Object Collections.Generic.List[object]; Fond = $(if ($Sombre) { $Navy } else { $Blanc }) }
  $script:slides.Add($sl)
  if (-not $Sombre) {
    Texte $sl $titre 43 22 875 48 28 -Gras $Navy 1 'Cambria'
    Texte $sl $Pied 43 508 760 16 10 -coul $Gris
    Texte $sl "$script:n" 860 508 58 16 10 -coul $Gris -align 3
  }
  $sl
}
# $lignes : tableaux de cellules ; cellule = chaîne ou @{ T = texte; F = fond; C = couleur; B = gras; A = alignement; Liens = @(@(texte,url),…) }
# La hauteur des lignes (18 pt) est un minimum : PowerPoint l'agrandit à l'ouverture si le texte passe à la ligne.
function Tableau($sl, [string[]]$entetes, $lignes, $x, $y, [double[]]$largeurs, $taille = 10.5) {
  if (@($lignes).Count -and $lignes[0] -isnot [Collections.IList]) { $lignes = , @($lignes) }   # une seule ligne : PowerShell aplatit le tableau
  $id = Nouvel-Id
  $bord = '<a:solidFill><a:srgbClr val="FFFFFF"/></a:solidFill>'
  $lnx = (@('lnL', 'lnR', 'lnT', 'lnB') | ForEach-Object { "<a:$_ w=""12700"" cap=""flat"" cmpd=""sng"" algn=""ctr"">$bord<a:prstDash val=""solid""/></a:$_>" }) -join ''
  $sb = New-Object Text.StringBuilder
  $toutes = @(, @($entetes | ForEach-Object { @{ T = $_; F = $Navy; C = $Blanc; B = $true } })) + @($lignes)
  for ($r = 0; $r -lt $toutes.Count; $r++) {
    [void]$sb.Append("<a:tr h=""$(Emu 18)"">")
    for ($c = 0; $c -lt $entetes.Count; $c++) {
      $v = $toutes[$r][$c]; if ($v -isnot [hashtable]) { $v = @{ T = "$v" } }
      $fondCellule = if ($v.F) { $v.F } elseif ($r % 2 -eq 1) { $Fond } else { $Blanc }
      $al = if ($v.A) { Algn $v.A } else { 'l' }
      if ($v.Liens) {
        $runs = New-Object Text.StringBuilder; $i = 0
        foreach ($k in $v.Liens) { if ($i++) { [void]$runs.Append((Run $sl ', ' ($taille - 1))) }; [void]$runs.Append((Run $sl $k[0] ($taille - 1) $false $Lien 'Calibri' $false $k[1])) }
        if ($v.T) { [void]$runs.Append((Run $sl "$($v.T)" ($taille - 1) $false $CoulTexte)) }
        $p = Para $runs.ToString() $al ($taille - 1)
      } else { $p = Para (Run $sl "$($v.T)" $taille ([bool]$v.B) $(if ($v.C) { $v.C } else { $CoulTexte })) $al $taille }
      [void]$sb.Append("<a:tc><a:txBody><a:bodyPr/><a:lstStyle/>$p</a:txBody><a:tcPr marL=""63500"" marR=""50800"" marT=""25400"" marB=""25400"" anchor=""ctr"">$lnx<a:solidFill><a:srgbClr val=""$fondCellule""/></a:solidFill></a:tcPr></a:tc>")
    }
    [void]$sb.Append('</a:tr>')
  }
  $grille = (@($largeurs | ForEach-Object { "<a:gridCol w=""$(Emu $_)""/>" }) -join '')
  $w = ($largeurs | Measure-Object -Sum).Sum
  [void]$sl.Xml.Append("<p:graphicFrame><p:nvGraphicFramePr><p:cNvPr id=""$id"" name=""Tableau $id""/><p:cNvGraphicFramePr><a:graphicFrameLocks noGrp=""1""/></p:cNvGraphicFramePr><p:nvPr/></p:nvGraphicFramePr><p:xfrm><a:off x=""$(Emu $x)"" y=""$(Emu $y)""/><a:ext cx=""$(Emu $w)"" cy=""$(Emu (18 * $toutes.Count))""/></p:xfrm><a:graphic><a:graphicData uri=""http://schemas.openxmlformats.org/drawingml/2006/table""><a:tbl><a:tblPr firstRow=""1""/><a:tblGrid>$grille</a:tblGrid>$($sb.ToString())</a:tbl></a:graphicData></a:graphic></p:graphicFrame>")
}
# Cellule de gravité : score CVSS s'il est connu, sinon « n.r. » (non renseigné) sur la couleur de la gravité publiée
function CelSev([string]$cvss, [string]$grav) { $g = if ($Sev.Contains($grav)) { $grav } else { 'Non renseignée' }; @{ T = $(if ($cvss) { $cvss } else { 'n.r.' }); F = $Sev[$g]; C = $Blanc; B = $true; A = 2 } }
function Paquets($liste, [int]$taille) { $p = @(); for ($i = 0; $i -lt @($liste).Count; $i += $taille) { $p += , @($liste[$i..([math]::Min($i + $taille, @($liste).Count) - 1)]) }; , $p }
function Tableau-Pagine([string]$titre, [string[]]$entetes, $lignes, [double[]]$largeurs, [int]$parPage, $taille = 10, [string]$note = '') {
  if (-not @($lignes).Count) { return }
  $pages = Paquets $lignes $parPage; $i = 0
  foreach ($pg in $pages) {
    $i++; $sl = Diapo $(if ($pages.Count -gt 1) { "$titre ($i/$($pages.Count))" } else { $titre })
    Tableau $sl $entetes $pg 43 82 $largeurs $taille
    if ($note) { Texte $sl $note 43 486 875 16 10 -coul $Gris -Italique }
  }
}
# Écriture du paquet .pptx (thème, masque, disposition vierge, diapositives)
function Enregistrer([string]$suffixe) {
  $f = Join-Path $Rapport ("SEAL_$($Resume.VersionSeal)_CVE_$($genere.ToString('yyyy-MM-dd'))_$suffixe.pptx")
  $ns = 'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"'
  $grp = '<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>'
  $rel = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'
  $e = [ordered]@{}
  $e['_rels/.rels'] = "<Relationships xmlns=""http://schemas.openxmlformats.org/package/2006/relationships""><Relationship Id=""rId1"" Type=""$rel/officeDocument"" Target=""ppt/presentation.xml""/><Relationship Id=""rId2"" Type=""http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties"" Target=""docProps/core.xml""/><Relationship Id=""rId3"" Type=""$rel/extended-properties"" Target=""docProps/app.xml""/></Relationships>"
  $d = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
  $e['docProps/core.xml'] = "<cp:coreProperties xmlns:cp=""http://schemas.openxmlformats.org/package/2006/metadata/core-properties"" xmlns:dc=""http://purl.org/dc/elements/1.1/"" xmlns:dcterms=""http://purl.org/dc/terms/"" xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance""><dc:title>$(X "SEAL $($Resume.VersionSeal) - CVE des dépendances")</dc:title><dc:creator>SEAL CVE</dc:creator><dcterms:created xsi:type=""dcterms:W3CDTF"">$d</dcterms:created><dcterms:modified xsi:type=""dcterms:W3CDTF"">$d</dcterms:modified></cp:coreProperties>"
  $e['docProps/app.xml'] = "<Properties xmlns=""http://schemas.openxmlformats.org/officeDocument/2006/extended-properties""><Application>SEAL CVE</Application><PresentationFormat>Grand écran</PresentationFormat><Slides>$($script:slides.Count)</Slides></Properties>"
  $e['ppt/theme/theme1.xml'] = '<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="SEAL"><a:themeElements><a:clrScheme name="SEAL"><a:dk1><a:srgbClr val="1B2430"/></a:dk1><a:lt1><a:srgbClr val="FFFFFF"/></a:lt1><a:dk2><a:srgbClr val="14213D"/></a:dk2><a:lt2><a:srgbClr val="EEF1F5"/></a:lt2><a:accent1><a:srgbClr val="3B5B8C"/></a:accent1><a:accent2><a:srgbClr val="D9480F"/></a:accent2><a:accent3><a:srgbClr val="B3261E"/></a:accent3><a:accent4><a:srgbClr val="E6A100"/></a:accent4><a:accent5><a:srgbClr val="5C8A2D"/></a:accent5><a:accent6><a:srgbClr val="8A94A0"/></a:accent6><a:hlink><a:srgbClr val="1F5FA8"/></a:hlink><a:folHlink><a:srgbClr val="6B4C9A"/></a:folHlink></a:clrScheme><a:fontScheme name="SEAL"><a:majorFont><a:latin typeface="Cambria"/><a:ea typeface=""/><a:cs typeface=""/></a:majorFont><a:minorFont><a:latin typeface="Calibri"/><a:ea typeface=""/><a:cs typeface=""/></a:minorFont></a:fontScheme><a:fmtScheme name="SEAL"><a:fillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:fillStyleLst><a:lnStyleLst><a:ln w="6350"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln><a:ln w="12700"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln><a:ln w="19050"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln></a:lnStyleLst><a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst><a:bgFillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:bgFillStyleLst></a:fmtScheme></a:themeElements></a:theme>'
  $e['ppt/slideMasters/slideMaster1.xml'] = "<p:sldMaster $ns><p:cSld><p:spTree>$grp</p:spTree></p:cSld><p:clrMap bg1=""lt1"" tx1=""dk1"" bg2=""lt2"" tx2=""dk2"" accent1=""accent1"" accent2=""accent2"" accent3=""accent3"" accent4=""accent4"" accent5=""accent5"" accent6=""accent6"" hlink=""hlink"" folHlink=""folHlink""/><p:sldLayoutIdLst><p:sldLayoutId id=""2147483649"" r:id=""rId1""/></p:sldLayoutIdLst><p:txStyles><p:titleStyle/><p:bodyStyle/><p:otherStyle/></p:txStyles></p:sldMaster>"
  $e['ppt/slideMasters/_rels/slideMaster1.xml.rels'] = "<Relationships xmlns=""http://schemas.openxmlformats.org/package/2006/relationships""><Relationship Id=""rId1"" Type=""$rel/slideLayout"" Target=""../slideLayouts/slideLayout1.xml""/><Relationship Id=""rId2"" Type=""$rel/theme"" Target=""../theme/theme1.xml""/></Relationships>"
  $e['ppt/slideLayouts/slideLayout1.xml'] = "<p:sldLayout $ns type=""blank"" preserve=""1""><p:cSld name=""Vierge""><p:spTree>$grp</p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>"
  $e['ppt/slideLayouts/_rels/slideLayout1.xml.rels'] = "<Relationships xmlns=""http://schemas.openxmlformats.org/package/2006/relationships""><Relationship Id=""rId1"" Type=""$rel/slideMaster"" Target=""../slideMasters/slideMaster1.xml""/></Relationships>"
  $ids = New-Object Text.StringBuilder; $prels = New-Object Text.StringBuilder
  $types = New-Object Text.StringBuilder
  [void]$types.Append('<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/><Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/><Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/><Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>')
  for ($i = 0; $i -lt $script:slides.Count; $i++) {
    $k = $i + 1; $sl = $script:slides[$i]
    $e["ppt/slides/slide$k.xml"] = "<p:sld $ns><p:cSld><p:bg><p:bgPr><a:solidFill><a:srgbClr val=""$($sl.Fond)""/></a:solidFill><a:effectLst/></p:bgPr></p:bg><p:spTree>$grp$($sl.Xml.ToString())</p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>"
    $sr = "<Relationships xmlns=""http://schemas.openxmlformats.org/package/2006/relationships""><Relationship Id=""rIdLayout"" Type=""$rel/slideLayout"" Target=""../slideLayouts/slideLayout1.xml""/>"
    foreach ($l in $sl.Liens) { $sr += "<Relationship Id=""$($l.Id)"" Type=""$rel/hyperlink"" Target=""$(X $l.Cible)"" TargetMode=""External""/>" }
    $e["ppt/slides/_rels/slide$k.xml.rels"] = $sr + '</Relationships>'
    [void]$ids.Append("<p:sldId id=""$(255 + $k)"" r:id=""rIdS$k""/>"); [void]$prels.Append("<Relationship Id=""rIdS$k"" Type=""$rel/slide"" Target=""slides/slide$k.xml""/>")
    [void]$types.Append("<Override PartName=""/ppt/slides/slide$k.xml"" ContentType=""application/vnd.openxmlformats-officedocument.presentationml.slide+xml""/>")
  }
  $e['ppt/presentation.xml'] = "<p:presentation $ns saveSubsetFonts=""1""><p:sldMasterIdLst><p:sldMasterId id=""2147483648"" r:id=""rIdM""/></p:sldMasterIdLst><p:sldIdLst>$($ids.ToString())</p:sldIdLst><p:sldSz cx=""12192000"" cy=""6858000""/><p:notesSz cx=""6858000"" cy=""9144000""/><p:defaultTextStyle/></p:presentation>"
  $e['ppt/_rels/presentation.xml.rels'] = "<Relationships xmlns=""http://schemas.openxmlformats.org/package/2006/relationships""><Relationship Id=""rIdM"" Type=""$rel/slideMaster"" Target=""slideMasters/slideMaster1.xml""/><Relationship Id=""rIdT"" Type=""$rel/theme"" Target=""theme/theme1.xml""/>$($prels.ToString())</Relationships>"
  $e['[Content_Types].xml'] = $types.ToString() + '</Types>'
  $tmp = "$f.tmp"; if (Test-Path $tmp) { Remove-Item $tmp -Force }
  $zip = [IO.Compression.ZipFile]::Open($tmp, [IO.Compression.ZipArchiveMode]::Create)
  try {
    foreach ($nom in @('[Content_Types].xml') + @($e.Keys | Where-Object { $_ -ne '[Content_Types].xml' })) {
      $w = New-Object IO.StreamWriter(($zip.CreateEntry($nom, [IO.Compression.CompressionLevel]::Optimal)).Open(), (New-Object Text.UTF8Encoding($false)))
      try { $w.Write('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' + $e[$nom]) } finally { $w.Dispose() }
    }
  } finally { $zip.Dispose() }
  Move-Item $tmp $f -Force
  Log "Présentation : $f ($script:n diapositives)"; $f
}

# Ligne de constat (annexes) : mois, CVE cliquable, gravité, composant, version, correction, état ou modules
function Modules-Courts([string]$m) { $t = @($m -split ', ' | Where-Object { $_ }); if ($t.Count -gt 3) { (($t | Select-Object -First 3) -join ' · ') + " +$($t.Count - 3)" } else { $t -join ' · ' } }
function Ligne-Constat($l, [string]$derniere) { if ($l.KEV -eq 'OUI') { $derniere = "KEV · $derniere" }; , @($l.Mois, @{ T = ''; Liens = @(, @($l.CVE, $l.Lien)) }, (CelSev $l.CVSS $l.'Gravité'), (Court $l.Composant), $l.'Version installée', $(if ($l.'Version corrigée') { $l.'Version corrigée' } else { '—' }), $derniere) }

$vulnSeal = @($Inventaire | Where-Object { $_.'Catégorie' -eq 'Dépendance SEAL' })
$eol = @($Dotnet | Where-Object HorsSupport -eq 'OUI')
$fichiers = @()

# =========================================================================================== SYNTHÈSE
if ($Synthese) {
  Nouvelle-Presentation
  # ---- 1. titre
  $sl = Diapo '' -Sombre
  [void](Texte $sl "SEAL $($Resume.VersionSeal) : CVE des dépendances" 58 175 845 70 40 -Gras $Blanc 1 'Cambria')
  [void](Texte $sl 'Dépendances SEAL (NuGet, npm, C++) et environnement .NET, CVE classées par mois' 58 255 845 30 20 -coul 'CADCFC')
  [void](Texte $sl "Source : $sourceTxt$(if ($Resume.OS) { " ($($Resume.OS))" }) · collecte du $($Resume.DateCollecte) · CVE au $($genere.ToString('dd/MM/yyyy'))" 58 292 845 40 14 -coul 'A9B8D6')
  if (-not $Resume.InventaireComplet) { [void](Texte $sl "Inventaire incomplet : $($Resume.ExportsVides) export(s) de dépendances vide(s). Voir « Périmètre et couverture »." 58 345 845 24 14 -Gras 'F5A97F') }

  # ---- 2. synthèse : chiffres du périmètre SEAL uniquement
  $s = $Pc.'Dépendance SEAL'
  $sl = Diapo 'Synthèse : dépendances SEAL'
  $kpi = @(@($Resume.ComposantsSEAL, 'composants SEAL inventoriés', $Bleu), @($s.Composants, 'composants SEAL vulnérables', $Orange), @($s.CVE, 'CVE distinctes', $Navy),
    @($s.Critique, 'constats critiques', $Rouge), @($s.Haute, 'constats hauts', $Orange), @($s.KEV, 'CVE exploitées (KEV)', '000000'))
  for ($i = 0; $i -lt 6; $i++) {
    $x = 43 + ($i % 3) * 148; $y = 95 + [math]::Floor($i / 3) * 126
    [void](Boite $sl $x $y 134 112)
    [void](Texte $sl "$($kpi[$i][0])" $x ($y + 12) 134 52 36 -Gras $kpi[$i][2] 2 'Cambria')
    [void](Texte $sl $kpi[$i][1] ($x + 8) ($y + 70) 118 34 12 -align 2)
  }
  [void](Texte $sl "Hors de ces chiffres : environnement serveur $($Pc.'Environnement'.Constats) constat(s)$(if ($Pc.'Environnement'.KEV) { " (dont $($Pc.'Environnement'.KEV) CVE KEV)" }) · à confirmer $($Pc.'À confirmer'.Constats) · corrigés ou non applicables $($Pc.'Corrigée / non applicable'.Constats) · non couverts $($Resume.NonCouverts) composant(s)" 43 352 430 48 12 -coul $Gris -Italique)
  $msgs = New-Object Collections.Generic.List[object]
  if (-not $Resume.InventaireComplet) { $msgs.Add(@('Inventaire incomplet', "$($Resume.ExportsVides) export(s) de dépendances vide(s) : la couverture de ces modules repose sur des listes de licences ou n'est pas démontrée.", $Rouge)) }
  foreach ($g in @($vulnSeal | Sort-Object @{ e = { $Rang[$_.'Gravité max'] }; Descending = $true }, @{ e = { [int]$_.CVE }; Descending = $true } | Group-Object Composant | Select-Object -First 3)) {
    $c = $g.Group[0]; $cib = if ($c.'Version cible') { $c.'Version cible' } else { 'à déterminer' }
    $msgs.Add(@("$($g.Name) $(@($g.Group.Version) -join ', ')", "$((@($g.Group.CVE) | ForEach-Object { [int]$_ } | Measure-Object -Sum).Sum) CVE, gravité max $($c.'Gravité max')$(if ($c.'CVSS max') { " (CVSS $($c.'CVSS max'))" }). Cible : $cib.", $Orange))
  }
  if ($eol.Count) { $msgs.Add(@('Environnement : runtimes .NET hors support', (((@($eol | ForEach-Object { "$($_.Runtime -replace '^Microsoft\.', '') $($_.Version)" } | Select-Object -Unique)) -join ', ') + '. Hors périmètre SEAL, mais à traiter sur le serveur.' + $(if ($Pc.'Environnement'.KEV) { " Dont $($Pc.'Environnement'.KEV) CVE exploitée(s) activement (KEV)." } else { '' })), $Bleu)) }
  $y = 95
  for ($k = 0; $k -lt [math]::Min(5, $msgs.Count); $k++) { $m = $msgs[$k]; $y += (Bloc $sl $m[0] $m[1] 500 $y 418 $m[2]) + 12; if ($y -gt 440) { break } }

  # ---- 3. périmètre et couverture : les 4 catégories, l'état des exports, la comparabilité
  $sl = Diapo 'Périmètre et couverture de l''analyse'
  $rows = @(foreach ($cat in 'Dépendance SEAL', 'Environnement', 'À confirmer', 'Corrigée / non applicable') { $st = $Pc.$cat; , @(@{ T = $cat; B = $true }, @{ T = "$($st.CVE)"; A = 2 }, @{ T = "$($st.Constats)"; A = 2 }, @{ T = "$($st.Composants)"; A = 2 }, @{ T = "$($st.Critique)"; A = 2 }, @{ T = "$($st.Haute)"; A = 2 }, @{ T = "$($st.KEV)"; A = 2 }) })
  $tab = Tableau $sl @('Catégorie', 'CVE', 'Constats', 'Composants', 'Critique', 'Haute', 'KEV') $rows 43 82 @(190, 70, 70, 80, 65, 60, 55) 10.5
  $y = 82
  $y += (Bloc $sl 'Lecture' 'Dépendance SEAL : composant livré par SEAL, identité exacte. Environnement : runtimes et .NET Framework du serveur. À confirmer : identité ou applicabilité non démontrée. Corrigée / non applicable : KB .NET installé ou produit absent de l''avis.' 660 $y 258 $Navy 11) + 10
  $etatExports = if ($Resume.InventaireComplet) { "$($Resume.ExportsLus) export(s) lus, aucun vide." } else { "$($Resume.ExportsLus) export(s) lus, $($Resume.ExportsVides) vide(s) ou invalide(s)." }
  $y += (Bloc $sl 'Couverture des exports' $etatExports 660 $y 258 $(if ($Resume.InventaireComplet) { $Navy } else { $Rouge }) 11) + 10
  $comp = if (-not $Resume.RapportPrecedent) { "Premier rapport de cette source avec le moteur $($Resume.VersionMoteur)." } elseif ($Resume.HistoriqueComparable) { "Comparé au rapport $($Resume.RapportPrecedent) : $($Resume.Nouvelles) nouveau(x), $($Resume.Disparues) disparu(s)." } else { "Rapport précédent $($Resume.RapportPrecedent) non comparable (autre moteur ou autre source) : aucune évolution n'est calculée." }
  [void](Bloc $sl 'Historique' $comp 660 $y 258 $Navy 11)
  [void](Texte $sl "Non couvert : $($Resume.NonCouverts) composant(s) sans référentiel CVE public (voir annexe E). « Non couvert » ne signifie pas « sans vulnérabilité »." 43 (82 + 20 * 5 + 8) 600 30 10.5 -coul $Gris -Italique)
  $partiels = @($ExportsRap | Where-Object { $_.Etat -ne 'Lu' })
  if ($partiels.Count) {
    $txt = (@($partiels | ForEach-Object { "$($_.Module) : $($_.Couverture -replace ' \(une liste globale peut couvrir le module\)', '')" }) | Select-Object -First 9) -join "`r"
    [void](Bloc $sl "Modules à couverture partielle ou non démontrée ($($partiels.Count))" $txt 43 (82 + 20 * 5 + 50) 600 $Rouge 10)
  } else { [void](Texte $sl "Source : $($Resume.Source) · collecte du $($Resume.DateCollecte)" 43 (82 + 20 * 5 + 50) 600 30 11 -coul $Gris) }

  # ---- 4. dépendances SEAL : constats par mois (12 derniers mois, formes natives)
  $sl = Diapo 'Dépendances SEAL : constats par mois de publication'
  $mois = @(for ($k = 11; $k -ge 0; $k--) { $genere.AddMonths(-$k).ToString('yyyy-MM') })
  $par = @{}; foreach ($l in $Seal) { $k = "$($l.Mois)|$($l.'Gravité')"; $par[$k] = 1 + [int]$par[$k] }
  $tot = @($mois | ForEach-Object { $m = $_; ($Sev.Keys | ForEach-Object { [int]$par["$m|$_"] } | Measure-Object -Sum).Sum })
  $max = [math]::Max(1, ($tot | Measure-Object -Maximum).Maximum)
  $x0 = 70; $base = 440; $haut = 300; $pas = 50
  Ligne $sl ($x0 - 8) $base ($x0 + 12 * $pas) 'C5CCD6'
  for ($i = 0; $i -lt 12; $i++) {
    $y = $base
    foreach ($g in $Sev.Keys) {
      $v = [int]$par["$($mois[$i])|$g"]; if (-not $v) { continue }
      $h = $haut * $v / $max; Rect $sl ($x0 + $i * $pas) ($y - $h) 34 $h $Sev[$g]; $y -= $h
    }
    if ($tot[$i]) { [void](Texte $sl "$($tot[$i])" ($x0 + $i * $pas - 4) ($y - 18) 42 14 11 -Gras -align 2) }
    [void](Texte $sl ($moisCourt[[int]$mois[$i].Substring(5, 2) - 1] + ' ' + $mois[$i].Substring(2, 2)) ($x0 + $i * $pas - 6) ($base + 6) 46 14 10 -coul '5B6573' -align 2)
  }
  $lx = 70; foreach ($g in $Sev.Keys) { Rect $sl $lx 478 10 10 $Sev[$g]; [void](Texte $sl $g ($lx + 14) 475 95 14 11); $lx += 110 }
  $t12 = ($tot | Measure-Object -Sum).Sum; $anciens = @($Seal | Where-Object { $_.Mois -lt $mois[0] }).Count
  TexteRiche $sl @(@{ T = "$t12"; Taille = 36; Gras = $true; Police = 'Cambria'; Coul = $Orange }, @{ T = 'constats publiés sur les 12 derniers mois'; Taille = 13 }, @{ T = "$anciens"; Taille = 36; Gras = $true; Police = 'Cambria'; Coul = $Navy }, @{ T = 'constats plus anciens, toujours présents dans la version'; Taille = 13 }) 700 110 218 300
  if ($Pc.'Dépendance SEAL'.Constats -and (@($Seal | Where-Object { -not $_.CVSS }).Count)) { [void](Texte $sl "$(@($Seal | Where-Object { -not $_.CVSS }).Count) constat(s) sans score CVSS publié : gravité reprise de l'avis (« Non renseignée » si absente)." 700 420 218 50 10 -coul $Gris -Italique) }

  # ---- 5+. détail mensuel des dépendances SEAL (mois × composant)
  $agg = @($Seal | Group-Object Mois, Composant | ForEach-Object {
      $g = @($_.Group | Sort-Object @{ e = { $Rang[$_.'Gravité'] }; Descending = $true }, @{ e = { Num $_.CVSS }; Descending = $true })
      $cves = @($g | Group-Object CVE | ForEach-Object { , @($_.Name, $_.Group[0].Lien) })
      $fix = (@($g | Group-Object 'Version installée' | Sort-Object { CleV $_.Name } -Descending | ForEach-Object { $f = @($_.Group.'Version corrigée'); if ($f | Where-Object { $_ -notmatch '^\d' }) { 'à vérifier' } else { @($f | Sort-Object { CleV $_ }) | Select-Object -Last 1 } } | Select-Object -Unique) -join ' / ')
      $sc = @($g | Where-Object { $_.CVSS } | ForEach-Object { $_.CVSS }) | Select-Object -First 1
      [pscustomobject]@{ Mois = $g[0].Mois; Comp = $g[0].Composant; Vers = (@(Uniques $g.'Version installée') -join ', '); Cves = $cves; Cvss = "$sc"; Grav = $g[0].'Gravité'; Fix = $fix }
    } | Sort-Object @{ e = 'Mois'; Descending = $true }, @{ e = { $Rang[$_.Grav] }; Descending = $true })
  $pages = Paquets $agg $LignesParDiapo
  foreach ($pg in $pages) {
    $m1 = $pg[0].Mois; $m2 = $pg[-1].Mois
    $sl = Diapo $(if ($m1 -eq $m2) { "Dépendances SEAL : $(NomMois $m1)" } else { "Dépendances SEAL : $(NomMois $m1) à $(NomMois $m2)" })
    $prev = ''
    $rows = @(foreach ($a in $pg) {
        $lk = @($a.Cves | Select-Object -First 5); $plus = if ($a.Cves.Count -gt 5) { " +$($a.Cves.Count - 5)" } else { '' }
        $r = , @(@{ T = $(if ($a.Mois -eq $prev) { '' } else { NomMois $a.Mois }); B = $true }, (Court $a.Comp), $a.Vers, @{ T = "$($a.Cves.Count)"; A = 2 }, (CelSev $a.Cvss $a.Grav), $a.Fix, @{ T = $plus; Liens = $lk })
        $prev = $a.Mois; $r })
    [void](Tableau $sl @('Mois', 'Composant', 'Version(s)', 'Nb', 'CVSS', 'Corrigée en', 'CVE (lien NVD)') $rows 43 82 @(100, 170, 105, 30, 50, 110, 310) 10)
    [void](Texte $sl 'n.r. : score CVSS non renseigné par l''avis (couleur = gravité publiée). « à vérifier » : au moins un avis sans version corrigée publiée.' 43 486 875 16 10 -coul $Gris -Italique)
  }
  if (-not $Seal.Count) { $sl = Diapo 'Dépendances SEAL'; [void](Texte $sl 'Aucun constat sur les dépendances SEAL inventoriées. Vérifier la couverture (diapositive précédente) avant de conclure.' 43 100 875 40 16) }

  # ---- composants SEAL à mettre à jour en priorité
  $prio = @($vulnSeal | Group-Object Composant | ForEach-Object {
      $g = $_.Group; $mods = @($g.'Modules SEAL' -split ', ' | Sort-Object -Unique)
      [pscustomobject]@{ Comp = $_.Name; Eco = $g[0].'Écosystème'; Vers = (@($g.Version) -join ', '); Cve = ($g.CVE | ForEach-Object { [int]$_ } | Measure-Object -Maximum).Maximum
        Grav = @($g | Sort-Object { $Rang[$_.'Gravité max'] } -Descending)[0].'Gravité max'; Cvss = @($g | Where-Object { $_.'CVSS max' } | Sort-Object { Num $_.'CVSS max' } -Descending | ForEach-Object { $_.'CVSS max' } | Select-Object -First 1)
        Cible = (@($g.'Version cible' | Where-Object { $_ } | Sort-Object -Unique) -join ' / '); Mods = $mods }
    } | Sort-Object @{ e = { $Rang[$_.Grav] }; Descending = $true }, @{ e = { Num "$($_.Cvss)" }; Descending = $true }, @{ e = 'Cve'; Descending = $true })
  if ($prio.Count) {
    $rows = @($prio | Select-Object -First 15 | ForEach-Object { , @(@{ T = (Court $_.Comp); B = $true }, $_.Eco, $(if ($_.Vers.Length -gt 26) { $_.Vers.Substring(0, 24) + '…' } else { $_.Vers }), @{ T = "$($_.Cve)"; A = 2 }, (CelSev "$($_.Cvss)" $_.Grav), $(if ($_.Cible) { $_.Cible } else { 'à déterminer' }), ((@($_.Mods | Select-Object -First 3) -join ', ') + $(if ($_.Mods.Count -gt 3) { " +$($_.Mods.Count - 3)" }))) })
    $sl = Diapo 'Dépendances SEAL à mettre à jour en priorité'
    [void](Tableau $sl @('Composant', 'Type', 'Version(s)', 'CVE', 'CVSS', 'Version cible', 'Modules SEAL') $rows 43 82 @(185, 60, 130, 40, 50, 160, 250) 10)
    [void](Texte $sl 'Version cible : plus petite version qui corrige tous les avis connus de la version installée. À valider avec les tests SEAL avant déploiement.' 43 486 875 16 10 -coul $Gris -Italique)
  }

  # ---- environnement : runtimes .NET et .NET Framework (hors périmètre SEAL)
  $fw = @($Constats | Where-Object { $_.'Écosystème' -eq '.NET Framework' })
  if (-not $Dotnet.Count -and -not $fw.Count) {   # livraison : l'environnement d'exécution n'est pas observable
    $sl = Diapo 'Environnement .NET : non évalué pour une livraison'
    $y = 90
    $y += (Bloc $sl 'Pourquoi' 'Une livraison contient les exports de build (paquets NuGet, npm, bibliothèques C++). Elle ne dit pas quels runtimes .NET, quel .NET Framework ni quels correctifs Windows sont installés chez le client.' 43 $y 875 $Navy 13) + 14
    $y += (Bloc $sl 'Où trouver cette information' 'Dans les rapports des serveurs (mode -Installation, planifié sur SEAL-OMEGA et QA) : runtimes observés, usage par SEAL (runtimeconfig), fin de support, et CVE .NET Framework qualifiées par les KB installés.' 43 $y 875 $Navy 13) + 14
    [void](Bloc $sl 'Option' 'Des runtimes relevés à part peuvent être déclarés avec -Runtimes / -NetFramework : ils apparaissent alors en « Environnement » (runtimes) ou « À confirmer » (.NET Framework sans liste de KB).' 43 $y 875 $Gris 12)
  }
  if ($Dotnet.Count -or $fw.Count) {
    $sl = Diapo 'Environnement serveur : runtimes .NET et .NET Framework'
    $kevRt = @{}; foreach ($l in $EnvSrv | Where-Object { $_.KEV -eq 'OUI' }) { $kevRt["$($l.Composant)|$($l.'Version installée')"] = $true }
    $rows = @($Dotnet | Sort-Object Runtime, { CleV $_.Version } | Select-Object -First 13 | ForEach-Object { , @(@{ T = (Court $_.Runtime); B = $true }, $_.Version, $_.Usage, $(if ($_.HorsSupport -eq 'OUI') { @{ T = "$($_.FinSupport) HORS SUPPORT"; C = $Rouge; B = $true } } else { $_.FinSupport }), $(if ($kevRt.ContainsKey("$($_.Runtime)|$($_.Version)")) { @{ T = "$($_.CVE) KEV"; A = 2; B = $true; C = $Rouge } } else { @{ T = $_.CVE; A = 2 } }), $(if ($_.HorsSupport -eq 'OUI') { 'Migrer vers une branche LTS supportée' } else { $_.Commentaire })) })
    if ($rows.Count) { [void](Tableau $sl @('Runtime', 'Version', 'Usage par SEAL', 'Fin de support', 'CVE', 'Action') $rows 43 82 @(150, 65, 190, 140, 40, 290) 9.5) }
    if ($fw.Count) {
      $yb = 82 + 20 * ($rows.Count + 1) + 20
      $nc = @($fw | Where-Object { $_.'Catégorie' -eq 'Corrigée / non applicable' -and $_.'État' -like 'Corrigée*' }).Count
      $na = @($fw | Where-Object { $_.'État' -like 'Non applicable*' }).Count
      $no = @($fw | Where-Object { $_.'Catégorie' -eq 'Environnement' }).Count
      $ac = @($fw | Where-Object { $_.'Catégorie' -eq 'À confirmer' }).Count
      $cumul = @($fw | Where-Object { $_.'État' -match 'cumulatif \.NET ultérieur (KB\d+) \((\d{4}-\d{2})\)' } | ForEach-Object { "$($Matches[1]) ($($Matches[2]))" } | Select-Object -First 1)
      $corps = "$($fw.Count) CVE NVD : $nc corrigée(s) par un KB installé$(if ($cumul) { " (dernier cumulatif .NET : $cumul)" }), $na non applicable(s) à cet OS, $no non corrigée(s), $ac à confirmer."
      if ($ac) { $corps += ' « À confirmer » : correctifs de l''hôte non relevés (livraison) ou CVE absente des bulletins MSRC.' }
      [void](Bloc $sl '.NET Framework (bulletins MSRC et correctifs installés)' $corps 43 $yb 875 $(if ($no) { $Rouge } else { $Navy }) 12)
    }
  }

  # ---- à confirmer : identité ou applicabilité non démontrée
  if ($AConf.Count) {
    $rows = @($AConf | Group-Object Composant, 'Version installée' | ForEach-Object { $g = $_.Group; , @(@{ T = (Court $g[0].Composant); B = $true }, $g[0].'Version installée', $g[0].'Écosystème', @{ T = "$(@(Uniques $g.CVE).Count)"; A = 2 }, (CelSev (@($g | Where-Object { $_.CVSS } | Sort-Object { Num $_.CVSS } -Descending | ForEach-Object { $_.CVSS } | Select-Object -First 1) -join '') @($g | Sort-Object { $Rang[$_.'Gravité'] } -Descending)[0].'Gravité'), ($g[0].'État' -replace '^Identité à confirmer : ', '' -replace '^À confirmer : ', '')) } | Select-Object -First 12)
    $sl = Diapo "À confirmer : $($Pc.'À confirmer'.Constats) constat(s), identité ou applicabilité non démontrée"
    [void](Tableau $sl @('Composant', 'Version', 'Type', 'Avis', 'CVSS', 'Motif') $rows 43 82 @(170, 85, 90, 40, 50, 440) 10)
  }

  # ---- bibliothèques natives et binaires tiers : vérifiées, à confirmer, non couvertes
  $nat = @($Inventaire | Where-Object { $_.'Écosystème' -in 'Natif', 'Binaire' })
  if ($nat.Count) {
    $nv = @($nat | Where-Object { [int]$_.CVE -gt 0 }).Count; $nnc = @($nat | Where-Object { $_.Statut -like 'Non couvert*' }).Count; $nok = $nat.Count - $nv - $nnc
    $sl = Diapo "Bibliothèques natives et binaires : $nv avec avis, $nok vérifiée(s) sans avis, $nnc non couverte(s)"
    $rows = @($nat | Sort-Object @{ e = { [int]$_.CVE }; Descending = $true }, Composant | Select-Object -First 15 | ForEach-Object { , @(@{ T = $_.Composant; B = $true }, $_.Version, $_.'Écosystème', @{ T = $(if ($_.Statut -like 'Non couvert*') { '—' } else { $_.CVE }); A = 2 }, $(if ([int]$_.CVE -gt 0) { CelSev $_.'CVSS max' $_.'Gravité max' } else { @{ T = '—'; A = 2 } }), $_.'Version cible', ($_.Statut + $(if ($_.Note) { " · $($_.Note)" }))) })
    [void](Tableau $sl @('Bibliothèque', 'Version', 'Type', 'CVE', 'CVSS', 'Cible', 'Statut') $rows 43 82 @(130, 85, 60, 40, 50, 80, 430) 9.5)
    [void](Texte $sl '« Non couvert » ne signifie pas « sans vulnérabilité » : aucun référentiel CVE public ne permet de vérifier ces composants.' 43 486 875 16 10 -coul $Gris -Italique)
  }

  # ---- évolution (uniquement si comparable)
  if ($Resume.HistoriqueComparable -and ($Resume.Nouvelles -or $Resume.Disparues)) {
    $nvx = @($Constats | Where-Object Nouveau -eq 'OUI' | Sort-Object @{ e = { $Rang[$_.'Gravité'] }; Descending = $true })
    $sl = Diapo "Évolution depuis le rapport $($Resume.RapportPrecedent)"
    [void](Texte $sl "$($Resume.Nouvelles) nouveau(x) constat(s) · $($Resume.Disparues) disparu(s) (dépendance mise à jour, retirée ou avis modifié)" 43 78 875 20 14 -Gras $Orange)
    $rows = @($nvx | Select-Object -First 9 | ForEach-Object { , @(@{ T = ''; Liens = @(, @($_.CVE, $_.Lien)) }, $_.'Catégorie', (CelSev $_.CVSS $_.'Gravité'), (Court $_.Composant), $_.'Version installée', $_.'Version corrigée') })
    if ($rows.Count) { [void](Tableau $sl @('Nouvelle CVE', 'Catégorie', 'CVSS', 'Composant', 'Version', 'Corrigée en') $rows 43 108 @(150, 150, 50, 280, 110, 135)) }
    $rows = @($Disparus | Select-Object -First 5 | ForEach-Object { , @($_.CVE, $_.'Catégorie', (Court $_.Composant), $_.'Version installée') })
    if ($rows.Count) { [void](Tableau $sl @('CVE disparue', 'Catégorie', 'Composant', 'Version') $rows 43 (130 + 20 * [math]::Min(9, $nvx.Count) + 20) @(150, 150, 400, 175)) }
  }

  # ---- plan d'action (calculé)
  $sl = Diapo 'Plan d''action proposé'
  $acts = New-Object Collections.Generic.List[object]
  if (-not $Resume.InventaireComplet) { $acts.Add(@('Compléter l''inventaire', "Corriger la génération des exports de dépendances vides ($($Resume.ExportsVides)) puis relancer l'analyse de cette livraison.", $Rouge)) }
  foreach ($eco in 'npm', 'NuGet', 'Natif') {
    $p = @($prio | Where-Object Eco -eq $eco | Select-Object -First 6)
    if ($p.Count) { $acts.Add(@($(switch ($eco) { 'npm' { 'Front web (npm)' } 'NuGet' { 'Bibliothèques .NET (NuGet)' } default { 'Bibliothèques natives (C++)' } }), (((@($p | ForEach-Object { "$($_.Comp) ≥ $(if ($_.Cible -match '^\d') { $_.Cible } else { 'version à vérifier' })" })) -join ', ') + '.'), $Orange)) }
  }
  if ($AConf.Count) { $noms = @(Uniques ($AConf | ForEach-Object { $_.Composant })); $acts.Add(@('Lever les « à confirmer »', "Confirmer l'identité ou l'applicabilité de $($noms.Count) composant(s) : $($noms -join ', ') (version réelle, KB, éditeur).", 'E6A100')) }
  if ($eol.Count -or $EnvSrv.Count) { $acts.Add(@('Environnement serveur', "$(if ($eol.Count) { "Migrer ou retirer les runtimes hors support ($(@(Uniques ($eol | ForEach-Object { "$($_.Runtime -replace '^Microsoft\.', '') $($_.Branche)" })) -join ', ')). " })$(if (@($EnvSrv | Where-Object { $_.'Écosystème' -eq '.NET Framework' }).Count) { 'Installer les KB .NET Framework manquants. ' })Appliquer les correctifs .NET mensuels.", $Bleu)) }
  $acts.Add(@('Suivi', 'Relancer l''analyse à chaque livraison et chaque mois sur les serveurs : les rapports du même moteur sont comparés automatiquement.', $Bleu))
  $y = 85
  for ($k = 0; $k -lt [math]::Min(6, $acts.Count); $k++) {
    $a = $acts[$k]
    Pastille $sl 43 ($y + 4) 34 $a[2] "$($k + 1)"
    $y += [math]::Max(52, (Bloc $sl $a[0] $a[1] 92 $y 826 $Navy 13) + 14)
  }

  # ---- méthode
  $sl = Diapo 'Méthode et règles d''analyse'
  $cols = @(@('Inventaire', "Source : $sourceTxt.`rExports Dependencies / Licences, *.deps.json, packages.config, runtimeconfig.json, DLL tierces ; pour un serveur : runtimes, .NET Framework, OS et correctifs installés."),
    @('Vulnérabilités', "OSV.dev (GitHub Advisory) : NuGet, npm, runtimes .NET.`rNVD : bibliothèques C++, .NET Framework.`rMSRC : KB .NET Framework par OS.`rCISA KEV, endoflife.date."),
    @('Règles', "Constat = CVE × composant × version ; mois = publication de la CVE.`rLes chiffres clés portent sur les dépendances SEAL ; l'environnement serveur est présenté à part.`rCVSS absent = « n.r. », jamais 0.`rComparaison uniquement entre rapports du même moteur et de la même source."))
  for ($k = 0; $k -lt 3; $k++) { $x = 43 + $k * 295; [void](Boite $sl $x 85 280 300); [void](Bloc $sl $cols[$k][0] $cols[$k][1] ($x + 14) 97 252 $Navy 12) }
  [void](Texte $sl "Détail complet : annexes PowerPoint, rapport.html, cve-detail.csv, inventaire.csv, exports.csv, controles.csv ($Rapport)" 43 405 875 30 11 -coul $Gris -Italique)
  $fichiers += Enregistrer 'synthese'
}

# =========================================================================================== ANNEXES
if ($Annexes) {
  Nouvelle-Presentation
  $sl = Diapo '' -Sombre
  [void](Texte $sl "SEAL $($Resume.VersionSeal) : annexes techniques" 58 175 845 70 40 -Gras $Blanc 1 'Cambria')
  [void](Texte $sl 'Constats complets par catégorie, corrections KB, composants non couverts, couverture et diagnostics' 58 255 845 30 18 -coul 'CADCFC')
  [void](Texte $sl "Source : $sourceTxt · CVE au $($genere.ToString('dd/MM/yyyy')) · descriptions intégrales : rapport.html" 58 292 845 24 14 -coul 'A9B8D6')
  $tri = { param($liste) $liste | Sort-Object @{ e = 'Mois'; Descending = $true }, @{ e = { $Rang[$_.'Gravité'] }; Descending = $true }, Composant }
  $cols = @('Mois', 'CVE', 'CVSS', 'Composant', 'Version', 'Corrigée en', 'Modules SEAL / état'); $larg = @(55, 120, 45, 175, 80, 110, 290)
  Tableau-Pagine "A. Dépendances SEAL : $($Seal.Count) constat(s)" $cols @(& $tri $Seal | ForEach-Object { Ligne-Constat $_ (Modules-Courts $_.'Modules SEAL') }) $larg 15 9.5
  Tableau-Pagine "B. Environnement serveur : $($EnvSrv.Count) constat(s)" $cols @(& $tri $EnvSrv | ForEach-Object { Ligne-Constat $_ $_.'État' }) $larg 15 9.5
  Tableau-Pagine "C. À confirmer : $($AConf.Count) constat(s)" $cols @(& $tri $AConf | ForEach-Object { Ligne-Constat $_ $_.'État' }) $larg 15 9.5
  Tableau-Pagine "D. .NET Framework corrigées ou non applicables : $($Corr.Count)" @('Mois', 'CVE', 'CVSS', 'Statut') @(& $tri $Corr | ForEach-Object { , @($_.Mois, @{ T = ''; Liens = @(, @($_.CVE, $_.Lien)) }, (CelSev $_.CVSS $_.'Gravité'), $(if ($_.KEV -eq 'OUI') { "KEV · $($_.'État')" } else { $_.'État' })) }) @(60, 130, 50, 635) 18 9.5 'Statuts établis à partir des bulletins MSRC et de la liste des correctifs installés sur le serveur.'
  $nc = @($Inventaire | Where-Object { $_.Statut -like 'Non couvert*' -or $_.Statut -like 'Non vérifié*' })
  Tableau-Pagine "E. Composants non couverts ou non vérifiés : $($nc.Count)" @('Composant', 'Version', 'Type', 'Statut', 'Modules SEAL') @($nc | Sort-Object 'Écosystème', Composant | ForEach-Object { , @(@{ T = $_.Composant; B = $true }, $_.Version, $_.'Écosystème', $_.Statut, (Modules-Courts $_.'Modules SEAL')) }) @(170, 90, 70, 300, 245) 17 9.5
  Tableau-Pagine "F. Couverture des exports : $($ExportsRap.Count) fichier(s)" @('Fichier', 'Type', 'État', 'Entrées', 'Couverture') @($ExportsRap | ForEach-Object { , @($_.Fichier, $_.Type, $(if ($_.Etat -ne 'Lu') { @{ T = $_.Etat; C = $Rouge; B = $true } } else { $_.Etat }), @{ T = $_.Entrees; A = 2 }, $_.Couverture) }) @(260, 85, 80, 55, 395) 17 9.5
  Tableau-Pagine "G. Diagnostics : $($Diags.Count)" @('Niveau', 'Source', 'Message') @($Diags | ForEach-Object { , @($_.Niveau, $_.Source, $_.Message) }) @(70, 230, 575) 17 9.5
  $fichiers += Enregistrer 'annexes'
}
$fichiers






# SIG # Begin signature block
# MIIJXQYJKoZIhvcNAQcCoIIJTjCCCUoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCClEIxdEN4n1JPW
# Uk2uqHom8ehz14zcoQCr1vs1ZYW6+qCCBpIwggaOMIIFdqADAgECAhNVAABq4hV6
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
# DAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg4nmKooa9qPaEuLiGA6SH2Axg
# 50Yn83S+LXpg8llxo4YwDQYJKoZIhvcNAQEBBQAEggEALdhzs2EdbKNHsbzxMHZZ
# qKt2A6VTW9n6JjTatyF5+58SF2UVyec7jsLs7oSb5XFzFQUiKRQa8OZYPwAMWPmM
# S6mJlaBdqFnP4f/HzTMh22mOiBbEQGG7z2HBgByllChud6ya2yyS90GcCZzbLHRT
# auTZsdqupJRHZj8P/BrlLeoUBmBRUkkaU9AYJdlHm/BeqO1hMn+u+GSRD3koaID7
# edsYoNsJisY1szRhUjxFsNeXRe1DS7sMsdxEwRpPYYe5ZF79Lwu1uGHy8UFJICnh
# OYC0tcjoEdy5TokZQn0uOXc15W4Sgyy21eue7EUEN0ORngBTQZGmrFJbcWoUrss9
# Jw==
# SIG # End signature block
