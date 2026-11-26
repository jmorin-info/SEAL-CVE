# SEAL CVE : vulnérabilités des dépendances SEAL

Outil PowerShell qui inventorie les dépendances d'une version de SEAL (livraison ou serveur installé), recherche les CVE
publiées pour chaque version et produit, avec **les mêmes règles pour toutes les versions** :

- des données CSV / JSON (source unique de tous les indicateurs) ;
- un rapport HTML interactif (filtre, liens NVD, couverture, diagnostics) ;
- une **synthèse PowerPoint** (10 à 16 diapositives) et des **annexes PowerPoint** (tableaux complets), générées sans Office.

Compatible Windows PowerShell 5.1 et PowerShell 7. Les scripts sont signés (certificat interne « ADM - Julien Morin »).

## Contenu

| Fichier | Rôle |
|---|---|
| `README.md` | Ce mode d'emploi |
| `Get-SealCveReport.ps1` | Moteur : collecte, recherche des CVE, classement, rapports, consolidation |
| `New-SealCvePresentation.ps1` | Synthèse et annexes PowerPoint, écrites directement (aucun Office requis) |
| `Invoke-SealCvePlanifie.ps1` | Orchestration planifiée sur le DC : analyse quotidienne, rapport hebdomadaire par mail |
| `planification.exemple.json` | Modèle de configuration de la planification (serveurs, dépôt, destinataires) |
| `Signer-SealProjet.ps1` | Signature des scripts sur le serveur de signature après modification |
| `Livraison\<version>` | Exports de build par version (Dependencies.zip, Licences.zip), non versionnés |
| `Rapports\SEAL_<version>_<source>\<date>` | Rapports horodatés (un dossier par exécution), non versionnés |
| `Cache\` | Cache des référentiels (OSV, NVD, MSRC, KEV), supprimable |

## Utilisation

```powershell
# Livraison (dossier contenant Dependencies.zip / Licences.zip, ou le *_artifacts.zip)
.\Get-SealCveReport.ps1 -Artefacts 'C:\SEAL\Livraison\45.0' -Presentation

# Serveur SEAL avec Internet (console administrateur) : découverte automatique sur tous les disques, services, IIS
.\Get-SealCveReport.ps1 -Installation -Presentation
.\Get-SealCveReport.ps1 -Installation -RacineInstallation 'D:\SEAL','E:\SEALWeb'      # chemins imposés

# Serveur sans Internet : collecte, puis analyse sur un poste connecté
.\Get-SealCveReport.ps1 -Installation -InventaireSeul
.\Get-SealCveReport.ps1 -Inventaire '.\inventaire.json' -Presentation

# Présentation d'un rapport existant (dossier d'un rapport ou dossier parent : rapport le plus récent)
.\New-SealCvePresentation.ps1 -Rapport '.\Rapports\SEAL_45.0.25468_BX-SEAL-OMEGA'

# Tableau comparatif de toutes les versions (dernier rapport de chaque version / source)
.\Get-SealCveReport.ps1 -Consolider
```

Pour passer une liste (`-Runtimes`, `-RacineInstallation`) depuis un raccourci, utiliser
`powershell -Command "& '.\Get-SealCveReport.ps1' …"` : avec `-File`, les virgules ne sont pas interprétées.

## Règles d'analyse (moteur 3.0)

**Périmètre.** *SEAL* = dépendances livrées ou déployées par SEAL (NuGet, npm, bibliothèques C++, runtime inclus dans
une application autonome). *Environnement* = runtimes .NET et .NET Framework installés sur le serveur.

**Catégories.** Chaque constat est classé dans une seule catégorie :

| Catégorie | Contenu | Compté dans les chiffres clés |
|---|---|---|
| Dépendance SEAL | Composant SEAL d'identité exacte (manifeste, export de paquets) associé à un avis publié pour sa version | Oui |
| Environnement | Runtime .NET de l'hôte ; CVE .NET Framework dont le KB requis est absent | Non (présenté à part) |
| À confirmer | Identité ou applicabilité non démontrée : version lue dans une DLL, version de fichier non standard, .NET Framework sans liste de KB | Non |
| Corrigée / non applicable | CVE .NET Framework corrigée par un KB installé (ou un cumulatif ultérieur), ou produit absent de l'avis MSRC pour cet OS | Non |
| Non couvert (inventaire) | Composant sans référentiel CVE public (DLL propriétaires, SDK tiers, DLL Windows) | Non : « non couvert » ≠ « sans vulnérabilité » |

**Comptage.** Un constat = une CVE (ou un avis sans CVE) × un composant × une version. Les CVE distinctes sont
dédoublonnées par identifiant. Un score CVSS absent est affiché « n.r. » (jamais 0) ; la gravité vient alors de l'avis.

**Version cible.** Plus petite version qui corrige tous les avis connus de la version installée. Si un avis n'a pas de
correction publiée : « À vérifier ». À valider avec les tests SEAL avant déploiement.

**.NET Framework.** La liste des CVE vient de la NVD ; l'applicabilité est établie avec les bulletins MSRC (KB requis
pour l'OS et la version .NET de l'hôte) et la liste des correctifs installés. Les cumulatifs .NET étant cumulatifs, un
cumulatif .NET installé d'un mois postérieur couvre les CVE des mois précédents.

**Livraison.** Une livraison ne dit pas quels runtimes, quel .NET Framework ni quels KB sont installés chez le client :
l'environnement .NET est évalué sur les serveurs. Des runtimes relevés à part peuvent être déclarés (`-Runtimes`,
`-NetFramework`).

**Complétude.** Un export de dépendances vide ou invalide rend l'inventaire **incomplet** : il est signalé dès la page
de titre, avec pour chaque module la couverture restante (liste de licences dédiée = couverture partielle sans graphe).

**Historique.** Chaque exécution crée un sous-dossier daté. Un rapport n'est comparé au précédent (nouveaux / disparus)
que s'il provient du même moteur et de la même source ; sinon aucune évolution n'est calculée.

**Contrôles.** Le moteur vérifie la cohérence des compteurs (catégories, mois, inventaire) dans `controles.csv` ; le
générateur PowerPoint les recontrôle et refuse de produire une présentation incohérente.

## Fichiers d'un rapport

| Fichier | Contenu |
|---|---|
| `resume.json` | Indicateurs par catégorie, source, date de collecte, complétude, comparabilité |
| `cve-detail.csv` | Un constat par ligne : catégorie, mois, CVE, CVSS, gravité, KEV, composant, version, correction, état, modules, lien |
| `cve-par-mois.csv` | Constats par catégorie et par mois de publication |
| `inventaire.csv` / `inventaire.json` | Inventaire enrichi (catégorie, CVSS max, gravité max, version cible, statut) / collecte réutilisable |
| `dotnet.csv` | Runtimes .NET : usage par SEAL (runtimeconfig), fin de support, CVE |
| `exports.csv` | État de chaque export Dependencies / Licences et couverture des modules |
| `controles.csv`, `diagnostic.csv`, `sources.csv` | Contrôles de cohérence, diagnostics, état des référentiels |
| `cve-disparues.csv` | Constats disparus depuis le rapport précédent comparable |
| `rapport.html`, `*_synthese.pptx`, `*_annexes.pptx` | Restitutions |

## Planification (serveurs SEAL et contrôleur de domaine)

```
 Serveur SEAL (tâche « OMS - SEAL CVE collecte (quotidien) », 05:30, compte Système)
   Get-SealCveReport.ps1 -Installation -InventaireSeul -Depot \\BX-AD-01-IT-VM\OMS-Postes$\SEAL-CVE
        │  inventaire_<date>.json
        ▼
 DC  C:\DC\Applications\SEAL-CVE
   « OMS - SEAL CVE analyse (quotidien) »  07:15  Invoke-SealCvePlanifie.ps1 -Mode Quotidien
        analyse de chaque nouvel inventaire ; mail d'alerte seulement si nouveau constat critique ou KEV
   « OMS - SEAL CVE rapport (hebdo) »      lundi 07:40  Invoke-SealCvePlanifie.ps1 -Mode Hebdo
        synthèse + annexes PowerPoint du dernier rapport de chaque serveur, envoyées aux destinataires
```

- Les serveurs SEAL déposent eux-mêmes leur inventaire (le DC n'a pas besoin d'accès WinRM aux serveurs) ; les
  tâches exigent des scripts signés (`-ExecutionPolicy AllSigned`).
- `planification.json` (copie de `planification.exemple.json`) : dossier de dépôt, destinataires, serveurs actifs,
  alerte quotidienne, conservation des rapports. Un fichier `SUSPENDRE-MAILS` dans le dossier suspend les envois.
- Mails : module commun `C:\DC\Scripts\_Commun\OMS-ReportCommon.ps1` (charte et relais SMTP du DC) ; copie
  archivée dans `C:\DC\Rapports`. Journaux : `Journaux\` (90 jours). Clé NVD : secret DPAPI déjà présent sur le DC.
- Un inventaire non reçu depuis 48 h et un serveur désactivé sont signalés dans le mail hebdomadaire.
- Ajouter un serveur : copier `Get-SealCveReport.ps1` dans `C:\ProgramData\OMNITECH\SEAL-CVE` du serveur,
  créer la tâche de collecte (même commande), puis l'ajouter à `planification.json`.

## Sources

OSV.dev / GitHub Advisory Database (NuGet, npm, runtimes .NET), NVD API 2.0 (bibliothèques C++, .NET Framework),
MSRC CVRF (KB .NET Framework), CISA KEV, endoflife.date. Clé NVD facultative : `-NvdApiKey` ou variable `NVD_API_KEY`.

## Signature

Toute modification d'un script invalide sa signature. Après modification :

```powershell
.\Signer-SealProjet.ps1        # demande le compte autorisé, signe sur le serveur de signature, vérifie, sauvegarde
```

Le certificat expire le 02/07/2028 ; les signatures ne sont pas horodatées et devront être renouvelées avant cette date.
