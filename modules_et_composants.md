# Modules et Composants Clés du Projet PEGASE

## 1. Noyau Central : PEGASE Core

Le noyau central de PEGASE est responsable de l'orchestration globale, de la coordination des modules et de la gestion du flux d'information entre les différents composants.

### Composants du Noyau

#### 1.1 Orchestrateur Principal
- **Fonction** : Coordonne l'exécution des différents modules d'attaque
- **Caractéristiques** :
  - Planification temporelle des attaques
  - Gestion des dépendances entre modules
  - Équilibrage de charge et allocation des ressources
  - Mécanismes de reprise sur erreur

#### 1.2 Bus d'Information Sécurisé
- **Fonction** : Assure la communication entre les modules
- **Caractéristiques** :
  - Partage sécurisé des découvertes entre modules
  - Chiffrement des communications internes
  - Journalisation immuable des actions

#### 1.3 Moteur d'IA Stratégique (couche `pegase/ai/`)
- **Fonction** : Analyse globale, priorisation et augmentation par LLM
- **Statut** : **implémenté** — couche IA native de PEGASE, multi-provider (offline par défaut / Anthropic / OpenAI / Ollama), **fonctionnelle sans clé API et hors-ligne**
- **Caractéristiques** :
  - Advisor ancré : score de risque, risques priorisés + remédiations, narration de la chaîne d'attaque, résumé exécutif
  - Garde-fou anti-hallucination (« no claim without a receipt ») : chaque phrase issue d'un LLM doit référencer une découverte réelle, sinon elle est rejetée
  - Sélection recon-aware : recommande les prochains modules selon ce que la reconnaissance a réellement observé
  - Jury multi-modèles : validation d'une découverte avec un juré déterministe basé sur les preuves toujours présent
  - Dégradation silencieuse en mode offline si un provider cloud n'a pas de clé — la plateforme ne peut jamais tomber à cause de l'IA

#### 1.4 Gestionnaire de Contraintes Légales
- **Fonction** : Assure le respect du cadre légal et des limites du mandat
- **Caractéristiques** :
  - Vérification en temps réel de la conformité des actions
  - Mécanismes d'arrêt d'urgence
  - Journalisation légale des opérations

## 2. Modules d'Attaque Spécialisés

### 2.1 Module d'Attaque Réseau (NetAssault)
- **Fonction** : Évaluation de la sécurité de l'infrastructure réseau
- **Sous-composants** :
  - Scanner de topologie réseau avancé
  - Analyseur de protocoles et de trafic
  - Moteur d'exploitation des vulnérabilités réseau
  - Simulateur de mouvement latéral
  - Testeur de segmentation réseau

### 2.2 Module d'Attaque Web (WebBreacher)
- **Fonction** : Tests d'intrusion des applications web et API
- **Sous-composants** :
  - Crawler intelligent avec analyse comportementale
  - Détecteur de vulnérabilités OWASP Top 10
  - Fuzzer adaptatif pour API
  - Analyseur de logique métier
  - Simulateur d'attaques par chaînage

### 2.3 Module d'Ingénierie Sociale (SocialMatrix)
- **Fonction** : Simulation d'attaques d'ingénierie sociale
- **Sous-composants** :
  - Générateur de campagnes de phishing personnalisées
  - Simulateur d'appels téléphoniques frauduleux
  - Analyseur de présence sur les réseaux sociaux
  - Moteur de création de profils psychologiques
  - Évaluateur de sensibilisation du personnel

### 2.4 Module d'Attaque Physique (PhysicalVector)
- **Fonction** : Évaluation de la sécurité physique
- **Sous-composants** :
  - Simulateur d'accès physique non autorisé
  - Testeur de contrôles d'accès
  - Analyseur de vulnérabilités des systèmes embarqués
  - Évaluateur de sécurité des dispositifs IoT
  - Cartographe de zones sensibles

### 2.5 Module d'Attaque Cloud (CloudStrike)
- **Fonction** : Tests d'intrusion des infrastructures cloud
- **Sous-composants** :
  - Analyseur de configuration cloud multi-fournisseurs
  - Testeur de séparation des tenants
  - Évaluateur de gestion des identités et des accès
  - Simulateur d'exfiltration de données cloud
  - Détecteur de mauvaises configurations

### 2.6 Module d'Attaque Mobile (MobileHunter)
- **Fonction** : Évaluation de la sécurité des applications et appareils mobiles
- **Sous-composants** :
  - Analyseur statique et dynamique d'applications
  - Testeur de communications mobiles
  - Évaluateur de stockage sécurisé
  - Simulateur de compromission d'appareil
  - Analyseur de flux de données sensibles

### 2.7 Module d'Attaque Wireless (WirelessPhantom)
- **Fonction** : Tests des réseaux sans fil et des communications radio
- **Sous-composants** :
  - Scanner de réseaux WiFi, Bluetooth, et autres protocoles
  - Analyseur de chiffrement sans fil
  - Simulateur d'interception de communications
  - Testeur de réseaux isolés (air-gapped)
  - Détecteur de signaux non autorisés

### 2.8 Module d'Attaque IA/LLM (AIBreacher)
- **Fonction** : Red-teaming des endpoints d'IA / LLM (OWASP Top 10 for LLM Applications)
- **Sous-composants** :
  - Sonde d'injection de prompt (LLM01) par jeton canari aléatoire
  - Détecteur de divulgation du prompt système (LLM06)
  - Sondes **bénignes et non destructives** : détection uniquement, jamais de génération de contenu nuisible
  - Preuves rédigées (on enregistre le déclenchement, pas la réponse sensible du modèle)
  - Contrôle de périmètre (`ScopeGuard`) et action `ACTIVE` comme tout module
- **Positionnement** : pendant « surface IA » de WebBreacher, pour les applications qui exposent un modèle de langage.

## 3. Modules de Support et d'Analyse

### 3.1 Module de Reconnaissance (ReconSphere)
- **Fonction** : Collecte d'informations préliminaires sur la cible
- **Sous-composants** :
  - Agrégateur OSINT multi-sources
  - Analyseur de présence numérique
  - Cartographe d'infrastructure
  - Profileur d'organisation et de personnel
  - Détecteur d'informations sensibles exposées

### 3.2 Module d'Analyse de Vulnérabilités (VulnMatrix)
- **Fonction** : Identification et analyse des vulnérabilités
- **Sous-composants** :
  - Moteur de scan multi-technologies
  - Base de connaissances de vulnérabilités évolutive
  - Système de scoring contextuel
  - Analyseur de faux positifs par IA
  - Corrélateur de vulnérabilités

### 3.3 Module de Post-Exploitation (PostXploit)
- **Fonction** : Simulation d'activités post-compromission
- **Sous-composants** :
  - Simulateur d'élévation de privilèges
  - Testeur de persistance
  - Évaluateur de détection d'intrusion
  - Simulateur d'exfiltration de données
  - Analyseur de logs et traces

### 3.4 Module de Reporting (InsightPortal)
- **Fonction** : Génération de rapports et visualisation des résultats
- **Sous-composants** :
  - Générateur de rapports personnalisables
  - Interface de visualisation interactive
  - Tableau de bord temps réel
  - Système de recommandations priorisées
  - Exportateur multi-formats

## 4. Modules d'Intégration et d'Extension

### 4.1 Module d'Intégration d'Outils Tiers (ToolForge)
- **Fonction** : Intégration d'outils de sécurité existants
- **Sous-composants** :
  - Connecteurs pour outils open-source
  - Adaptateurs pour solutions commerciales
  - Gestionnaire de plugins
  - Normalisateur de données
  - Orchestrateur de chaînes d'outils

### 4.2 Module d'API et d'Automatisation (AutoPilot)
- **Fonction** : Interfaces programmatiques et automatisation
- **Sous-composants** :
  - API RESTful sécurisée
  - Moteur de workflows personnalisables
  - Intégration CI/CD
  - Connecteurs pour plateformes DevSecOps
  - SDK pour extensions personnalisées

### 4.3 Module de Simulation Avancée (ThreatSim)
- **Fonction** : Simulation de menaces et d'attaquants spécifiques
- **Sous-composants** :
  - Bibliothèque de profils d'attaquants (APT, cybercriminels)
  - Simulateur de tactiques, techniques et procédures (TTP)
  - Émulateur de malwares (sans code malveillant réel)
  - Générateur de scénarios d'attaque complexes
  - Évaluateur de résilience face aux menaces ciblées

## 5. Modules de Gouvernance et Conformité

### 5.1 Module de Gestion des Missions (MissionControl)
- **Fonction** : Administration des campagnes de tests
- **Sous-composants** :
  - Gestionnaire de périmètres et autorisations
  - Planificateur de campagnes
  - Système de suivi et d'audit
  - Interface d'administration sécurisée
  - Gestionnaire de ressources

### 5.2 Module de Conformité et Référentiels (ComplianceGuard)
- **Fonction** : Alignement avec les normes et référentiels
- **Sous-composants** :
  - Mappeur de résultats vers référentiels (ISO, NIST, etc.)
  - Évaluateur de conformité réglementaire
  - Gestionnaire de preuves d'audit
  - Analyseur d'écarts (gap analysis)
  - Générateur de plans de remédiation

## Conclusion

Cette architecture modulaire permet à PEGASE d'offrir une flexibilité maximale tout en maintenant une cohérence globale. Chaque module peut fonctionner de manière autonome ou en coordination avec les autres, selon les besoins spécifiques de la mission. L'approche par composants facilite également l'évolution continue de la plateforme, permettant l'intégration de nouvelles techniques d'attaque et technologies de défense au fur et à mesure de leur apparition dans le paysage de la cybersécurité.
