# Architecture Globale de la Plateforme PEGASE

## Vue d'Ensemble

L'architecture de PEGASE est conçue selon un modèle hybride combinant microservices et architecture hexagonale, permettant une modularité maximale tout en maintenant une cohérence globale. Cette approche facilite le développement collaboratif, l'évolution indépendante des composants et l'intégration de nouvelles fonctionnalités.

## Principes Architecturaux

### 1. Architecture en Couches

PEGASE s'organise en quatre couches principales :

1. **Couche d'Orchestration** : Coordination globale et gestion des workflows
2. **Couche Métier** : Modules d'attaque et logique spécifique au domaine
3. **Couche d'Intégration** : Communication entre modules et avec les systèmes externes
4. **Couche Infrastructure** : Ressources techniques sous-jacentes

### 2. Communication Event-Driven

Les composants communiquent principalement via un modèle événementiel, permettant un couplage faible et une meilleure résilience :

- Publication/souscription pour les événements asynchrones
- Communication synchrone via API REST pour les interactions nécessitant une réponse immédiate
- File d'attente pour les tâches longues et la répartition de charge

### 3. Sécurité by Design

La sécurité est intégrée à tous les niveaux de l'architecture :

- Isolation des composants critiques
- Chiffrement des communications internes et externes
- Principe du moindre privilège pour chaque module
- Journalisation immuable de toutes les actions
- Mécanismes de vérification d'intégrité

### 4. Évolutivité Horizontale

L'architecture permet une mise à l'échelle horizontale des composants selon les besoins :

- Conteneurisation de tous les services
- Orchestration via Kubernetes
- État partagé minimal entre instances
- Équilibrage de charge automatique

## Diagramme d'Architecture Globale

```
+-----------------------------------------------------+
|                  INTERFACE UTILISATEUR              |
|  +----------------+  +----------------+             |
|  |  Console Web   |  |  API Gateway   |             |
|  +----------------+  +----------------+             |
+-----------------------------------------------------+
                |                |
                v                v
+-----------------------------------------------------+
|                 PEGASE CORE                         |
|  +----------------+  +----------------+             |
|  | Orchestrateur  |  | Gestionnaire   |             |
|  | Principal      |  | de Contraintes |             |
|  +----------------+  +----------------+             |
|           |                   |                     |
|  +----------------+  +----------------+             |
|  | Moteur d'IA    |  | Bus            |             |
|  | Stratégique    |  | d'Information  |             |
|  +----------------+  +----------------+             |
+-----------------------------------------------------+
        |         |          |         |
        v         v          v         v
+------------------+    +------------------+
| MODULES D'ATTAQUE|    | MODULES DE       |
|                  |    | SUPPORT          |
| +-------------+  |    | +-------------+  |
| | NetAssault  |  |    | | ReconSphere |  |
| +-------------+  |    | +-------------+  |
|                  |    |                  |
| +-------------+  |    | +-------------+  |
| | WebBreacher |  |    | | VulnMatrix  |  |
| +-------------+  |    | +-------------+  |
|                  |    |                  |
| +-------------+  |    | +-------------+  |
| | SocialMatrix|  |    | | PostXploit  |  |
| +-------------+  |    | +-------------+  |
|                  |    |                  |
| +-------------+  |    | +-------------+  |
| | PhysicalVec.|  |    | | InsightPort.|  |
| +-------------+  |    | +-------------+  |
|                  |    |                  |
| +-------------+  |    | +-------------+  |
| | CloudStrike |  |    | | ThreatSim   |  |
| +-------------+  |    | +-------------+  |
|                  |    |                  |
| +-------------+  |    | +-------------+  |
| | MobileHunter|  |    | | MissionCtrl |  |
| +-------------+  |    | +-------------+  |
|                  |    |                  |
| +-------------+  |    | +-------------+  |
| | WirelessPha.|  |    | | Compliance  |  |
| +-------------+  |    | +-------------+  |
+------------------+    +------------------+
        |                        |
        v                        v
+-----------------------------------------------------+
|              COUCHE D'INTÉGRATION                   |
|  +----------------+  +----------------+             |
|  | ToolForge      |  | AutoPilot     |             |
|  | (Intégration   |  | (API &        |             |
|  |  Outils Tiers) |  |  Automation)  |             |
|  +----------------+  +----------------+             |
+-----------------------------------------------------+
                |                |
                v                v
+-----------------------------------------------------+
|              INFRASTRUCTURE                         |
|  +----------------+  +----------------+             |
|  | Conteneurs &   |  | Stockage &     |             |
|  | Orchestration  |  | Bases de       |             |
|  | (Kubernetes)   |  | Données        |             |
|  +----------------+  +----------------+             |
|                                                     |
|  +----------------+  +----------------+             |
|  | Sécurité &     |  | Monitoring &   |             |
|  | Identité       |  | Logging        |             |
|  +----------------+  +----------------+             |
+-----------------------------------------------------+
```

## Description Détaillée des Composants Architecturaux

### 1. Interface Utilisateur

#### 1.1 Console Web
- Interface utilisateur principale pour la configuration, le suivi et l'analyse des tests
- Architecture SPA (Single Page Application) avec Vue.js ou React
- Communication avec le backend via l'API Gateway
- Visualisations interactives des résultats et des attaques en cours

#### 1.2 API Gateway
- Point d'entrée unique pour toutes les interactions externes
- Gestion de l'authentification et des autorisations
- Routage des requêtes vers les services appropriés
- Rate limiting et protection contre les abus
- Documentation OpenAPI intégrée

### 2. PEGASE Core

#### 2.1 Orchestrateur Principal
- Coordination des workflows d'attaque
- Gestion du cycle de vie des missions
- Planification et ordonnancement des tâches
- Gestion des dépendances entre modules
- Mécanismes de reprise sur erreur

#### 2.2 Gestionnaire de Contraintes
- Vérification de la conformité légale des actions
- Application des limites du mandat
- Journalisation sécurisée des opérations
- Mécanismes d'arrêt d'urgence

#### 2.3 Moteur d'IA Stratégique (couche `pegase/ai/`, implémentée)
- Advisor ancré : score de risque, risques priorisés + remédiations, narration de la chaîne d'attaque
- Sélection recon-aware des prochains modules à exécuter
- Jury multi-modèles pour la validation des découvertes
- Garde-fou anti-hallucination (« no claim without a receipt »)
- Multi-provider (offline par défaut / Anthropic / OpenAI / Ollama), fonctionnel sans clé et hors-ligne

#### 2.4 Bus d'Information
- Communication entre les modules
- Partage sécurisé des découvertes
- Journalisation immuable des événements
- Gestion des événements asynchrones

### 3. Modules d'Attaque

Chaque module d'attaque suit une architecture interne similaire :

- **API de Module** : Interface standardisée pour l'intégration avec le Core
- **Contrôleur de Module** : Logique spécifique au domaine d'attaque
- **Adaptateurs d'Outils** : Intégration avec les outils spécifiques
- **Moteur d'Analyse** : Traitement et interprétation des résultats
- **Base de Connaissances** : Stockage des techniques et vulnérabilités spécifiques

Les modules communiquent avec le Core via le Bus d'Information et peuvent également communiquer directement entre eux pour des opérations coordonnées.

### 4. Modules de Support

Les modules de support suivent une architecture similaire aux modules d'attaque, mais se concentrent sur des fonctions transversales :

- **Reconnaissance** : Collecte d'informations préliminaires
- **Analyse de Vulnérabilités** : Identification et évaluation des faiblesses
- **Post-Exploitation** : Simulation d'activités après compromission
- **Reporting** : Génération de rapports et visualisation
- **Simulation de Menaces** : Émulation d'attaquants spécifiques
- **Gestion de Mission** : Administration des campagnes de tests
- **Conformité** : Alignement avec les normes et référentiels

### 5. Couche d'Intégration

#### 5.1 ToolForge (Intégration d'Outils Tiers)
- Gestion des plugins et extensions
- Conteneurisation des outils externes
- Normalisation des données entre formats
- Orchestration des chaînes d'outils

#### 5.2 AutoPilot (API & Automation)
- API RESTful pour l'intégration externe
- Moteur de workflows personnalisables
- Intégration avec les systèmes CI/CD
- SDK pour le développement d'extensions

### 6. Infrastructure

#### 6.1 Conteneurs & Orchestration
- Kubernetes pour l'orchestration des conteneurs
- Gestion des déploiements et des mises à l'échelle
- Isolation des environnements d'exécution
- Résilience et haute disponibilité

#### 6.2 Stockage & Bases de Données
- Bases de données relationnelles pour les données structurées
- Bases de données NoSQL pour les données non structurées
- Stockage objet pour les artefacts et résultats volumineux
- Caches distribués pour les performances

#### 6.3 Sécurité & Identité
- Gestion des identités et des accès
- PKI interne et gestion des certificats
- Coffre-fort pour les secrets et les clés
- Chiffrement des données au repos et en transit

#### 6.4 Monitoring & Logging
- Surveillance des performances et de la disponibilité
- Agrégation et analyse des logs
- Alertes et notifications
- Tableaux de bord opérationnels

## Flux de Données et Interactions

### 1. Flux d'une Mission de Pentest Typique

1. **Configuration de la Mission**
   - L'utilisateur configure les paramètres via la Console Web
   - Les informations sont validées par le Gestionnaire de Contraintes
   - L'Orchestrateur crée un plan de mission initial

2. **Phase de Reconnaissance**
   - Le module ReconSphere collecte des informations sur la cible
   - Les données sont partagées via le Bus d'Information
   - Le Moteur d'IA analyse les informations et affine la stratégie

3. **Exécution Coordonnée**
   - L'Orchestrateur lance les modules d'attaque selon le plan
   - Les modules partagent leurs découvertes en temps réel
   - Le Moteur d'IA adapte la stratégie en fonction des résultats

4. **Analyse et Reporting**
   - Les résultats sont consolidés et analysés
   - Le module InsightPortal génère des rapports interactifs
   - L'utilisateur peut explorer les résultats via la Console Web

### 2. Interactions entre Modules

Les interactions entre modules suivent principalement deux modèles :

- **Modèle Événementiel** : Publication d'événements sur le Bus d'Information (ex: découverte d'une vulnérabilité)
- **Modèle Requête/Réponse** : Communication directe via API pour les opérations synchrones (ex: demande d'information spécifique)

## Considérations de Déploiement

### 1. Environnements de Déploiement

PEGASE peut être déployé dans différentes configurations :

- **Déploiement Complet** : Tous les modules sur une infrastructure dédiée
- **Déploiement Léger** : Sous-ensemble de modules pour des tests ciblés
- **Déploiement Hybride** : Core et modules critiques en local, modules intensifs en ressources dans le cloud

### 2. Exigences Matérielles

Les exigences varient selon la configuration, mais une installation complète nécessite typiquement :

- Cluster Kubernetes avec au moins 3 nœuds
- Minimum 32 GB RAM par nœud
- Stockage SSD rapide pour les bases de données
- Réseau à faible latence entre les composants

### 3. Sécurisation du Déploiement

- Isolation réseau des composants critiques
- Chiffrement des communications inter-services
- Rotation régulière des secrets et des certificats
- Surveillance continue des accès et des activités

## Évolutivité et Extensions

### 1. Ajout de Nouveaux Modules

L'architecture permet l'ajout de nouveaux modules d'attaque ou de support via :

- Implémentation de l'API de module standardisée
- Enregistrement auprès du Bus d'Information
- Déclaration des capacités et dépendances à l'Orchestrateur

### 2. Intégration d'Outils Tiers

De nouveaux outils peuvent être intégrés via :

- Développement d'adaptateurs dans ToolForge
- Conteneurisation de l'outil
- Création de transformateurs de données pour la normalisation

### 3. Extensions Personnalisées

Les utilisateurs peuvent étendre les fonctionnalités via :

- API AutoPilot pour l'automatisation
- SDK pour le développement de plugins
- Hooks d'événements pour les intégrations externes

## Conclusion

L'architecture de PEGASE est conçue pour offrir une flexibilité maximale tout en maintenant une cohérence globale. La combinaison d'une approche microservices pour l'indépendance des composants et d'une architecture hexagonale pour la séparation des préoccupations permet une évolution continue de la plateforme.

Cette architecture modulaire facilite également la contribution de la communauté open source, chaque module pouvant être développé et amélioré indépendamment, tout en s'intégrant harmonieusement dans l'ensemble de la plateforme grâce aux interfaces standardisées et au bus d'information central.
