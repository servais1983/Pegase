# PEGASE - Penetration Engagement for Global Attack Simulation & Evasion

![Logo PEGASE](docs/images/logo_pegase.png)

## Présentation

PEGASE (Penetration Engagement for Global Attack Simulation & Evasion) est une plateforme de test d'intrusion de nouvelle génération, conçue pour simuler des attaques multi-vecteurs coordonnées dans un cadre légal et éthique. Contrairement aux solutions traditionnelles qui se concentrent sur un seul vecteur à la fois, PEGASE adopte une approche holistique permettant d'évaluer la posture de sécurité globale d'une organisation.

## Caractéristiques Principales

- **Orchestration Multi-Vecteurs** : Coordination d'attaques simultanées sur différents vecteurs (réseau, web, social, physique, cloud, mobile, etc.)
- **Intelligence Adaptative** : Algorithmes d'IA capables d'ajuster dynamiquement les stratégies d'attaque en fonction des défenses rencontrées
- **Modularité Avancée** : Architecture extensible permettant l'ajout facile de nouveaux modules et l'intégration d'outils existants
- **Simulation Réaliste** : Reproduction fidèle des techniques utilisées par les attaquants réels, incluant les mouvements latéraux et l'élévation de privilèges
- **Reporting Interactif** : Interface web permettant de suivre les attaques en temps réel et de visualiser les chemins d'attaque complexes
- **Cadre Éthique et Légal** : Mécanismes intégrés pour garantir le respect des limites légales et éthiques du pentest

## Vision

PEGASE incarne une nouvelle philosophie dans le domaine du pentest légal : l'approche "Omnidirectionnelle Adaptative". Cette vision repose sur trois principes fondamentaux :

1. **Simultanéité multi-vecteurs** : Les attaques réelles ne se limitent jamais à un seul vecteur. PEGASE simule des attaques coordonnées sur l'ensemble des surfaces d'exposition d'une organisation.

2. **Intelligence adaptative** : Les attaquants modernes adaptent constamment leurs techniques en fonction des défenses rencontrées. PEGASE intègre des algorithmes d'IA capables d'ajuster dynamiquement les stratégies d'attaque en fonction des résultats obtenus.

3. **Transparence et contrôle** : Malgré sa puissance, PEGASE reste un outil de pentest légal avec des garde-fous intégrés, une traçabilité totale et des mécanismes de contrôle permettant d'éviter tout dommage non intentionnel.

## Architecture

L'architecture de PEGASE est conçue selon un modèle hybride combinant microservices et architecture hexagonale, permettant une modularité maximale tout en maintenant une cohérence globale.

![Architecture PEGASE](docs/images/architecture_pegase.png)

### Composants Principaux

- **PEGASE Core** : Noyau central responsable de l'orchestration globale
  - Orchestrateur Principal
  - Bus d'Information Sécurisé
  - Moteur d'IA Stratégique
  - Gestionnaire de Contraintes Légales

- **Modules d'Attaque Spécialisés**
  - NetAssault (Réseau)
  - WebBreacher (Web)
  - SocialMatrix (Ingénierie Sociale)
  - PhysicalVector (Sécurité Physique)
  - CloudStrike (Cloud)
  - MobileHunter (Mobile)
  - WirelessPhantom (Sans-fil)

- **Modules de Support et d'Analyse**
  - ReconSphere (Reconnaissance)
  - VulnMatrix (Analyse de Vulnérabilités)
  - PostXploit (Post-Exploitation)
  - InsightPortal (Reporting)

- **Modules d'Intégration et d'Extension**
  - ToolForge (Intégration d'Outils Tiers)
  - AutoPilot (API et Automatisation)
  - ThreatSim (Simulation Avancée)

Pour plus de détails sur l'architecture, consultez la [documentation d'architecture](docs/architecture/architecture_globale.md).

## Technologies

PEGASE utilise un ensemble de technologies modernes et éprouvées :

- **Langages principaux** : Go, Python, Rust
- **Orchestration** : Temporal.io, Kubernetes
- **Intelligence Artificielle** : PyTorch, TensorFlow, Ray RLlib
- **Communication** : Apache Kafka, gRPC
- **Stockage** : PostgreSQL, MongoDB, Neo4j
- **Frontend** : Vue.js, D3.js
- **Sécurité** : Vault, PKI interne, chiffrement de bout en bout

Pour plus de détails sur les technologies utilisées, consultez la [documentation technique](docs/technique/technologies.md).

## Scénarios d'Utilisation

PEGASE peut être utilisé dans divers contextes pour évaluer la sécurité globale d'une organisation :

- **Compromission d'Entreprise via Approche Hybride** : Combinaison de phishing, exploitation web et accès physique
- **Compromission d'Infrastructure Cloud Critique** : Évaluation de la sécurité des environnements multi-cloud
- **Attaque Ciblée contre une Infrastructure Critique** : Test de la sécurité des systèmes industriels
- **Évaluation de Sécurité Mobile et IoT** : Analyse de l'écosystème mobile et IoT complet
- **Attaque Coordonnée contre une Organisation Internationale** : Simulation d'APT ciblant plusieurs sites

Pour des exemples détaillés de scénarios, consultez la [documentation des scénarios](docs/scenarios/scenarios_attaque.md).

## Éthique et Légalité

PEGASE intègre des mécanismes robustes pour garantir que toutes les activités respectent un cadre éthique et légal strict :

- **Gestionnaire de Contraintes Légales** : Vérification en temps réel de la conformité des actions
- **Journalisation Immuable** : Traçabilité complète de toutes les actions effectuées
- **Supervision Humaine** : Points de validation obligatoires pour les actions critiques
- **Protection des Données** : Chiffrement et minimisation des données collectées

Pour plus d'informations sur le cadre éthique et légal, consultez la [documentation éthique](docs/ethique/ethique_legalite_transparence.md).

## Installation

### Prérequis

- Kubernetes 1.22+
- Docker 20.10+
- Go 1.18+
- Python 3.9+
- PostgreSQL 14+

### Installation rapide

```bash
# Cloner le dépôt
git clone https://github.com/votre-organisation/pegase.git
cd pegase

# Installation des dépendances
make install-deps

# Configuration
cp config/config.example.yaml config/config.yaml
# Éditer config/config.yaml selon vos besoins

# Déploiement
make deploy
```

Pour des instructions d'installation détaillées, consultez le [guide d'installation](docs/installation/installation.md).

## Utilisation

### Démarrage rapide

```bash
# Lancer l'interface web
pegase-cli start --web

# Créer une nouvelle mission
pegase-cli mission create --name "Test-Entreprise-X" --config missions/templates/standard.yaml

# Exécuter la mission
pegase-cli mission run --id <mission-id>
```

Pour un guide d'utilisation complet, consultez la [documentation utilisateur](docs/utilisation/guide_utilisation.md).

## Contribution

Nous accueillons favorablement les contributions à PEGASE ! Voici comment vous pouvez participer :

1. Forker le projet
2. Créer une branche pour votre fonctionnalité (`git checkout -b feature/amazing-feature`)
3. Committer vos changements (`git commit -m 'Add some amazing feature'`)
4. Pousser vers la branche (`git push origin feature/amazing-feature`)
5. Ouvrir une Pull Request

Pour plus d'informations, consultez le [guide de contribution](CONTRIBUTING.md).

## Licence

Ce projet est distribué sous licence [GNU Affero General Public License v3.0](LICENSE). Voir le fichier LICENSE pour plus de détails.

## Contact

Pour toute question ou suggestion concernant PEGASE, n'hésitez pas à ouvrir une issue sur ce dépôt ou à contacter l'équipe de développement à l'adresse suivante : contact@pegase-pentest.org

---

**Note importante** : PEGASE est un outil de test d'intrusion légal et doit être utilisé uniquement dans le cadre de missions autorisées. L'utilisation de cet outil pour des activités non autorisées est illégale et contraire à l'éthique.
