# Guide de Contribution à PEGASE

Nous sommes ravis que vous envisagiez de contribuer au projet PEGASE ! Ce document fournit les lignes directrices et les informations nécessaires pour contribuer efficacement.

## Code de Conduite

En participant à ce projet, vous vous engagez à respecter notre [Code de Conduite](CODE_OF_CONDUCT.md). Veuillez le lire attentivement avant de contribuer.

## Comment Contribuer

### Signaler des Bugs

Les bugs sont suivis via les issues GitHub. Pour signaler un bug :

1. Utilisez le modèle d'issue "Bug Report"
2. Décrivez clairement le problème rencontré
3. Incluez les étapes pour reproduire le bug
4. Précisez l'environnement dans lequel le bug se produit
5. Suggérez une solution si possible

### Proposer des Améliorations

Pour proposer une nouvelle fonctionnalité ou une amélioration :

1. Utilisez le modèle d'issue "Feature Request"
2. Décrivez clairement la fonctionnalité souhaitée
3. Expliquez pourquoi cette fonctionnalité serait utile
4. Proposez une implémentation si possible

### Processus de Pull Request

1. Forker le dépôt
2. Créer une branche à partir de `develop`
3. Implémenter vos modifications
4. Ajouter ou mettre à jour les tests si nécessaire
5. S'assurer que tous les tests passent
6. Mettre à jour la documentation si nécessaire
7. Soumettre une Pull Request vers la branche `develop`

### Conventions de Codage

#### Go
- Suivre les conventions de la [Effective Go](https://golang.org/doc/effective_go.html)
- Utiliser `gofmt` pour formater le code
- Documenter toutes les fonctions exportées

#### Python
- Suivre [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- Utiliser des docstrings pour documenter les fonctions et classes
- Maintenir une couverture de tests adéquate

#### JavaScript/TypeScript
- Suivre les règles ESLint configurées dans le projet
- Utiliser des composants fonctionnels et des hooks pour React/Vue

### Tests

Tous les nouveaux modules et fonctionnalités doivent être accompagnés de tests appropriés :

- Tests unitaires pour les fonctions et classes individuelles
- Tests d'intégration pour les interactions entre composants
- Tests de bout en bout pour les scénarios complets

## Structure du Projet

```
pegase/
├── cmd/                    # Points d'entrée des applications
├── internal/               # Code privé de l'application
├── pkg/                    # Bibliothèques réutilisables
├── modules/                # Modules d'attaque et de support
│   ├── core/               # Noyau PEGASE
│   ├── netassault/         # Module d'attaque réseau
│   ├── webbreacher/        # Module d'attaque web
│   └── ...
├── api/                    # Définitions d'API et clients
├── web/                    # Interface utilisateur web
├── docs/                   # Documentation
├── scripts/                # Scripts utilitaires
├── build/                  # Fichiers de build et CI/CD
└── deployments/            # Configurations de déploiement
```

## Développement Local

### Prérequis

- Go 1.18+
- Python 3.9+
- Node.js 16+
- Docker et Docker Compose
- Kubernetes (minikube ou kind pour le développement local)

### Configuration de l'Environnement

```bash
# Cloner le dépôt
git clone https://github.com/votre-organisation/pegase.git
cd pegase

# Installer les dépendances de développement
make dev-setup

# Lancer l'environnement de développement
make dev-up
```

### Exécution des Tests

```bash
# Exécuter tous les tests
make test

# Exécuter les tests d'un module spécifique
make test-module MODULE=netassault

# Exécuter les tests avec couverture
make test-coverage
```

## Processus de Release

1. Les fonctionnalités sont développées sur des branches de fonctionnalités
2. Les Pull Requests sont fusionnées dans `develop`
3. Périodiquement, `develop` est fusionné dans `main` pour une nouvelle release
4. Les tags sont créés pour chaque version selon [Semantic Versioning](https://semver.org/)

## Documentation

La documentation est aussi importante que le code. Pour contribuer à la documentation :

1. Les modifications de la documentation doivent suivre le même processus de PR que le code
2. La documentation technique est maintenue dans le dossier `docs/`
3. Les commentaires de code doivent être clairs et suivre les conventions du langage

## Sécurité

Si vous découvrez une vulnérabilité de sécurité, veuillez NE PAS ouvrir une issue publique. Envoyez plutôt un email à security@pegase-pentest.org avec les détails.

## Questions

Si vous avez des questions sur la contribution, n'hésitez pas à ouvrir une issue avec le tag "question" ou à contacter l'équipe de développement.

Merci de contribuer à PEGASE !
