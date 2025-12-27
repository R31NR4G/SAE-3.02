# SAE 3.02 – Développer des applications communicantes  
## Routage en oignon – Communication anonyme

## Présentation du projet
Ce projet a pour objectif de mettre en place un système de communication anonyme inspiré du principe du routage en oignon (Tor).  
Les messages échangés entre les clients passent par plusieurs routeurs virtuels. Chaque routeur ne connaît que le routeur précédent et le suivant, ce qui permet d’assurer l’anonymat des communications.

Le système est composé de :
- un master
- plusieurs routeurs
- plusieurs clients
- une base de données MariaDB

---

## Technologies utilisées
- Python 3
- Sockets TCP
- Threading
- MariaDB
- PyQt5 / PyQt6
- GitHub pour le versionnement

## Utilisation
https://youtu.be/sjx8iEqVbFY?si=osbRZ1yG-Lodzk7U

### Prérequis
- Python 3 installé
- MariaDB installé et configuré
- VMs installé et configuré


### Documentation de réponse au cahier des charges

## 1. Éléments implémentés et non implémentés

### Éléments implémentés
- Communication client/serveur via sockets TCP  
- Routage multi-sauts avec plusieurs routeurs  
- Gestion multi-connexions grâce aux threads  
- Chiffrement en couches (routage en oignon)  
- Génération et utilisation de clés asymétriques simplifiées  
- Base de données MariaDB pour stocker :
  - les routeurs
  - les clés publiques
  - les informations de routage  
- Interfaces graphiques pour le client et le master  
- Lancement dynamique des routeurs via la ligne de commande  
- Logs anonymisés côté routeurs  

### Éléments non implémentés
- Gestion automatique du redémarrage des routeurs
- Interface graphique avancée pour les statistiques réseau
- Tests unitaires automatisés
- client = routeur
- 
---

## 2. Structure du code, modules, protocole, API

### Structure du projet
- `master/`
  - gestion des routeurs
  - distribution des clés
  - communication avec les clients
- `router/`
  - réception des messages
  - déchiffrement d’une couche
  - transmission au prochain saut
- `client/`
  - construction du message en oignon
  - envoi et réception des messages
- `crypto/`
  - fonctions de chiffrement et déchiffrement
- `database/`
  - accès à MariaDB
  - requêtes SQL
- `config/`
  - fichiers de configuration

### Protocole applicatif
Les échanges reposent sur TCP avec un protocole simple :
- envoi de la taille du message
- envoi du message chiffré
- traitement selon le rôle (client, routeur, master)

### API interne
Les modules communiquent via des fonctions clairement séparées :
- fonctions réseau (send / receive)
- fonctions de chiffrement
- fonctions d’accès à la base de données

---

## 3. Description de l’algorithme de chiffrement (forces et faiblesses)

### Principe
Le client construit un message chiffré en plusieurs couches :
- chaque couche est chiffrée avec la clé publique d’un routeur
- chaque routeur enlève une seule couche
- le dernier routeur transmet le message au destinataire final

### Forces
- Anonymisation du chemin réseau
- Aucun routeur ne connaît l’origine et la destination finale
- Principe fidèle au routage en oignon
- Simplicité de compréhension et d’implémentation

### Faiblesses
- Chiffrement simplifié (non sécurisé pour un usage réel)
- Pas de protection contre certaines attaques avancées
- Pas de gestion de l’intégrité ou de l’authentification forte

Ce choix est volontaire et cohérent avec le cadre pédagogique du projet.

---

## 4. Rapport de projet et gestion du projet

Le projet a été organisé de manière progressive :
- analyse du sujet et du cahier des charges
- mise en place d’une architecture simple
- développement incrémental des fonctionnalités
- tests réguliers sur plusieurs machines

### Outils de gestion
- GitHub pour le suivi du code
- commits réguliers pour tracer l’évolution du projet
- organisation du code en modules clairs
