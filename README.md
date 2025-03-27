# Rapport d'Analyse des Logs Réseau

## 1. Introduction

Ce rapport présente une analyse approfondie des données de logs réseau contenues dans le fichier `log2.csv`. L'objectif de cette analyse est de comprendre le trafic réseau, d'identifier des tendances, des anomalies potentielles, et de fournir des recommandations pour améliorer la sécurité et les performances du réseau.

## 2. Description des données

Le jeu de données contient **65 532 entrées** avec **12 colonnes** incluant :

- **Informations sur les ports** : Source Port, Destination Port, NAT Source Port, NAT Destination Port
- **Actions effectuées** : allow, deny, drop, reset-both
- **Métriques de trafic** : Bytes, Bytes Sent, Bytes Received, Packets
- **Informations temporelles** : Elapsed Time (sec)
- **Statistiques de paquets** : pkts_sent, pkts_received

## 3. Nettoyage et préparation des données

Lors de l'analyse préliminaire, nous avons constaté que :

- Le jeu de données ne présente pas de valeurs manquantes
- Toutes les colonnes numériques sont correctement typées
- Aucune duplication évidente n'a été détectée

Le jeu de données était déjà relativement propre et n'a pas nécessité de transformations majeures. Nous avons toutefois créé quelques variables dérivées pour faciliter l'analyse :

- Ratio bytes/packet pour analyser l'efficacité des transmissions
- Catégorisation du temps écoulé pour simplifier l'analyse temporelle
- Indicateurs de direction de trafic (entrant/sortant)

## 4. Analyse exploratoire des données

### 4.1 Distribution des actions

L'analyse des actions montre la distribution suivante :

- **allow** : 37 640 entrées (57,4%)
- **drop** : 12 851 entrées (19,6%)
- **deny** : 14 987 entrées (22,9%)
- **reset-both** : 54 entrées (0,1%)

Cette distribution révèle qu'environ 42,6% du trafic est bloqué d'une manière ou d'une autre, ce qui suggère un niveau modéré de filtrage.

### 4.2 Analyse des ports de destination

Les ports de destination les plus fréquents sont :

1. **Port 53** (DNS) : 15 414 connexions
   - 99,8% autorisées (allow)
   - Transfert moyen : 383,8 bytes

2. **Port 445** (SMB) : 12 891 connexions
   - 99,7% bloquées (principalement drop)
   - Transfert moyen très faible : 68,7 bytes

3. **Port 443** (HTTPS) : 11 684 connexions
   - 99,9% autorisées (allow)
   - Transfert moyen élevé : 294 260,9 bytes

4. **Port 80** (HTTP) : 4 035 connexions
   - 99,8% autorisées (allow)
   - Transfert moyen élevé : 246 069,0 bytes

5. **Port 25174** : 1 087 connexions
   - 100% bloquées (deny)
   - Transfert moyen faible : 78,9 bytes

Cette distribution montre une politique de sécurité cohérente :
- Trafic web (HTTP/HTTPS) principalement autorisé
- Résolution DNS largement autorisée
- Trafic SMB (port 445) presque systématiquement bloqué (bonne pratique de sécurité)

### 4.3 Analyse temporelle

La distribution des connexions par durée montre :

- **0-10s** : 31 483 connexions (48,0%)
  - Seulement 11,4% autorisées
  - Transfert moyen très faible : 102,3 bytes

- **10-60s** : 25 376 connexions (38,7%)
  - 100% autorisées
  - Transfert moyen : 20 506,3 bytes

- **1-5min** : 6 357 connexions (9,7%)
  - 100% autorisées
  - Transfert moyen élevé : 372 016,0 bytes

- **5-30min** : 2 049 connexions (3,1%)
  - 100% autorisées
  - Transfert moyen très élevé : 501 729,2 bytes

- **>30min** : 267 connexions (0,4%)
  - 100% autorisées
  - Transfert moyen extrêmement élevé : 9 169 246,4 bytes

Cette distribution révèle que :
- Les connexions courtes (<10s) sont souvent bloquées (probablement des tentatives d'accès non autorisées)
- Les connexions plus longues sont systématiquement autorisées et transfèrent plus de données
- La durée de connexion est fortement corrélée au volume de données transférées

### 4.4 Analyse du ratio bytes/packet

La distribution du ratio bytes/packet montre :

- **<100 bytes/packet** : 40 992 connexions (62,6%)
- **100-500 bytes/packet** : 21 146 connexions (32,3%)
- **500-1000 bytes/packet** : 2 914 connexions (4,4%)
- **1-10KB/packet** : 480 connexions (0,7%)

Cette distribution suggère que la majorité des paquets sont relativement petits, ce qui est typique pour de nombreux protocoles réseau.

### 4.5 Corrélations

L'analyse des corrélations révèle :

- **Bytes Sent vs Bytes Received** : corrélation forte (0,92)
- **Packets vs Bytes** : corrélation très forte (0,99)
- **Elapsed Time vs Packets** : corrélation faible (0,05)
- **Elapsed Time vs Bytes** : corrélation faible (0,04)

Ces corrélations montrent que :
- Le nombre de paquets est un excellent prédicteur du volume total de données
- Les bytes envoyés et reçus sont généralement proportionnels
- La durée d'une connexion n'est que faiblement liée au volume de données ou au nombre de paquets

## 5. Observations clés et tendances

### 5.1 Trafic Web

Le trafic web (ports 80 et 443) représente une part importante des connexions autorisées et du volume de données transférées. Les connexions HTTPS sont plus nombreuses que HTTP, ce qui reflète la tendance générale vers des communications sécurisées.

### 5.2 Politique de sécurité SMB

Le blocage systématique des connexions sur le port 445 (SMB) indique une politique de sécurité robuste contre les vulnérabilités courantes associées à ce protocole.

### 5.3 Trafic DNS

Le grand nombre de requêtes DNS (port 53) avec de petits volumes de données est typique d'un réseau fonctionnel, où les résolutions de noms sont fréquentes mais légères en terme de données.

### 5.4 Direction du trafic

L'analyse montre que 69,2% des connexions sont principalement sortantes (plus de bytes envoyés que reçus), ce qui suggère que le réseau est davantage utilisé pour envoyer des données que pour en recevoir.

### 5.5 Efficacité des connexions longues

Les connexions de plus longue durée sont significativement plus efficaces en termes de transfert de données, avec un volume moyen beaucoup plus élevé.

## 6. Anomalies potentielles

Bien que l'ensemble des données semble relativement normal, quelques points méritent attention :

1. **Port 25174** : Ce port non standard est systématiquement bloqué, ce qui pourrait indiquer des tentatives d'accès à un service spécifique ou une activité suspecte.

2. **Connexions reset-both** : Bien que peu nombreuses (54), ces connexions pourraient indiquer des problèmes de communication ou des tentatives de connexion malveillantes qui ont été activement terminées.

3. **Trafic de courte durée massivement bloqué** : 88,6% des connexions de moins de 10 secondes sont bloquées, suggérant des tentatives d'accès rapides qui sont potentiellement malveillantes.

## 7. Recommandations

### 7.1 Sécurité

- **Maintenir la politique de blocage SMB** : Continuer à bloquer le trafic SMB (port 445) pour minimiser les risques d'exploitation de vulnérabilités.
- **Surveiller le port 25174** : Investiguer la raison des tentatives d'accès répétées à ce port non standard.
- **Analyser les modèles de blocage** : Examiner plus en détail les motifs des connexions bloquées pour identifier d'éventuelles tentatives d'attaque systématiques.

### 7.2 Performance

- **Optimiser les connexions de longue durée** : Les connexions de plus de 5 minutes sont très efficaces en termes de transfert de données; maximiser leur utilisation pourrait améliorer l'efficacité globale.
- **Investiguer les connexions à ratio bytes/packet élevé** : Ces connexions pourraient bénéficier d'une optimisation pour augmenter l'efficacité de la transmission.

### 7.3 Surveillance

- **Mettre en place une détection d'anomalies** : Implémenter un système qui détecte les écarts par rapport aux patterns normaux identifiés dans cette analyse.
- **Surveiller les changements dans la distribution des actions** : Une augmentation soudaine des actions de blocage pourrait indiquer une activité suspecte.

## 8. Conclusion

L'analyse des logs réseau révèle un environnement réseau avec une politique de sécurité robuste, particulièrement pour les protocoles sensibles comme SMB. Le trafic web et DNS constitue une part significative des communications, avec une tendance vers les connexions sécurisées (HTTPS).

Les corrélations fortes entre paquets et volume de données, ainsi qu'entre bytes envoyés et reçus, fournissent des métriques fiables pour la modélisation et la prédiction du comportement du réseau.

Les recommandations proposées visent à renforcer la sécurité tout en optimisant les performances, en se concentrant sur les modèles identifiés pendant cette analyse.

## 9. Perspectives futures

Pour approfondir cette analyse, il serait pertinent de :

1. **Intégrer des données temporelles** : Ajouter des horodatages précis permettrait d'analyser les variations de trafic au cours du temps.
2. **Classifier par adresses IP** : Analyser les modèles de trafic par source et destination IP.
3. **Identification de protocoles** : Associer chaque connexion à un protocole spécifique pour une analyse plus granulaire.
4. **Développer un modèle prédictif** : Utiliser les corrélations identifiées pour prédire le comportement du réseau et détecter des anomalies en temps réel.