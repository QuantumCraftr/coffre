# Politique de sécurité

## Statut

`coffre` est en **pré-alpha**. Il n'a pas encore été audité et ne doit pas stocker de secrets
critiques. Les primitives sont validées par validation croisée, mais l'ensemble n'a pas subi
d'audit externe.

## Signaler une vulnérabilité

Merci de **ne pas ouvrir d'issue publique** pour une faille de sécurité.

- GitHub : onglet **Security** → **Report a vulnerability** (advisory privée).
- Email : `jbdev31@gmail.com`, objet `[coffre security]`.

Merci d'inclure :

- une description de la vulnérabilité et de son impact ;
- les étapes de reproduction ou une preuve de concept ;
- la version ou le commit concerné ;
- ton nom ou pseudo si tu souhaites être crédité.

## Périmètre

Couvre notamment : format de fichier, chiffrement, dérivation de clé, écriture atomique,
zeroization, CLI et mode `run`.

Hors périmètre (assumé, voir [`THREAT_MODEL.md`](THREAT_MODEL.md)) : attaquant root sur la
machine en cours d'usage, keylogger, cold boot, evil maid, exposition de l'environnement d'un
process enfant en mode `run`, `COFFRE_PASSPHRASE` visible dans l'environnement du process.

## Délais

- Accusé de réception sous 7 jours.
- Correctif ou plan sous 30 jours pour les failles confirmées, selon la gravité.
- Divulgation coordonnée après publication du correctif.

## Pas de bug bounty

Projet bénévole, pas de récompense financière. Crédit dans l'advisory si souhaité.
