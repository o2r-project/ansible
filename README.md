# Ansible configuration for o2r reference implementation

**Internal documentation, which started out in German and will translated as needed. Please file an issue if you have any questions.**

## tl;dr

Für die Benutzung liegt ein `Makefile` bereit.
Mit `make` wird das Playbook auf die Produktionsserver angewandt.
Zuvor muss der lokale SSH key für den deployment user noch im authentication agent hinterlegt werden.

```bash
ssh-add /<path>/id_rsa
make
```

Bei Fragen: [https://o2r.slack.com/messages/server/](https://o2r.slack.com/messages/server/)

## Enthaltene services

Die Konfiguration erfolgt mittels Ansible (`>= 2.0`), und richtet den Server mit folgender Software ein.

- proxy-Einstellungen (WWU-spezifisch)
- [screen](https://centoshelp.org/resources/scripts-tools/a-basic-understanding-of-screen-on-centos/)
- yum updates
- EPEL repository
- MongoDB `3.4` (bare metal, sollte besser sein als im Container)
  - config file liegt unter `cat /usr/lib/systemd/system/mongod.service `
- docker
- docker-py (für Docker via Ansible benötigt)
- mariadb in Docker-Container
- piwik in Docker-Container (Nutzungsstatistiken von http://o2r.info)
- nginx in Docker-Container (läuft _nicht_ über systemd!)
  - reverse proxy für die o2r-microservices (siehe reverse proxies in `provisioning/roles/docker-nginx/templates/nginx.conf_all.j2`)
  - reverse proxy /mongo-express auf die mongo-express-Instanz >> http://o2r-mongo-express:8081
  - reverse proxy /piwik auf die Piwik-Instanz
  - hosting von `/static` - Dateien
  - proxy für WWU-Webseite (`/wwuproxy`) für CORS-losen Zugriff auf CRIS (genutzt für [Publikationsliste](https://o2r.uni-muenster.de/wwuproxy/forschungaz-rest/ws/public/infoobject/getrelated/Project/9520/PROJ_has_PUBL) auf o2r.info)
- mongo-express in Docker-Container (abgesichert über HTTP Basic Auth), erreibbar unter http://ubsvirt148.uni-muenster.de:8027/ (Username und Passwort sind im vault)
- Elasticsearch in Docker-Container ("abgesichert" über nginx Proxy, der nur `GET` requests and den Endpoint für Suche erlaubt)
- o2r-microservices in Docker-Containern
  - bouncer
  - muncher (inklusive mount von `/var/run/docker.sock` um Container zu starten)
  - finder
  - informer
  - loader
  - transporter (inklusive mount von `/var/run/docker.sock` um Container zu starten)
  - platform (die Website)
  - shipper
  - badger
  - substituter

## Server OS

`cat /etc/centos-release` > CentOS Linux release 7.2.1511 (Core)
`cat /proc/version` > Linux version 3.10.0-327.28.2.el7.x86_64 (builder@kbuilder.dev.centos.org) (gcc version 4.8.3 20140911 (Red Hat 4.8.3-9) (GCC) ) #1 SMP Wed Aug 3 11:11:39 UTC 2016

## Server Hardware

Info bei Einrichtung:

> _CentOS 7.2 mit 4 Kernen und 8 GB Ram. Die Platte ist zurzeit 100 GB groß. Sollte da in der Performance etwas nicht passen, können wir das noch korrigieren._
> _Snapshots sind eingerichtet. Es wird jeden Sonntag um ca. 21:00 ein komplettes Image der VM erstellt und auf ein anderes Storage (außerhalb des Datacenters) gespeichert._

## [Beta] Lokaler Test

Mittels Vagrant kann das Playbook lokal auf einer automatisch erstellten virtuellen Maschine getestet werden. Dazu gibt es die Befehle `make staging`, welcher mittels Vagrant eine VM einrichtet und Ansible ausführt, sowie `make clean` um diese nach den Tests wieder zu entfernen.

## Secrets und Passwörter

Sicherheitsrelevante Einstellungen werden je host in einem [Ansible Vault](http://docs.ansible.com/ansible/playbooks_vault.html) gespeichert. Kommando zum Editieren dieses Vaults:

```bash
ansible-vault edit provisioning/host_vars/ubsvirt148.uni-muenster.de/vault.yml
```

Das Passwort für den vault gibt es bei Daniel.

## Entwicklung

### Microservices oder Apps hinzufügen

1. neue Ansible role erstellen, dabei den zugehörigen Container über eine [systemd service unit configuration](https://www.freedesktop.org/software/systemd/man/systemd.service.html) ([unit configuration](https://www.freedesktop.org/software/systemd/man/systemd.unit.html)) starten und überwachen lassen (wichtig: links zu benötigten containern nicht vergessen); systemd fährt fehlende container automatisch wieder hoch
1. role in `provisioning/master.yml` eintragen (_vor nginx!_)
1. location mapping in nginx Konfiguration eintragen: `../docker-nginx/templates/nginx.conf.j2`
1. container aus nginx heraus verlinken (damit internes resolving funktioniert), siehe `../docker-nginx/tasks/main.yml`
1. [optional/bei Problemen:] nginx container auf dem Server stoppen und entfernen, damit neuer Link funktioniert (scheint bei jeder Änderung der veröffentlichten ports etc. notwendig zu sein)
1. Playbook laufen lassen

### Website "o2r-platform"

o2r-platform liegt container mit eigenem Webserver vor nicht mehr als [git submodule](https://git-scm.com/docs/git-submodule), da der uplauf auf den Server wegen extrem hoher Dateianzahl über Ansibles `copy` zu langsam war und `rsync` nicht funktioniert.

## Bugfixing

### Zertifikatsprobleme

Im Oktober 2017 gab es Probleme mit den Zertifikaten im nginx.
Alles Zertifikate waren gemountet wie vorher, und auch ohne dass der nginx-Container lief hat (irgendein?) nginx-Server geantwortet, natürlich nicht mit dem richtigen Zertifikat.
Geholfen hat `sudo shutdown -r now`.

### Kommandos zur Überwachung der mit `systemd` verwalteten services

```bash
# Statusübersicht
sudo systemctl | grep o2r

# Detaillierter Status eines service, inklusive neuester error logs
sudo systemctl status o2r-finder
sudo systemctl status mongod

# Logs sind auch über journalctl einsehbar: https://www.digitalocean.com/community/tutorials/how-to-use-journalctl-to-view-and-manipulate-systemd-logs
# Siehe auch roles/journald für die aktive Konfiguration
ls /etc/systemd/system
sudo journalctl -u o2r-transporter.service
sudo journalctl --since yesterday
sudo journalctl --since "1 hour ago"
sudo journalctl -b
sudo journalctl --list-boots

# Wenn nichts mehr hilft, vielleicht ein Docker restart
sudo systemctl restart docker

# Oder ein systemctl restart
systemctl daemon-reload
```

- Mehr Infos [hier](https://wiki.archlinux.de/title/Systemd).
- Bei Änderung der `.service`-Datei muss ggf. doch manuell der Container gestoppt und gestartet werden

### Kommandos für microservices

```bash
# Konsole in einem Container starten > nützlich um benötigte contaienr anzupingen etc.
sudo docker exec -it o2r-finder /bin/sh

# Elasticsearch Index löschen
sudo docker exec -it elasticsearch curl -XDELETE 'http://localhost:9200/o2r/'
```

### Verwalten der images

#### Auflistung der images

```bash
sudo docker images | grep o2r
```

#### Entfernen alter images

Die alten (untagged) images können mit folgendem Befehl entfernt werden (zum Test zuvor nur das innere Kommando ausführen):

```bash
sudo docker rmi $(sudo docker images | grep "<none>" | awk '{print $3}')
```

Eigentlich sollte keines dieser images genutzt werden. Wenn dennoch images nicht entfernt werden können dann nutzen die microservices vermutlich veraltete images. Das Alter der images überprüfen mit `sudo docker ps`, Spalte `CREATED` zeigt wann der container erzeugt wurde, was einen Ansatzpunkt zur Überprüfung des image-Alters gibt.

```bash
# simple Variante, die funktionieren sollte: image pullen, container geforced entfernen, systemctl startet container neu

# ausführlichere Variante mit manuellem stoppen des containers und entfernen des alten images
sudo systemctl stop [service name, e.g. o2r-<microservice>] # note the image ID
sudo docker rmi -f <image ID>
sudo docker rm [container name, e.g. o2r-<microservice>]
sudo systemctl start [service name]
sudo docker ps
```

### Debugging der µservices

Wie kann ich prüfen ob der µservice läuft oder das Problem im Proxy liegt?

```bash
sudo docker exec -it nginx /bin/sh # shell im nginx proxy starten

wget -qO- o2r-muncher:8080/api/v1 # µservice direct aufrufen
```

### Debugging der sytemd Konfiguration

Für schnelleres testen verschiedener systemd-Konfigurationen (schneller als immer Ansible laufen lassen..) ist auch ein direktes editieren der `.service` - Dateien möglich.

```bash
# Datei editieren (Beispielµservice "o2r-badger")
sudo nano /etc/systemd/system/o2r-badger.service

# Service neu starten
sudo systemctl daemon-reload
sudo systemctl restart o2r-badger

# Hat alles geklappt?
sudo systemctl status o2r-badger

# Wie sieht die Konfiguration aus, die wirklich genutzt wird? (Nützlich wenn es Probleme beim escaping gibt)
sudo systemctl show o2r-shipper
```

### Debugging der Docker network Konfiguration

Alle IPs der Docker container anzeigen lassen:

```bash
sudo docker ps -q | xargs -n 1 sudo docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}} {{ .Name }}' | sed 's/ \//\t/'
```

## Sicherheit

### SSH und ports

SSH-Zugriff auf den Server kann nur aus dem verschlüsselten WWU VPN erfolgen. Öffentlicher Zugriff (nur https per redirect in der nginx-Konfiguration) ist nur über die Ports `80` und `443` möglich. Diese Ports sind explizit in der ZIV Firewall gewhitelistet (via CH, ULB).

Auf dem Server `ubsvirt148` wird dies durch `iptables` festgelegt ([Basisdokumentation](http://www.howtogeek.com/177621/the-beginners-guide-to-iptables-the-linux-firewall/), die Konfiguration dafür befindet sich in `/etc/sysconfig/iptables`. Ein dump der Konfiguration (Stand 10.08.2016) befindet sich in der Datei `iptables-rules-2016-08-10.txt`.

Die beim Serverstart geladenen Regeln befinden sich in der Datei `/etc/sysconfig/iptables`.

#### VPN Zugriff Konfiguration

Zugriff ist nur über die IP range von dem gesicherten VPN der Uni Münster möglich. Konfigurationsparameter:

- Zugriff über "Cisco Compatible", also `vpnc` Protokoll unter Linux, möglich
- ~~Unter Ubuntu `vpnc` (und `network-manager-vpnc-gnome`) installieren~~
- ~~Alle Konfigurationsparameter sind in (_nur_) dieser Anleitung im ZIV-Wiki enthalten (inkl. "geheimen" Gruppenpasswort): https://www.uni-muenster.de/ZIVwiki/bin/view/Anleitungen/CiscoIPSecVPNSetupAndroid4~~
- Linux: `sudo openconnect vpn.uni-muenster.de`

### Session secrets

Die o2r microservices auf Basis von node.js nutzen express.js zum Handling der Sessions. Hier wird eine zufällige session-ID gesetzt, die zur Authentifikation als ein bestimmter User genutzt werden kann. Der zusätzliche Konfigurationsparameter `secret` wird genutzt um die session zu verschlüsseln, liefert aber laut [diesem Stackoverflow post](http://stackoverflow.com/questions/18565512/importance-of-session-secret-key-in-express-web-framework) keine zusätzliche Sicherheit, sondern ist notwendig wenn incrementelle IDs vergeben werden. Daher wird diese Einstellung, die in den diversen `config.js`-Dateien vorhanden ist, _nicht genutzt_. Mit der session ID aus dem Cookie [kann (wie zu erwarten) die session gestohlen werden](http://security.stackexchange.com/questions/92122/why-is-it-insecure-to-store-the-session-id-in-a-cookie-directly).

### HTTPS / Zertifikate

Die Zertifikate liegen auf dem host in `/etc/nginx-docker/` und werden von da in den nginx proxy gemountet, siehe `provisioning/role/docker-nginx/tasks/main.yml` ([genutzte Anleitung 1](http://nginx.org/en/docs/http/configuring_https_servers.html), [genutzte Anleitung 2](https://bjornjohansen.no/securing-nginx-ssl)).
HTTP wird auf HTTPS umgeleitet ([genutzte Anleitung](https://bjornjohansen.no/redirect-to-https-with-nginx)).

Die chain (_ohne_ das Telekom Root Zertifikat) ist mit folgenden Befehlen auf dem Server erstellt worden:

```bash
wget https://pki.pca.dfn.de/wwu-ca/pub/cacert/chain.txt
# manually remove certificate starting with "subject= /C=DE/O=Deutsche Telekom ..."
cat cert-7648722783260631.pem chain.txt > bundle.crt
```

Die Seriennummer des Zertifikats sowie der key werden bei Daniel gesichert aufbewahrt.

Test suite: https://www.ssllabs.com/ssltest/analyze.html?d=o2r.uni%2dmuenster.de&hideResults=on&latest

DH Parameter wurden auf dem Server generiert ([Anleitung](https://weakdh.org/sysadmin.html), [Keylength](https://www.keylength.com/en/compare/); Dauer für Erstellung von 4096er Variante: 15 min.):

```bash
[o2r@ubsvirt148 /etc/nginx-docker]$ sudo openssl dhparam -out dhparams.pem 8192
```

### SELinux

SELinux ist auf `permissive` gesetzt, weil anders MongoDB nicht funktionieren wollte, siehe https://zivgitlab.uni-muenster.de/o2r/o2r-ansible/issues/9.

## Datenbanken

### MongoDB

Die MongoDB läuft direkt auf dem host, und muss aus den Containern erreichbar sein. Falls eine Firewall mit `iptables` o. Ä. umgesetzt wurde, müssen dementsprechende Regeln gesetzt werden.

Außerdem muss auf der MongoDB ein [replication set](https://docs.mongodb.com/manual/replication/) konfiguriert und initialisiert sein, selbst wenn es keine Replikationen gibt, weil der [oplog](https://docs.mongodb.com/manual/core/replica-set-oplog/) von einigen Microservices für event-basierte Updates genutzt wird. Die entsprechenden Tasks sind in der Rolle `roles/mongodb` enthalten.

### MariaDB

Eine MariaDB (MySQL) läuft in einem container und wird von PiWik genutzt. Im vault ist ein Passwort für Verbindung als root user. Folgender code kann helfen von einer Server-Shell aus direkt in der DB Änderungen vorzunehmen.

```bash
sudo docker exec -it mariadb /bin/bash
mysql -p
# Passwort eingeben..
MariaDB [(none)] > SHOW DATABASES;
MariaDB [(none)] > USE piwik;

# in Piwik eine Tabelle (für einen bestimmten Monat) droppen um Daten einer Site zu löschen, siehe https://piwik.org/faq/how-to/faq_73/
MariaDB [(piwik)] > SHOW TABLES;
MariaDB [(piwik)] > SELECT DISTINCT(idsite) FROM piwik_archive_numeric_2017_09;
MariaDB [(piwik)] > DELETE FROM piwik_archive_numeric_2017_09 WHERE idsite = 4;
MariaDB [(piwik)] > DELETE FROM piwik_archive_blob_2017_09 WHERE idsite = 4;
# purge visitor log data for a given site
MariaDB [(piwik)] > DELETE FROM piwik_log_visit WHERE idsite = 4; DELETE FROM piwik_log_link_visit_action WHERE idsite = 4; DELETE FROM piwik_log_conversion WHERE idsite = 4; DELETE FROM piwik_log_conversion_item WHERE idsite = 4;
```

## Schnelles Deployen von `o2r-***` services

Die Unit-Files der einzelnen Services erstellen Container automatisch neu, sobald diese abstürzen/fehlen. Dadurch genügt

```sh
sudo docker pull o2rproject/o2r-**** # neues Image für den service aus Docker Hub laden, dann container stoppen und neu starten

# alternativ:
sudo docker rm -f o2r-**** && sudo docker rmi o2rproject/o2r-**** # container mit altem Image entfernen (mit force weil er läuft), und altes image entfernen (damit latest gepullt wird), ein neuer container wird unmittelbar durch systemd gestartet.
# kurz warten bis er wieder da ist, dann ggf. web server neu starten damit die Proxy-Verbindungen wieder funktionieren
sudo docker restart nginx
```

um einen Service aus dem Docker Hub zu aktualisieren und auf dem Server zu deployen.

Alternative: alle Docker images, die `<none>` getaggt sind vom Server löschen:

```sh
sudo docker ps | grep o2r | 
sudo docker images | grep none | awk {'print $3'} | xargs sudo docker rmi --force
```

## ERC container / Bagtainers verwalten

Ein cronbjob für den user `root` löscht alle `bagtainer:` images welche `Created`, also nicht `Up`, und älter als 2 Wochen sind.
Dieser job ist über die Rolle `roles/dockercontainers-cron` eingerichtet. Der log output der Tasks steht in `/var/log/cron`.

## License

Files in this project are licensed under Apache License, Version 2.0, see file LICENSE.

Copyright (C) 2018 - o2r project.