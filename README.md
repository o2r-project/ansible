# Ansible configuration for o2r reference implementation

**Internal documentation, which started out in German and will translated as needed. Please file an issue if you have any questions.**

## tl;dr

There is a `Makefile`.
The default `make` target applies the full playbook to the demo server.
Beforehand you must add the local SSH key for the demo server to the authentication agent.

```bash
ssh-add /<path>/id_rsa
make
```

### Docker timeout issues

**Problem**

```bash
[o2r@ubsvirt148 system]$ sudo docker pull o2rproject/o2r-muncher:0.25.0
Error response from daemon: Get https://registry-1.docker.io/v2/: net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers)
```

**Solution**

```bash
[o2r@ubsvirt148 system]$ sudo systemctl daemon-reload
[o2r@ubsvirt148 system]$ sudo systemctl restart docker
```

## Docker user

The o2r password safe contains the crendentials of a Docker ID account `o2ruser` that can be used to login on the server.

## Configuration files to edit for this playbook to work

- `provisioning/group_vars/all/vars.yml.template` - rename to `vars.yml` and put in the proxy server for public web access
- `provisioning/host_vars/<hostname>/vault.yml` - the vault file for each host (see section [#secrets-and-passwords](Secrets and passwords))

## Configuration overview

Configuration is done with Ansible (`>= 2.0`), which installs the following software and applies configurations on a server.

- proxy settings (WWU-specific)
- [screen](https://centoshelp.org/resources/scripts-tools/a-basic-understanding-of-screen-on-centos/)
- yum updates
- EPEL repository
- docker
- Python package [`docker`](https://pypi.org/project/docker/) from PyPi (required for Docker via Ansible)
- MongoDB `3.6` in Docker container
- mariadb in Docker container
- [inactive] piwik in Docker container (visitor statistics for http://o2r.info and https://o2r.uni-muenster.de); inofficial piwik container, but works well; watch out when updating the container because on the first run the build in webserver might have to generate private keys, which takes some time!
- nginx in Docker-Container (_not_ running as a systemd service!)
  - reverse proxy für die o2r-microservices (siehe reverse proxies in `provisioning/roles/docker-nginx/templates/nginx.conf_all.j2`)
  - reverse proxy /mongo-express auf die mongo-express-Instanz >> http://o2r-mongo-express:8081
  - reverse proxy /piwik auf die Piwik-Instanz
  - hosting von `/static` - Dateien
  - proxy for WWU website (available at `/wwuproxy`) for accessing the CRIS system without CORS issues (used for [publication list](https://o2r.uni-muenster.de/wwuproxy/forschungaz-rest/ws/public/infoobject/getrelated/Project/9520/PROJ_has_PUBL) on https://o2r.info/publications)
- mongo-express in Docker container, publicly available at http://ubsvirt148.uni-muenster.de:8027/ (secured via HTTP Basic Auth, username and password in o2r password safe)
- [inactive]  Elasticsearch in Docker Container currently disabled (secured via nginx proxy, which only allows `GET` requests on the endpoint for search)
- o2r-microservices in Docker containers
  - bouncer
  - muncher (with access to Docker socket)
  - [inactive] finder
  - informer
  - ui (the web page)
  - shipper
  - [inactive] badger
  - substituter

## Service names

Container names should match names of systemd services, i.e. the name of the unit file should be `<container-name>.service`.

## Server OS

`cat /etc/centos-release` > CentOS Linux release 7.2.1511 (Core)
`cat /proc/version` > Linux version 3.10.0-327.28.2.el7.x86_64 (builder@kbuilder.dev.centos.org) (gcc version 4.8.3 20140911 (Red Hat 4.8.3-9) (GCC) ) #1 SMP Wed Aug 3 11:11:39 UTC 2016

## Server hardware

Information received by IT staff:

> _CentOS 7.2 mit 4 Kernen und ~~8~~ 16 GB Ram. Die Platte ist zurzeit 100 GB groß. Sollte da in der Performance etwas nicht passen, können wir das noch korrigieren._
> _Snapshots sind eingerichtet. Es wird jeden Sonntag um ca. 21:00 ein komplettes Image der VM erstellt und auf ein anderes Storage (außerhalb des Datacenters) gespeichert._

## Secrets and passwords

Tokens, passwords, account names - everything relevant to security is stored in an [Ansible Vault](http://docs.ansible.com/ansible/playbooks_vault.html) for each host.
The vault file is stored in an independent project, which is not publicly hosted, as an additional layer of security.
To use the vault file, copy it into this project at `provisioning/host_vars/<hostname>`, where it will be ignored by git.

The command to edit a vault file is

```bash
ansible-vault edit <path to vault project>/provisioning/host_vars/<hostname>/vault.yml
```

Don't forget to manually sync the vault files between the vault file project and this project.
Daniel has the password to the vault(s) and can give it to you in a secure way.

## Server connection and authentication

`id_rsa` file for connecting to the demo server is in Daniel's custory.
Not that you must copy it to your own machine an restrict the access (`chmod 400`) so you can add it to your local keychain before you connnect.

There is a user `o2r` on the demo server.

## Development

### Add microservices or apps

1. neue Ansible role erstellen, dabei den zugehörigen Container über eine [systemd service unit configuration](https://www.freedesktop.org/software/systemd/man/systemd.service.html) ([unit configuration](https://www.freedesktop.org/software/systemd/man/systemd.unit.html)) starten und überwachen lassen (wichtig: links zu benötigten containern nicht vergessen); systemd fährt fehlende container automatisch wieder hoch
1. role in `provisioning/master.yml` eintragen (_vor nginx!_)
1. location mapping in nginx Konfiguration eintragen: `../docker-nginx/templates/nginx.conf.j2`
1. container aus nginx heraus verlinken (damit internes resolving funktioniert), siehe `../docker-nginx/tasks/main.yml`
1. [optional/bei Problemen:] nginx container auf dem Server stoppen und entfernen, damit neuer Link funktioniert (scheint bei jeder Änderung der veröffentlichten ports etc. notwendig zu sein)
1. Playbook laufen lassen

### Remove services

```bash
[o2r@ubsvirt148 ~]$ sudo systemctl stop elasticsearch
[o2r@ubsvirt148 ~]$ sudo systemctl disable elasticsearch
Removed symlink /etc/systemd/system/multi-user.target.wants/elasticsearch.service.
[o2r@ubsvirt148 ~]$ sudo rm /etc/systemd/system/elasticsearch.service 
```

```bash
[o2r@ubsvirt148 ~]$ sudo systemctl stop o2r-finder
[o2r@ubsvirt148 ~]$ sudo docker rm -f o2r-finder
o2r-finder
[o2r@ubsvirt148 ~]$ sudo systemctl disable o2r-finder
Removed symlink /etc/systemd/system/multi-user.target.wants/o2r-finder.service.
[o2r@ubsvirt148 ~]$ sudo rm /etc/systemd/system/o2r-finder.service
```

### Update second-level containers

If you want to update the version of `o2r-meta` and `containerit`, i.e., the "second-level" containers used by the microservices, then make sure to recreate (`docker rm -f`) the containers of the microservices using them (`o2r-muncher`).

### Website "o2r-UI"

o2r-UI runs in a container with it's own webserver respectively Node.js application with a development server.

## Bugfixing

### Check deployed versions on a server

A static versions file in JSON format is generated at provisioning and available on the server at `http(s)://.../_config/versions.json`, for example [https://o2r.uni-muenster.de/_config/versions.json](https://o2r.uni-muenster.de/_config/versions.json).

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

# List all o2r services
sudo systemctl list-unit-files | grep o2r
sudo systemctl list-units o2r-* --all

# Stop/start all o2r services
sudo systemctl stop o2r-*
sudo systemctl start o2r-*

# Logs sind auch über journalctl einsehbar: https://www.digitalocean.com/community/tutorials/how-to-use-journalctl-to-view-and-manipulate-systemd-logs
# Siehe auch roles/journald für die aktive Konfiguration
ls /etc/systemd/system
sudo journalctl -u o2r-muncher.service
sudo journalctl --since yesterday
sudo journalctl --since "1 hour ago"
sudo journalctl -b
sudo journalctl --list-boots

# if there are too many logs, retain only the past x hours/days
journalctl --vacuum-time=1d

# Wenn nichts mehr hilft, vielleicht ein Docker restart
sudo systemctl restart docker

# ... or maybe a systemctl restart
sudo systemctl daemon-reload
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

#### Remove old images and clean up space used by Docker

Die alten (untagged) images können mit folgendem Befehl entfernt werden (zum Test zuvor nur das innere Kommando ausführen):

```bash
sudo docker rmi $(sudo docker images | grep "<none>" | awk '{print $3}')
```

Check used space with

```bash
sudo docker system df
```

and clean up specific parts with (the `-a` option removes unused images, not just dangling ones)

```bash
docker volume prune
docker container prune
docker image prune -a
docker network prune
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

# How des the configuration look like, that is actually used by sytemctl? Very helpful if there are issues with escaping environment variables, e.g. shipper with JSON; execute the commands manually to see what the error message is.
sudo systemctl show o2r-shipper

# If there are problems starting the service, copy and paste the ExecStartPre content from the previous output and run it manually with Docker
```

### Debugging der Docker network Konfiguration

Alle IPs der Docker container anzeigen lassen:

```bash
sudo docker ps -q | xargs -n 1 sudo docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}} {{ .Name }}' | sed 's/ \//\t/'
```

### "Topology was destroyed" error

This can happen if the MongoDB was restarted and a microservice still has the "old" connection open.
You need to restart the service of that microservice, just restarting the container will result in an incorrect link to an outdated `mongodb` container.

### Quoting variables for Docker

Source: https://github.com/mozilla/fxa-dev#about-using-docker_container-and-quoting-of-environment-values

> `docker_container` (>=2.8) now insists that environment values be quoted. However, when evaluating `"{{ foo }}"`, those quotes are removed.
> So use the `to_json` jinja2 filter to ensure that the value is quoted.
> Note: I use `to_json` instead of `quote` because `quote` will not quote Boolean values `true` and `false`.
> 
> If not quoted, the error will look like `"Non-string value found for env option. Ambiguous env options must be wrapped in quotes to avoid them being interpreted. Key: ENV_VAR_NAME"`. If you see this error, add a to_json in your templates and try again.

Example:

```yaml
ME_CONFIG_MONGODB_PORT: '"{{ mongo_port | to_json }}"'
```

## Security

### SSH and ports

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

### HTTPS certificate

The certificates are stored on the host in `/etc/nginx-docker/` (uploaded via SCP).
The certificate files are mounted into the nginx proxy (see `provisioning/role/docker-nginx/tasks/main.yml` ([used manual 1](http://nginx.org/en/docs/http/configuring_https_servers.html), [used manual 2](https://bjornjohansen.no/securing-nginx-ssl)).
HTTP is redirected to HTTPS ([used instruction](https://bjornjohansen.no/redirect-to-https-with-nginx)) and only strong cipher suites are enabled.

You can learn more about CA certificate issuing at WWU at [https://www.uni-muenster.de/WWUCA/de/cacerts.html](https://www.uni-muenster.de/WWUCA/de/cacerts.html).
Please check that site for up-to-date links to base certificates and more instructions.
The certificate chain _without_ the Telekom Root certificate (!) was created with the following commands _on the server_:

```bash
# Upload files
#scp /home/daniel/ownCloud/o2r-data/Server/o2r.uni-muenster.de\ @\ ULB/Server-Certificate_2019/*.pem o2r@ubsvirt148.uni-muenster.de:/home/o2r

# Login to server and move the files
cd /etc/nginx-docker/
mv ~/*.pem /etc/nginx-docker/
chown root:root *.pem

# Get chain 2016
# wget https://pki.pca.dfn.de/wwu-ca/pub/cacert/chain.txt
# manually remove certificate starting with "subject= /C=DE/O=Deutsche Telekom ..."
# nano chain.txt

# 2016 certificate:
#cat cert-7648722783260631.pem chain.txt > bundle.crt

# Get chain without root in 2019
wget https://www.uni-muenster.de/WWUCA/chain.pem

# 2019 certificate:
#mv bundle.crt bundle.crt_2016
cat cert-10275895817424272556132495911.pem chain.pem > bundle.crt

# Restart the webserver so new certificate takes effect
docker restart nginx
```

The serial number of the certificate as well as the certificate key are stored in the o2r password safe.

The SSL certificate password is stored in the file `/etc/keys/global.pass` on the server, which can only be read by the `root` user.
The file is generated as part of the Ansible script with information from the vault.

Test suite: https://www.ssllabs.com/ssltest/analyze.html?d=o2r.uni%2dmuenster.de&hideResults=on&latest

The DH parameters were generated on the server ([used instructions](https://weakdh.org/sysadmin.html), [about keylength](https://www.keylength.com/en/compare/); duration for creation of 4096er varian: about 15 minutes):

```bash
[o2r@ubsvirt148 /etc/nginx-docker]$ sudo openssl dhparam -out dhparams.pem 8192
```

### SELinux

SELinux ist auf `permissive` gesetzt, weil anders MongoDB nicht funktionieren wollte, siehe https://zivgitlab.uni-muenster.de/o2r/o2r-ansible/issues/9.

## Databases

### MongoDB

MongoDB is running in version `3.6` in a container, but without a system service configuration.

**Important**: The MongoDB must have a [replication set](https://docs.mongodb.com/manual/replication/) configured and initialised, even if there are no replications, because the [oplog](https://docs.mongodb.com/manual/core/replica-set-oplog/) is used by some microservices as a makeshift event queue for notifications.
The taks to set this up are included in the role, `roles/mongodb`.

To get the current state of the MongoDB, run

```bash
sudo docker logs mongodb
```

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