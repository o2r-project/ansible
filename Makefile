default: provision

lint:
	ansible-playbook --ask-vault-pass --syntax-check -i hosts provisioning/site.yml
.PHONY: lint

provision:
	ansible-playbook --ask-vault-pass -i hosts provisioning/site.yml
.PHONY: provision

provision-microservices:
	ansible-playbook --ask-vault-pass -i hosts provisioning/site.yml --tags "microservice,nginx"
.PHONY: provision-muncher

provision-docker:
	ansible-playbook --ask-vault-pass -i hosts provisioning/site.yml --tags "docker"
.PHONY: provision-docker

provision-mariadb:
	ansible-playbook --ask-vault-pass -i hosts provisioning/site.yml --tags "mariadb"
.PHONY: provision-mariadb

provision-mongo-express:
	ansible-playbook --ask-vault-pass -i hosts provisioning/site.yml --tags "mongoexpress"
.PHONY: provision-mongo-express

provision-nginx:
	ansible-playbook --ask-vault-pass -i hosts provisioning/site.yml --tags "nginx"
.PHONY: provision-nginx

provision-insert-ip:
	ansible-playbook --ask-vault-pass -i hosts provisioning/site.yml --tags "insert_ip" -vv
.PHONY: provision-insert-ip

provision-bouncer:
	ansible-playbook --ask-vault-pass -i hosts provisioning/site.yml --tags "bouncer,nginx"
.PHONY: provision-bouncer

provision-muncher:
	ansible-playbook --ask-vault-pass -i hosts provisioning/site.yml --tags "muncher,nginx"
.PHONY: provision-muncher

provision-finder:
	ansible-playbook --ask-vault-pass -i hosts provisioning/site.yml --tags "finder,nginx"
.PHONY: provision-finder

provision-informer:
	ansible-playbook --ask-vault-pass -i hosts provisioning/site.yml --tags "informer,nginx"
.PHONY: provision-informer

provision-inspecter:
	ansible-playbook --ask-vault-pass -i hosts provisioning/site.yml --tags "inspecter,nginx"
.PHONY: provision-inspecter

provision-shipper:
	ansible-playbook --ask-vault-pass -i hosts provisioning/site.yml --tags "shipper,nginx"
.PHONY: provision-shipper

provision-piwik:
	ansible-playbook --ask-vault-pass -i hosts provisioning/site.yml --tags "piwik,nginx"
.PHONY: provision-piwik

provision-badger:
	ansible-playbook --ask-vault-pass -i hosts provisioning/site.yml --tags "badger,nginx"
.PHONY: provision-badger

provision-mongodb:
	ansible-playbook --ask-vault-pass -i hosts provisioning/site.yml --tags "mongodb"
.PHONY: provision-mongodb

provision-ui:
	ansible-playbook --ask-vault-pass -i hosts provisioning/site.yml --tags "ui,nginx"
.PHONY: provision-ui

provision-bindings:
	ansible-playbook --ask-vault-pass -i hosts provisioning/site.yml --tags "bindings,nginx"
.PHONY: provision-bindings

ping:
	ansible all -i hosts -m ping -u o2r
.PHONY: ping
