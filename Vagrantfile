# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.require_version ">= 1.7.0"

Vagrant.configure(2) do |config|
  # Always use Vagrants insecure key
  config.ssh.insert_key = false


  config.vm.box = "centos/7"
  config.vm.define "o2r-staging"

  config.vm.provision "ansible" do |ansible|
    ansible.verbose = "v"
    ansible.playbook = "provisioning/site.yml"
    ansible.groups = {
      "master" => ["o2r-staging"],
      "master:vars" => {
        "docker_mariadb_root_pass" => "superdupersecure!"
      }
    }
  end
end
