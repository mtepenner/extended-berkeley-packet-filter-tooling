Vagrant.configure("2") do |config|
  # Use a standard, modern Ubuntu LTS release
  config.vm.box = "ubuntu/jammy64" 
  
  # Allocate enough resources for compiling
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
    vb.cpus = 2
  end

  # The provisioning script runs automatically on the first boot
  config.vm.provision "shell", inline: <<-SHELL
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    
    # Install standard build tools, LLVM/Clang for eBPF, Go, and kernel headers
    apt-get install -y build-essential \
                       clang \
                       llvm \
                       make \
                       golang-go \
                       linux-headers-$(uname -r) \
                       linux-tools-$(uname -r) \
                       linux-tools-common

    # Automatically drop the user into the shared folder upon login
    echo "cd /vagrant" >> /home/vagrant/.bashrc
    
    echo "=========================================="
    echo "eBPF Dev Environment Ready!"
    echo "Run 'vagrant ssh' to enter the VM."
    echo "=========================================="
  SHELL
end
