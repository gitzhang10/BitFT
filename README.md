## Description
This project is used to implement a blockChain with a weak asynchronous BFT -- BitFT.
There are two protocols: BitFT and Layered BitFT.

## Usage
### 1. Machine types
Machines are divided into two types:
- *WorkComputer*: just configure `servers` at the initial stage, particularly via `ansible` tool. 
- *Servers*: run daemons of `BitFT`, communicate with each other via P2P model.

### 2. Precondition
- Recommended OS releases: Ubuntu 18.04 (other releases may also be OK)
- Go version: 1.16+ (with Go module enabled)
- Python version: 3.6.9+

#### 2.1 Install go
```
sudo apt-get update
mkdir tmp
cd tmp
wget https://dl.google.com/go/go1.16.15.linux-amd64.tar.gz
sudo tar -xvf go1.16.15.linux-amd64.tar.gz
sudo mv go /usr/local
```
#### 2.2 Install pip3 and ansible
```
sudo apt install python3-pip
sudo pip3 install --upgrade pip
pip3 install ansible 
```
#### 2.3 Configure environment
```
echo 'export PATH=$PATH:~/.local/bin:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go env -w GO111MODULE="on"  
go env -w GOPROXY=https://goproxy.io 
```
#### 2.4 Install necessary programs
```
sudo apt-get install sshpass
pip3 install paramiko
```

### 3. Run the protocol
Download our code in your *WorkComputer* and build it.
#### 3.1 Generate configurations
You need to change the `config_gen/config_template.yaml` first, and next you can generate configurations for all *Servers*.
```
cd config_gen
go run main.go
```
#### 3.2 Run
Now you should enter the ansible directory to take the next operations.You need to change the `ansible/hosts` first.
##### 3.2.1 Login without passwords
```
ansible -i ./hosts bit -m authorized_key -a "user=vagrant key='{{lookup('file', '/home/vagrant/.ssh/id_rsa.pub')}}' path='/home/vagrant/.ssh/authorized_keys' manage_dir=no" --ask-pass -c paramiko
```
##### 3.2.2 Configure servers via ansible
```
ansible-playbook conf-server.yaml -i hosts
```
##### 3.2.3 Run servers via ansible
```
ansible-playbook run-server.yaml -i hosts
```
##### 3.2.4 Kill servers via ansible
```
ansible-playbook clean-server.yaml -i hosts
```
   

 











