#!/bin/bash

set -e
set -o pipefail

sudo apt-get install \
		apt-transport-https\
		ca-certificates\
		curl\
		gnupg-agent\
		software-properties-common

# Add docker GPG signature 
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

# Add docker repo
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"

# Install docker services
sudo apt update
sudo apt-get install docker-ce docker-ce-cli containerd.io

# Install docker-compose.
# We install from release and not from apt because apt is not updated :(
sudo curl -L "https://github.com/docker/compose/releases/download/1.25.4/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Allow python to send packets as non-sudo
sudo setcap cap_net_admin,cap_net_raw+eip /usr/bin/python3.7

# Pull and build image
docker image pull ubuntu:16.04
docker build . --network host --tag="pyroute"

# MUST Logout after this
sudo adduser $USER docker

INVERTED_BOLD_RED="\033[7;1;31m"
DEFAULT_GREY="\033[0;0;37m"

# Print in bold and red so the user will notice
echo -e $INVERTED_BOLD_RED "IN ORDER TO COMLETE THE INSTALLATION, PLAESE LOG OUT" $DEFAULT_GREY
read -p "To logout, enter Y: " CHOICE

if [[ $CHOICE == "Y" ]] || [[ $CHOICE == "y" ]]; then
	gnome-session-quit --logout
fi
