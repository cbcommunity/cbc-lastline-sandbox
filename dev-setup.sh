# This script is to set up the Theia development environment. This script should be run from the Theia terminal.

apt-get update
apt-get upgrade -y

apt-get install -y tmux htop iftop ncdu vim

pip3 install --upgrade pip
pip3 install pylint
pip3 install -r requirements.txt