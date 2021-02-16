###
# This script is to set up the Theia development environment. This script should be run from the Theia terminal.
###

# Update and install the basics
apt-get update
apt-get upgrade -y
apt-get install -y tmux htop iftop ncdu vim

# Install python requirements
pip3 install --upgrade pip
pip3 install pylint
pip3 install -r requirements.txt

# Create the debug config file for Theia
echo -e "{\n  \"version\": \"0.2.0\",\n  \"configurations\": [{\n    \"name\": \"CBC / Lastline Sandbox\",\n    \"type\": \"python\",\n    \"request\": \"launch\",\n    \"program\": \"\${file}\",\n    \"console\": \"integratedTerminal\"\n  }]\n}" > .theia/launch.json

echo -e "\n\nConfiguring Git. You will need to enter your name and email.\n"

# Configure Git
git config --local user.name
git config --local user.email

echo -e "\n\nFreezing the config file to prevent commiting creds\n"

# Freeze the config file so we don't commit creds accidentally
git update-index --skip-worktree app/config.conf