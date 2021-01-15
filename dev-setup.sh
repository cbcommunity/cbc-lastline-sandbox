# This script is to set up the Theia development environment. This script should be run from the Theia terminal.

# Function for yes/no questions
function yes_or_no {
    while true; do
        read -p "$* [y/n]: " yn
        case $yn in
            [Yy]*) return 0  ;;  
            [Nn]*) echo "Aborted" ; return  1 ;;
        esac
    done
}

function update_locale {
    apt-get install -y locales
    dpkg-reconfigure locales
}

# Install locales
apt-get update

# Update locale?
if [[ $LANG -eq "" ]]
then
    printf "\n\n\nCurrent locale is not set. "
else
    printf "\n\n\nLocale is $LANG. "
fi
yes_or_no "Do you want to change it?" && update_locale

# Install the basics
apt-get upgrade -y
apt-get install -y tmux htop iftop ncdu vim

# Install the PIP requirements
pip3 install --upgrade pip
pip3 install pylint
pip3 install -r requirements.txt

# Create the .theia folder if it doesn't exist
if [[ ! -d ".theia" ]]
then
    mkdir .theia
fi
# Create the launch.json file for enabling the debug functions
if [[ ! -f ".theia/launch.json" ]]
then
    echo -e "{\n  \"version\": \"0.2.0\",\n  \"configurations\": [{\n    \"name\": \"CBC / Lastline Sandbox\",\n    \"type\": \"python\",\n    \"request\": \"launch\",\n    \"program\": \"\${file}\",\n    \"console\": \"integratedTerminal\"\n  }]\n}" > .theia/launch.json
fi
