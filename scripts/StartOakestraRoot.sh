#!/bin/bash
echo 🌳 Running Oakestra Root \n

#Oakestra branch?
if [ -z "$OAKESTRA_BRANCH" ]; then
    OAKESTRA_BRANCH='main'
fi

# Check if docker and docker compose installed 
if [ ! -x "$(command -v docker)" ]; then
  echo "Docker is not installed. Please refer to the official Docker documentation for installation instructions specific to your OS: https://docs.docker.com/engine/install/"
  exit 1
fi
echo Checking docker compose version
sudo docker compose version
if [ $? -ne 0 ]; then
    current_os=$(uname)
    if [ "$current_os" = "Darwin" ]; then
        echo "Docker compose v2 or higher is required. Please refer to the official Docker documentation for installation instructions specific to your OS: https://docs.docker.com/compose/migrate/"
        exit 1
    else
        echo "Installing Docker Compose plugin"
        if [ ! -x "$(command -v apt-get)" ]; then
            sudo apt-get update
            sudo apt-get install docker-compose-plugin
        fi
        if [ ! -x "$(command -v yum)" ]; then
            sudo yum update
            sudo yum install docker-compose-plugin
        fi
    fi
fi

#Default configuration?
if [ -z "$SYSTEM_MANAGER_URL" ]; then
    echo 🔧 Using default configuration

    current_os=$(uname)
    
    # get IP address of this machine
    if [ "$current_os" = "Darwin" ]; then
        export SYSTEM_MANAGER_URL=$(ipconfig getifaddr en0)
    else
        export SYSTEM_MANAGER_URL=$(ip route get 1.1.1.1 | grep -oP 'src \K\S+')
    fi
    if [ $? -ne 0 ]; then
        echo "Error: Failed to retrieve interface IP."
        exit 1
    fi
    echo Default node IP: $SYSTEM_MANAGER_URL
fi

mkdir -p ~/oakestra/root_orchestrator 2> /dev/null
cd ~/oakestra/root_orchestrator 2> /dev/null

curl -sfL https://raw.githubusercontent.com/oakestra/oakestra/$OAKESTRA_BRANCH/scripts/utils/downloadConfigFiles.sh > downloadConfigFiles.sh
curl -sfL https://raw.githubusercontent.com/oakestra/oakestra/$OAKESTRA_BRANCH/root_orchestrator/docker-compose.yml > root-orchestrator.yml
curl -sfL https://raw.githubusercontent.com/oakestra/oakestra/$OAKESTRA_BRANCH/root_orchestrator/override-images-only.yml > override-root-images-only.yml

chmod +x downloadConfigFiles.sh
./downloadConfigFiles.sh run-a-cluster $OAKESTRA_BRANCH

#If additional override files provided, download them
OAK_OVERRIDES=''

if [ ! -z "$OVERRIDE_FILES" ]; then
    IFS=, 
    # Split the string into an array using read -r -a
    for element in $OVERRIDE_FILES
    do
        echo "Download override: $element"
        wget -c https://raw.githubusercontent.com/oakestra/oakestra/$OAKESTRA_BRANCH/root_orchestrator/$element 2> /dev/null
        OAK_OVERRIDES="${OAK_OVERRIDES}-f ${element} " 
    done
    IFS= 
    if [ $? -ne 0 ]; then
        echo "Error: Failed to retrieve the override."
        exit 1
    fi
fi

if sudo docker ps -a | grep oakestra/root >/dev/null 2>&1; then
  echo 🚨 Oakestra root containers are already running. Please stop them before starting the root orchestrator.
  echo 🪫 You can turn off the current root using: \$ docker compose -f ~/oakestra/root_orchestrator/root-orchestrator.yml down
  exit 1
fi

command_exec="sudo -E docker compose -f root-orchestrator.yml -f override-root-images-only.yml ${OAK_OVERRIDES}up -d"
echo executing "$command_exec"

eval "$command_exec"

echo 
echo 🌳 Oakestra Root Orchestrator is now starting up...
echo
echo 🖥️ Oakestra dashboard available at http://$SYSTEM_MANAGER_URL
echo 📊 Grafana dashboard available at http://$SYSTEM_MANAGER_URL:3000
echo 📈 You can access the APIs at http://$SYSTEM_MANAGER_URL:10000/api/docs
echo 🪫 You can turn off the cluster using: \$ docker compose -f ~/oakestra/root_orchestrator/root-orchestrator.yml down
