#!/bin/bash

# working dir is the directory the script is located in
WD="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$WD"
WEB_ENV="kibana elasticsearch"

CONF="-p pcapscan -f docker-compose.yml "

function exitIfErr() {
	if [ $1 -ne 0 ]; then
		echo
		echo "$2"
		echo "Abort execution."
		echo
		exit 1
	fi
}
which docker &> /dev/null
exitIfErr $? "Docker is noch installed on this system. Please install docker.io package or dockerCE."
function installComposerIfNotAvailable() {
        # is docker installed?
        which docker &> /dev/null
        exitIfErr $? "Can not find docker executable."
        # check if docker composer is installed
        which docker-composer &> /dev/null
        if [ $? -eq 0 ]; then
                echo "Docker composer is available from PATH: $( which docker-composer )."
                return
        elif [ -f "/usr/local/bin/docker-compose" ]; then
                echo "Docker composer is available in /usr/local/bin/docker-compose"
                return
        fi
        # download it and put it into /usr/local/
        echo sudo curl -L "https://github.com/docker/compose/releases/download/1.18.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        sudo curl -L "https://github.com/docker/compose/releases/download/1.18.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        exitIfErr $? "Failed to download and install docker-compose."
        # make executeable
        sudo chmod +x /usr/local/bin/docker-compose
        echo "Successfully downloaded and installed docker-composer from source."
}
function getAllComposeServiceNames() {
        docker-compose $CONF config --services | head -c -1
}
function getAllComposeServiceNamesOneliner() {
        getAllComposeServiceNames | tr '\n' '|'
}
# make sure docker-composer is available
installComposerIfNotAvailable

function usage() {
        SERVICES="[$(getAllComposeServiceNamesOneliner)]"
	echo "Usage:"
	echo "$0  [start|stop|restart|list|shell|log|clear] "
	echo
	echo "$0 shell $SERVICES"
	echo "$0 log $SERVICES"
	exit 1
}


CONF="-f docker-compose-dev.yml -p pcapscan"

if [ "$1" == "start" ]; then
	docker-compose $CONF up -d
	echo
	echo "Endpoints:"
	echo "elasticsearch:	http://localhost:9200"
	echo "kibana:       	http://localhost:5601"
	echo
elif [ "$1" == "stop" ]; then
	docker-compose $CONF down
elif [ "$1" == "list" ]; then
	docker-compose $CONF ps
elif [ "$1" == "restart" ]; then
	./$0 stop
	./$0 start
elif [ "$1" == "log" ]; then
	docker-compose $CONF logs -f "$2"
elif [ "$1" == "shell" ]; then
	docker compose $CONF exec "$2" bash
elif [ "$1" == "clear" ]; then
	echo
	echo "Clear elasticsearch index?"
	echo
	read -r -p "Are you sure? [y/N] " response
	echo
	if [[ ! $response =~ ^(yes|y)$ ]]; then
    	echo "Got $response from user. Abort processing."
  	exit 1
	else
    	echo "Ok, I'll do it."
	fi
	docker volume rm pcapscan_stats-elasticsearch
else
	echo "Unknown parameter $1. "
	echo
	usage
fi
