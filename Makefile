NEW_UID = 1000
NEW_GID = 1000
DVP_PROXY_CONF = ./services/proxy/app.conf
DVA_MOCK_CONF = ./services/nl-mgo-dva-mock-private/app.conf

.SILENT: help
all: help

submodules-install: ## Initialize and update all git submodules to their locked commits
	git submodule update --init --recursive

conf-setup: ## Set up the configuration files
	sh -c '[ -f "${DVP_PROXY_CONF}" ] && echo "${DVP_PROXY_CONF} already exists" || cp "${DVP_PROXY_CONF}.example" "${DVP_PROXY_CONF}"'
	sh -c '[ -f "${DVA_MOCK_CONF}" ] && echo "${DVA_MOCK_CONF} already exists" || cp "${DVA_MOCK_CONF}.example" "${DVA_MOCK_CONF}"'

setup: submodules-install conf-setup ## Set up the prerequisites
	docker compose build --build-arg="NEW_UID=${NEW_UID}" --build-arg="NEW_GID=${NEW_GID}"

run: ## Run the Docker containers
	docker compose up

help: ## Display available commands
	echo "Available make commands:"
	echo
	grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m  %-30s\033[0m %s\n", $$1, $$2}'
