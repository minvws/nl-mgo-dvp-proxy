# MGO DVP PROXY

## Table of Contents

- [Definitions](#definitions)
- [Purpose](#purpose)
- [Features](#features)
- [Composition](#composition)
- [External integrations](#external-integrations)
    - [DVA](#dva)
    - [VAD](#vad)
    - [MedMij](#medmij)
    - [StatsD](#statsd)
    - [Jaeger](#jaeger)
- [Installation](#installation)
    - [Prerequisites](#prerequisites)
    - [Setup](#setup)
    - [Run the application](#run-the-application)
    - [OpenAPI](#openapi)
    - [VAD integration](#vad-integration)
    - [Grafana](#grafana)
    - [MGO Health Checker](#mgo-health-checker)
- [Contributing](#contributing)
    - [Module Boundaries (tach)](#module-boundaries-tach)
    - [Visual Studio Code](#visual-studio-code)
        - [Developing inside a Container](#developing-inside-a-container)
        - [Version Control in the Dev Container](#version-control-in-the-dev-container)
        - [Enable SSH agent forwarding](#enable-ssh-agent-forwarding)
- [License](#license)
- [Security](#security)

## Definitions

| Abbreviation | Term                                       | Description                                                                                                                                         |
| ------------ | ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| **DVA**      | DienstVerlener Aanbieder                   | Service Provider Provider. A service that provides services to a service provider (usually a healthcare provider)                                   |
| **DVP**      | DienstVerlener Persoon                     | Service Provider Person. A service (usually a PGO) that provides services to a person.                                                              |
| **FHIR**     | Fast Healthcare Interoperability Resources | A HL-7 standard describing a set of rules and specifications for securely exchanging digital healthcare data                                        |
| **MedMij**   | MedMij Foundation                          | A Dutch foundation developing and maintaining rulesets for the safe exchange of medical data between healthcare providers and applications like MGO |
| **VAD**      | Vertrouwde AuthenticatieDienst             | Trusted Authentication Service. Used to describe the interconnected services that facilitate DigiD login, BRP data enrichment and Pseudonymization  |

## Purpose

The MGO DVP Proxy, as the name suggests, acts as a proxy between a DVP Front-end
(e.g. a client-side rendered web application or mobile app) and other services
that require server-to-server mTLS connections like a DVA Resource Server or
VAD. It decouples the logic and requirements from the front-end clients,
enabling a single instance of the MGO DVP Proxy to service multiple MGO
front-end clients.

## Features

- It provides an API that enables MGO front-end clients to log in on a DVA Auth
  Server using OAuth2 (currently in use)
- It provides an API that enables MGO front-end clients to log in on the VAD via
  Open-ID Connect (work in progress)
- It provides an API that enables MGO front-end clients to request FHIR
  resources from a DVA Resource Server
- It provides detailed logging as required and specified by MedMij as
  participant of their system

## Composition

This docker setup of this project is composed of a:

- Certificates manager
- DVA Mock
- DVP Proxy

The **Certificates manager** runs before the others, creating a bunch of CA,
client and server certificates, and writing them to a named volume for re-use by
the other services. After that, it automatically stops.

These certificates are used to set up an mTLS connection between the DVP Proxy
and DVA Mock.

While the **DVA Mock** has
[its own repository](https://github.com/minvws/nl-mgo-dva-mock-private), the
increased ease of development that comes with adding it in this setup, led to
its inclusion via Git Submodules.

## External integrations

As previously mentioned, the MGO DVP Proxy integrates with several external
systems:

### DVA

The MGO DVP Proxy connects to three servers in this domain:

1. Auth Server - handles authentication and authorization
2. Token Server - provides the access token with which clients can subsequently
   authenticate
3. Resource Server - provides the actual medical data (FHIR Resources)

Which DVA is targeted, is context provided by the MGO front-end client. However,
the URI must be signed with a valid signature, which can only be obtained from
the
[MGO Localization application](https://github.com/minvws/nl-mgo-localization-private).

### VAD

The VAD provides a more comprehensive way of authentication and authorization
that aims for improving the user-friendliness for both DVP and DVA clients while
maintaining the high standards for security and privacy.

The MGO DVP Proxy integrates with the VAD using the Open-ID Connect protocol. It
offers a simple API to the MGO front-end clients to make their implementation as
easy as possible.

### MedMij

In order to comply with the logging requirement imposed by MedMij, extensive
logging is done in and around the flows described in the [DVA chapter](#dva).
These logs are then pushed to a MedMij server.

### StatsD

This project utilizes a combination of StatsD, Graphite, and Grafana to
aggregate, store, and visualize metrics. In local development, a metric client
stub is used by default for ease of use.

For more information on how to view the Grafana dashboards, please refer to the
[Grafana repository](https://github.com/minvws/nl-mgo-grafana-private).

An overview of the metrics is found [here](./services/proxy/METRICS.md).

### Jaeger

To keep track of the application's performance and behaviour, tracing
information is gathered and pushed to a local instance of Jaeger.

## Installation

Follow the guide below to run this application on your local machine.

### Prerequisites

Please install the below programs if not present:

- [Git](https://git-scm.com/)
- [Docker](https://www.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)
- [Make](https://www.gnu.org/software/make/)
- [pre-commit](https://pre-commit.com/) (recommended to validate commit messages
  — see [Commit Guidelines](#commit-guidelines) for setup and usage)

### Setup

To initialize the application, run:

```bash
make setup
```

### Run the application

To run the application, execute:

```bash
make run
```

### OpenAPI

A browsable and executable version of the DVP Proxy API is located at:
http://localhost:8001/docs

### VAD integration

A guide to help MGO front-end clients implement the VAD OIDC flow can be found
at [./docs/vad-integration.md](./docs/vad-integration.md).

### Grafana

Should you want to run an actual metric client and Grafana dashboard, check out
[this repository](https://github.com/minvws/nl-mgo-grafana-private).

Configuring the DVP Proxy to interact with it, requires the following
configuration settings:

```ini
[metric]
; Select "statsd" to inject the StatsD implementation of the MetricService in the application service container
adapter=statsd
; The statsd host should point to your local host OS, e.g. "host.docker.internal" on Linux and macOS
host=host.docker.internal
; The default StatsD port
port=8125
; Optional prefix for metric keys; useful to distinguish between different environments for instance.
; Suggested prefix below takes the value from "env" in the "default" section
prefix=proxy.${default:env}
```

### MGO Health Checker

The MGO DVP Proxy implements the generic MGO health checker package for
displaying the status of the application and its components. The health page is
found at http://localhost:8001/health.

The FastAPI `APIRouter` is bootstrapped by providing an instance of
`HealthCheckerCollection`, containing all the health check requiring components.
The `__bind_health_checkers()` at `services/proxy/app/bindings.py` instantiates
this collection. Should additional components, or health check support for
existing components, be added in the future, this is where they can be
registered.

For more details, check out the
[package documentation](https://github.com/minvws/nl-mgo-package-healthchecker-private).

## Contributing

### Commit Guidelines

This project follows the
**[Conventional Commits](https://www.conventionalcommits.org/)** specification
for commit messages. To help enforce this, a
**[pre-commit](https://pre-commit.com/)** configuration is included that can
validate your commit messages.

To enable the commit message validation hook, run:

```bash
pre-commit install --install-hooks
```

**Note:** Pre-commit is already preconfigured in the devcontainer.

### Module Boundaries (tach)

The proxy service uses [tach](https://github.com/gauge-sh/tach) to enforce explicit
module dependency boundaries. The configuration lives in
[`services/proxy/tach.toml`](./services/proxy/tach.toml).

#### Checking boundaries

From the `services/proxy` directory, run:

```bash
uv run tach check
```

This will report any import that violates the declared `depends_on` lists. The
check is also run as part of the CI pipeline, so it must pass before merging.

#### Visualising the dependency graph

```bash
uv run tach show
```

#### Updating `tach.toml` after changing dependencies

When you add a new import from one module to another, tach will fail with a
violation error. To resolve it:

1. Open `services/proxy/tach.toml`.
2. Find the `[[modules]]` entry for the module that contains the new import.
3. Add the imported module to its `depends_on` list.
4. Re-run `uv run tach check` to confirm the violation is resolved.

When you add an entirely **new** module (i.e. a new top-level package under
`app/`), register it by appending a new entry:

```toml
[[modules]]
path = "app.<new_module>"
depends_on = ["app.<dependency>"]  # list every module it may import from
```

Keep `depends_on` minimal — only list modules that are actually imported. Avoid
creating circular dependencies; tach will report these as errors too.

Alternatively, run:

```bash
uv run tach sync
```

This automatically updates all `depends_on` lists in `tach.toml` to match the
current state of imports in the codebase. It is a convenient shortcut after
larger refactors, but review the diff afterwards to ensure no unintended
dependencies were introduced.

### Visual Studio Code

This repository contains shared configuration files, which automates the setup
of your workspace.

The configuration files reside in the `./.vscode` folder.

VS Code will detect this folder automatically and will recommend that you
install several extensions. It is advised to install all of them, as it will be
a good starting point for this project.

#### Developing inside a Container

Once you have installed all the extensions, VS Code may detect a Dev Container
configuration file and, hence, ask you to reopen the folder to develop in a
container.

This feature is enabled by the Dev Container extension. It allows you to use a
container as a full-featured development environment, providing a better
development experience, including auto-completion, code navigation, and
debugging.

#### Version Control in the Dev Container

To be able to use VS Code Source Control while in a Dev Container, both GIT and
GnuPG are installed. Dev Containers have out-of-the-box support for this;
however, it does require a running `ssh-agent` daemon with the appropriate
identity added to it when booting the Dev Container.

You can access your GPG key from within the Dev Container to sign commits, and
usually VS Code will copy your local `~/.ssh/known_hosts` to the Dev Container.
The latter is sometimes omitted for unknown reasons, in which case an error
might be raised upon storing GitHub's fingerprint when first connecting. To fix
it, simply manually create an empty `known_hosts` file inside the container.

```
touch ~/.ssh/known_hosts
```

Please refer to the VS Code documentation for more OS-specific explanations.

#### Enable SSH agent forwarding

Due to one or more dependencies on private Git repositories, the Docker
environment requires a SSH key for authentication. To enable this scenario,
follow the steps below to automatically forward your local SSH agent if one is
running.

```sh
# Example:
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519   # or your key path
ssh-add -l                  # verify key is loaded
```

Note that on macOS, the above `eval` command is not needed. Just make sure to
add the key to your path, every time the host machine is restarted.

Further information can be found in the
[VS Code docs](https://code.visualstudio.com/remote/advancedcontainers/sharing-git-credentials).
