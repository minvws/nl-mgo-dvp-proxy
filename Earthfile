VERSION 0.8
FROM debian:12
WORKDIR /src

docker:
    ARG --required python_version
    ENV PATH=/root/.local/bin:$PATH

    RUN apt update && \
        apt install -y curl jq python${python_version} pipx && \
        apt clean && \
        pipx install poetry==1.8.*

release-package:
    FROM +docker

    WORKDIR /var/www

    ARG --required python_version
    ARG --required service
    ARG --required release_version
    ARG --required git_ref

    COPY services/$service ./

    # update version.json
    RUN --no-cache \
        jq --arg release_version "$release_version" --arg git_ref "$git_ref" \
            '.release_version = $release_version | .git_ref = $git_ref' version.json > version_new.json && \
        mv version_new.json version.json

    # archive source
    RUN --no-cache \
        touch source.tar.gz && \
        tar --exclude=source.tar.gz \
            --exclude=poetry.lock \
            --exclude=pyproject.toml \
            --exclude='.[^/]*' \
            --exclude=*.md \
            --exclude=app.conf \
            --exclude=app.conf.test \
            --exclude=Makefile \
            --exclude=Dockerfile \
            --exclude=sonar-project.properties \
            --exclude=tests \
            --exclude=certs \
            --exclude=secrets \
            --exclude=docker \
            --exclude=./docs \
            -zcvf source.tar.gz ./

    SAVE ARTIFACT source.tar.gz AS LOCAL ./dvp-${service}_${release_version}.tar.gz
