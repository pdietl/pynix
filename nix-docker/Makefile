MAKEFILE_PATH     := $(abspath $(lastword $(MAKEFILE_LIST)))
MAKEFILE_DIR      := $(dir $(MAKEFILE_PATH))
MAKEFILE_DIR      := $(MAKEFILE_DIR:/=)
DOCKER_IMAGE_NAME := ubuntu-with-nix:1

DOCKER_CMD := \
    docker run -ti --rm \
        -u $(shell id -u):$(shell id -g) \
        -v $(HOME)/.cache:$(HOME)/.cache \
        -v /etc/group:/etc/group:ro \
        -v /etc/passwd:/etc/passwd:ro \
        -v '$(CURDIR):$(CURDIR)' \
        -w '$(CURDIR)' \
        $(DOCKER_IMAGE_NAME)

all: docker-build

.PHONY: docker-build
docker-build: $(MAKEFILE_DIR)/Dockerfile
	cd $(<D) && docker build . -t $(DOCKER_IMAGE_NAME)

shell:
	$(DOCKER_CMD) /bin/bash
