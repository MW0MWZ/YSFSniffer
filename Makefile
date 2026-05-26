#
# YSFSniffer - top-level Makefile
#
# All compilation and testing is expected to happen inside the Docker
# build container. The default target ('all') is the in-container build.
# From the host, use 'make image' to build the toolchain image and
# 'make docker-build' / 'make docker-clean' to run targets in it.
#

DOCKER_IMAGE ?= ysfsniffer-build:latest
DOCKER       ?= docker
DOCKERFILE   ?= docker/Dockerfile.build

CXX      ?= c++
CXXFLAGS  = -g -O2 -Wall -Wextra -Wno-unused-parameter -std=c++17 -MMD -MD -pthread -Isrc
LDFLAGS   = -g
LIBS      = -lpthread

SRCDIR    = src
SRCS      = $(wildcard $(SRCDIR)/*.cpp)
OBJS      = $(SRCS:.cpp=.o)
DEPS      = $(SRCS:.cpp=.d)

TARGET    = YSFSniffer

# ---- in-container targets (these are what the Dockerfile/CI actually run) ----

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) $(LDFLAGS) $(LIBS) -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

-include $(DEPS)

clean:
	$(RM) $(TARGET) $(OBJS) $(DEPS) $(SRCDIR)/GitVersion.h

install:
	install -m 755 $(TARGET) /usr/local/bin/

# ---- host-side helpers: run a target inside the Docker build container ----

image:
	$(DOCKER) build -f $(DOCKERFILE) -t $(DOCKER_IMAGE) .

docker-build: image
	$(DOCKER) run --rm \
	    -v "$(CURDIR)":/work -w /work \
	    -u $$(id -u):$$(id -g) \
	    $(DOCKER_IMAGE) make all

docker-clean: image
	$(DOCKER) run --rm \
	    -v "$(CURDIR)":/work -w /work \
	    -u $$(id -u):$$(id -g) \
	    $(DOCKER_IMAGE) make clean

docker-shell: image
	$(DOCKER) run --rm -it \
	    -v "$(CURDIR)":/work -w /work \
	    -u $$(id -u):$$(id -g) \
	    $(DOCKER_IMAGE) /bin/bash

.PHONY: all clean install image docker-build docker-clean docker-shell
