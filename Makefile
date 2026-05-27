#
# YSFSniffer - top-level Makefile
#
# Compilation runs inside the Docker build container so nothing leaks
# onto the host. The resulting binary runs natively next to MMDVMHost /
# YSFGateway on the user's target hardware (typically a Raspberry Pi
# running Pi-Star or WPSD).
#
# Host-side commands:
#   make image              -- build the toolchain image once
#   make docker-build       -- native build (build-host arch)
#   make docker-build-arm64 -- arm64  (Pi 3/4/5 64-bit, WPSD)
#   make docker-build-armhf -- armhf  (32-bit Pi, Pi-Star)
#   make docker-clean
#   make docker-shell       -- shell inside the build container
#
# Each arch keeps its objects in its own obj/<arch>/ dir, so all three
# binaries can coexist in the project root.
#

DOCKER_IMAGE ?= ysfsniffer-build:latest
DOCKER       ?= docker
DOCKERFILE   ?= docker/Dockerfile.build

CXX      ?= c++
CXXFLAGS  = -g -O2 -Wall -Wextra -Wno-unused-parameter -std=c++17 -MMD -MD -pthread
LDFLAGS   = -g
LIBS      = -lpthread

SRCDIR    = src
OBJDIR   ?= obj/native
TARGET   ?= YSFSniffer

# Filter out OneDrive / editor turds. GNU make's filter-out only honours a
# single % per pattern, so use a foreach + findstring chain that catches
# 'safeBackup' or '~conflict' anywhere in the filename.
ALL_SRCS  = $(wildcard $(SRCDIR)/*.cpp)
SRCS      = $(foreach f,$(ALL_SRCS),$(if $(or $(findstring safeBackup,$f),$(findstring ~conflict,$f)),,$f))
OBJS      = $(patsubst $(SRCDIR)/%.cpp,$(OBJDIR)/%.o,$(SRCS))
DEPS      = $(OBJS:.o=.d)

# ---- in-container build targets ----

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(OBJS) $(LDFLAGS) $(LIBS) -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(OBJDIR):
	@mkdir -p $(OBJDIR)

-include $(DEPS)

$(OBJDIR)/YSFSniffer.o: $(SRCDIR)/GitVersion.h FORCE

.PHONY: $(SRCDIR)/GitVersion.h FORCE

FORCE:

$(SRCDIR)/GitVersion.h:
ifneq ("$(wildcard .git/index)","")
	@echo 'const char *gitversion = "$(shell git rev-parse HEAD 2>/dev/null)";' > $@
else
	@echo 'const char *gitversion = "0000000000000000000000000000000000000000";' > $@
endif

clean:
	$(RM) -r obj YSFSniffer YSFSniffer-arm64 YSFSniffer-armhf $(SRCDIR)/GitVersion.h

install:
	install -m 755 $(TARGET) /usr/local/bin/

# ---- host-side wrappers (run inside the Docker build container) ----

DOCKER_RUN = $(DOCKER) run --rm \
	-v "$(CURDIR)":/work -w /work \
	-u $$(id -u):$$(id -g) \
	$(DOCKER_IMAGE)

image:
	$(DOCKER) build -f $(DOCKERFILE) -t $(DOCKER_IMAGE) .

docker-build: image
	$(DOCKER_RUN) make all OBJDIR=obj/native TARGET=YSFSniffer

docker-build-arm64: image
	$(DOCKER_RUN) make all \
	    OBJDIR=obj/arm64 \
	    CXX=aarch64-linux-gnu-g++ \
	    TARGET=YSFSniffer-arm64

docker-build-armhf: image
	$(DOCKER_RUN) make all \
	    OBJDIR=obj/armhf \
	    CXX=arm-linux-gnueabihf-g++ \
	    TARGET=YSFSniffer-armhf

docker-clean: image
	$(DOCKER_RUN) make clean

docker-shell: image
	$(DOCKER) run --rm -it \
	    -v "$(CURDIR)":/work -w /work \
	    -u $$(id -u):$$(id -g) \
	    $(DOCKER_IMAGE) /bin/bash

.PHONY: all clean install image docker-build docker-build-arm64 docker-build-armhf docker-clean docker-shell
