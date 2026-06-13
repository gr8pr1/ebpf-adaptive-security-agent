.PHONY: all build clean bpf install uninstall test

# Feature flags — all enabled by default
# Disable a feature: make bpf MONITOR_EXEC=0
MONITOR_EXEC    ?= 1
MONITOR_SUDO    ?= 1
MONITOR_PASSWD  ?= 0
MONITOR_CONNECT ?= 1
MONITOR_PTRACE  ?= 1
MONITOR_OPENAT  ?= 1
MONITOR_SETUID  ?= 1
MONITOR_FORK    ?= 1
MONITOR_EXIT    ?= 1
MONITOR_BIND    ?= 1
MONITOR_DNS     ?= 1
MONITOR_CAPSET  ?= 1
MONITOR_WRITE   ?= 1
MONITOR_OPEN    ?= 1
MONITOR_OPENAT2 ?= 1
MONITOR_OOM     ?= 1

BPF_FLAGS :=
ifeq ($(MONITOR_EXEC),1)
  BPF_FLAGS += -DMONITOR_EXEC
endif
ifeq ($(MONITOR_SUDO),1)
  BPF_FLAGS += -DMONITOR_SUDO
endif
ifeq ($(MONITOR_PASSWD),1)
  BPF_FLAGS += -DMONITOR_PASSWD
endif
ifeq ($(MONITOR_CONNECT),1)
  BPF_FLAGS += -DMONITOR_CONNECT
endif
ifeq ($(MONITOR_PTRACE),1)
  BPF_FLAGS += -DMONITOR_PTRACE
endif
ifeq ($(MONITOR_OPENAT),1)
  BPF_FLAGS += -DMONITOR_OPENAT
endif
ifeq ($(MONITOR_SETUID),1)
  BPF_FLAGS += -DMONITOR_SETUID
endif
ifeq ($(MONITOR_FORK),1)
  BPF_FLAGS += -DMONITOR_FORK
endif
ifeq ($(MONITOR_EXIT),1)
  BPF_FLAGS += -DMONITOR_EXIT
endif
ifeq ($(MONITOR_BIND),1)
  BPF_FLAGS += -DMONITOR_BIND
endif
ifeq ($(MONITOR_DNS),1)
  BPF_FLAGS += -DMONITOR_DNS
endif
ifeq ($(MONITOR_CAPSET),1)
  BPF_FLAGS += -DMONITOR_CAPSET
endif
ifeq ($(MONITOR_WRITE),1)
  BPF_FLAGS += -DMONITOR_WRITE
endif
ifeq ($(MONITOR_OPEN),1)
  BPF_FLAGS += -DMONITOR_OPEN
endif
ifeq ($(MONITOR_OPENAT2),1)
  BPF_FLAGS += -DMONITOR_OPENAT2
endif
ifeq ($(MONITOR_OOM),1)
  BPF_FLAGS += -DMONITOR_OOM
endif

all: bpf build

CLANG ?= $(shell which clang 2>/dev/null || echo /usr/bin/clang)
BPF_INCLUDE ?= $(shell if [ -d /usr/include/bpf ]; then echo "-I/usr/include"; elif [ -d /usr/local/include/bpf ]; then echo "-I/usr/local/include"; fi)

bpf:
	cd bpf && $(CLANG) -O2 -g -target bpf $(BPF_INCLUDE) $(BPF_FLAGS) -c exec.bpf.c -o exec.bpf.o
	mkdir -p cmd/agent/bpf
	cp bpf/exec.bpf.o cmd/agent/bpf/

build:
	go build -o ebpf-agent ./cmd/agent

test:
	go test ./...

clean:
	rm -f ebpf-agent
	rm -f bpf/exec.bpf.o
	rm -f cmd/agent/bpf/exec.bpf.o

install: all
	sudo mkdir -p /etc/ebpf-agent /var/lib/ebpf-agent
	sudo cp ebpf-agent /usr/local/bin/
	sudo cp config.yaml /etc/ebpf-agent/config.yaml
	sudo cp ebpf-agent.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable ebpf-agent
	sudo systemctl start ebpf-agent
	@echo "eBPF agent installed and started"

uninstall:
	sudo systemctl stop ebpf-agent || true
	sudo systemctl disable ebpf-agent || true
	sudo rm -f /etc/systemd/system/ebpf-agent.service
	sudo rm -f /usr/local/bin/ebpf-agent
	sudo rm -rf /etc/ebpf-agent /var/lib/ebpf-agent
	sudo systemctl daemon-reload
	@echo "eBPF agent uninstalled"
