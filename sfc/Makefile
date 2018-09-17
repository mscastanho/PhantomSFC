ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

# Get Makefile dir
PDIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = sfcapp

# all source are stored in SRCS-y
VPATH = ./
SRCS-y := main.c sfc_classifier.c sfc_forwarder.c sfc_loopback.c sfc_proxy.c nsh.c common.c parser.c $(PDIR)/../ubpf/libubpf.a $(PDIR)/../bpfmap/libbpfmap.a

CFLAGS += -O3 -g -I$(PDIR)/../ubpf/inc
CFLAGS += $(WERROR_FLAGS)
LDFLAGS += -L$(PDIR)/../ubpf

include $(RTE_SDK)/mk/rte.extapp.mk