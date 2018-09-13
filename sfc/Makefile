ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = sfcapp

# all source are stored in SRCS-y
SRCS-y := nsh.c common.c sfc_proxy.c sfc_classifier.c sfc_forwarder.c sfc_loopback.c parser.c main.c  

CFLAGS += -O3 -g
CFLAGS += $(WERROR_FLAGS)

include $(RTE_SDK)/mk/rte.extapp.mk