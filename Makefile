all: ubpf-vm bpf-maps phantomsfc

bpf-maps:
	cd bpfmap && $(MAKE)

proto:
	cd protocol && $(MAKE)

ubpf-vm: bpf-maps
	cd ubpf && $(MAKE)

agent-src: proto bpf-maps ubpf-vm
	cd agent && $(MAKE)

phantomsfc: ubpf-vm
	cd sfc && $(MAKE)

clean:
	cd bpfmap && $(MAKE) clean
	cd protocol && $(MAKE) clean
	cd ubpf && $(MAKE) clean
	cd agent && $(MAKE) clean
	cd sfc && $(MAKE) clean && rm -rd build/