all: ubpf-vm bpf-maps phantomsfc

bpf-maps:
	cd bpfmap && $(MAKE)

ubpf-vm: bpf-maps
	cd ubpf && $(MAKE)

phantomsfc: ubpf-vm
	cd sfc && $(MAKE)

clean:
	cd ubpf && $(MAKE) clean
	cd bpfmap && $(MAKE) clean
	cd sfc && $(MAKE) clean && rm -rd build/