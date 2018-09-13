all: ubpf-vm bpf-maps phantomsfc

ubpf-vm:
	cd ubpf && $(MAKE)

bpf-maps:
	cd bpfmap && $(MAKE)

phantomsfc: ubpf-vm
	cd sfc && $(MAKE)

clean:
	cd ubpf && $(MAKE) clean
	cd bpfmap && $(MAKE) clean
	cd sfc && $(MAKE) clean && rm -rd build/