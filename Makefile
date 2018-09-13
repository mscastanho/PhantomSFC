all: ubpf-vm phantomsfc

ubpf-vm:
	cd ubpf && $(MAKE)

phantomsfc: ubpf-vm
	cd sfc && $(MAKE)

clean:
	cd ubpf && $(MAKE) clean
	cd sfc && $(MAKE) clean && rm -rd build/
