Things to do:

- [ ] Add ubpf code from IOVisor project
- [ ] Create BPF map structures (get from BPFabric?)
- [ ] Create a second handler func on classifier
- [ ] Create command-line parameters 
    - [ ] Param to enable eBPF or 5-tuple classification
    - [ ] Param to specify path to ELF file in case of eBPF
- [ ] Change classifier init func to enable choosing handler func
- [ ] Add eBPF rule parser function to parser.c
- [ ] Write a different classifier