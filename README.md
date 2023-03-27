# KVM Dummy VMM

Dummy KVM hypervisor that triggers three VMexits:

- PMIO write
- MMIO write
- `hlt` instruction

The goal of this code is to illustrate the most basic hypervisor/VMM implementation.

Compile and run it with:
```
make run
```

You should get the following output:
```
VMM: PMIO guest write: size=1 port=0x42 value=0xba
VMM: MMIO guest write: len=2 addr=0x5000 value=0xcafe
VMM: KVM_EXIT_HLT
```
