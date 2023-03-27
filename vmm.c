// KVM API reference: https://www.kernel.org/doc/html/latest/virt/kvm/api.html
// Code initially based on example from https://lwn.net/Articles/658511/

#include <err.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <sys/eventfd.h>
#include <unistd.h>

typedef struct {
    int kvmfd;
    int vmfd;
    int vcpufd;
    struct kvm_run *run;
    int vcpu_mmap_size;
    uint8_t *guest_mem;
    u_int guest_mem_size;
} vm_t;

static void handle_pmio(vm_t *vm) {
    struct kvm_run *run = vm->run;
    
    // Guest wrote to an I/O port
    if (run->io.direction == KVM_EXIT_IO_OUT) {
        uint8_t *addr = (uint8_t *)run + run->io.data_offset;
        uint32_t value;
        switch (run->io.size) {
            case 1:  // Retrieve the 8-bit value written by the guest
                value = *(uint8_t *)addr;
                break;
            case 2:  // Retrieve the 16-bit value written by the guest
                value = *(uint16_t *)addr;
                break;
            case 4:  // Retrieve the 32-bit value written by the guest
                value = *(uint32_t *)addr;
                break;
            default:
                fprintf(stderr, "VMM: Unsupported size in KVM_EXIT_IO\n");
                value = 0;
        }
        printf("VMM: PMIO guest write: size=%d port=0x%x value=0x%x\n", run->io.size, run->io.port, value);
    }
    // Guest read from an I/O port
    else if (run->io.direction == KVM_EXIT_IO_IN) {
        uint32_t injected_val;
        uint8_t *addr = (uint8_t *)run + run->io.data_offset;
        switch (run->io.size) {
            case 1: { // Guest is reading 8 bits from the port
                injected_val = 0x12;  // dummy 8-bit value injected into the guest
                *addr = injected_val;
                } break;
            case 2: { // Guest is reading 16 bits from the port
                injected_val = 0x1234;  // dummy 16-bit value injected into the guest
                *((uint16_t *)addr) = injected_val;
                } break;
            case 4: { // Guest is reading 32 bits from the port
                injected_val = 0x12345678;  // dummy 32-bit value injected into the guest
                *((uint32_t *)addr) = injected_val;
                } break;
            default:
                fprintf(stderr, "VMM: Unsupported size in KVM_EXIT_IO\n");
        }
        printf("VMM: PMIO guest read: size=%d port=0x%x [value injected by VMM=0x%x]\n", run->io.size, run->io.port, injected_val);
    }
    else fprintf(stderr, "VMM: unhandled KVM_EXIT_IO\n");
}

static void handle_mmio(vm_t *vm) {
    struct kvm_run *run = vm->run;

    // Guest wrote to a non-mapped memory address (considered as "MMIO")
    if (run->mmio.is_write) {
        int bytes_written = run->mmio.len;
        uint32_t value;
        switch (bytes_written) {
            case 1:  // Retrieve the 8-bit value written by the guest
                value = *((uint8_t *)run->mmio.data);
                break;
            case 2:  // Retrieve the 16-bit value written by the guest
                value = *((uint16_t *)run->mmio.data);
                break;
            case 4:  // Retrieve the 32-bit value written by the guest
                value = *((uint32_t *)run->mmio.data);
                break;
            default:
                fprintf(stderr, "VMM: Unsupported size in KVM_EXIT_MMIO\n");
                value = 0;
        }
        printf("VMM: MMIO guest write: len=%d addr=0x%llx value=0x%x\n", bytes_written, run->mmio.phys_addr, value);
    }
    // Guest read a non-mapped memory address (considered as "MMIO")
    else {
        int bytes_read = run->mmio.len;
        uint32_t injected_val;
        switch (bytes_read) {
            case 1: { // Guest is reading 8 bits
                uint8_t *addr = (uint8_t *)run->mmio.data;
                injected_val = 0x12;  // dummy 8-bit value injected into the guest
                *addr = injected_val;
                } break;
            case 2: { // Guest is reading 16 bits
                uint16_t *addr = (uint16_t *)run->mmio.data;
                injected_val = 0x1234;  // dummy 16-bit value injected into the guest
                *addr = injected_val;
                } break;
            case 4: { // Guest is reading 32 bits
                uint32_t *addr = (uint32_t *)run->mmio.data;
                injected_val = 0x12345678;  // dummy 32-bit value injected into the guest
                *addr = injected_val;
                } break;
            default:
                fprintf(stderr, "VMM: Unsupported size in KVM_EXIT_MMIO\n");
        }
        fprintf(stderr, "VMM: MMIO guest read: len=%d addr=0x%llx injected=0x%x\n", bytes_read, run->mmio.phys_addr, injected_val);
    }
}

int main() {
    // Online dissassembler: https://disasm.pro/
    
    // ; Write 8-bit value 0xBA to 16-bit port 0x42 (PMIO)
    // mov     dx,0x42
    // mov     al,0xBA
    // out     dx,al
    //
    // ; Write 16-bit value 0xCAFE to address 0x5000 (MMIO)
    // mov     bx,0x5000
    // mov     ax,0xCAFE
    // mov     [bx],ax
    //
    // ; Stop CPU
    // hlt

    uint8_t guest_code[] = "\xBA\x42\x00\xB0\xBA\xEE\xBB\x00\x50\xB8\xFE\xCA\x89\x07\xF4";

    // Allocate custom structure for our VM
    vm_t *vm = malloc(sizeof(vm_t));
    if (!vm) err(1, NULL);
    memset(vm, 0, sizeof(vm_t));

    // Obtain KVM file descriptor
    char kvm_dev[] = "/dev/kvm";
    vm->kvmfd = open(kvm_dev, O_RDWR | O_CLOEXEC);
    if (vm->kvmfd < 0) err(1, "%s", kvm_dev);

    // Make sure we have the right version of the API
    int version = ioctl(vm->kvmfd, KVM_GET_API_VERSION, NULL);
    if (version < 0) err(1, "VMM: KVM_GET_API_VERSION");
    if (version != KVM_API_VERSION) err(1, "VMM: KVM_GET_API_VERSION %d, expected %d", version, KVM_API_VERSION);

    // Obtain VM file descriptor
    vm->vmfd = ioctl(vm->kvmfd, KVM_CREATE_VM, 0);
    if (vm->vmfd < 0) err(1, "VMM: KVM_CREATE_VM");

    // mmap syscall:
    // 1st arg: specifies at which virtual address to start the mapping; if NULL, kernel chooses the address
    // 2nd arg: size to allocate (in bytes)
    // 3rd arg: access type (read, write, etc.)
    // 4th arg: flags; MAP_ANONYMOUS = mapping not backed by any file and contents initialized to zero
    // 5th arg: file descriptor if mmap a file (otherwise, set to -1)
    // 6th arg: offset when mmap a file

    // Allocate 4KB of RAM for the guest
    vm->guest_mem_size = 4096;
    vm->guest_mem = mmap(NULL, vm->guest_mem_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!vm->guest_mem) err(1, "VMM: allocating guest memory");

    // Map guest_mem to physical address 0 in the guest address space
    // IMPORTANT:
    // - memory_size MUST be a multiple of page size (4KB)
    // - guest_phys_addr must be on a page boundary (4KB)
    struct kvm_userspace_memory_region mem_region = {
        .slot = 0,
        .guest_phys_addr = 0,
        .memory_size = vm->guest_mem_size,
        .userspace_addr = (uint64_t)vm->guest_mem,
        .flags = 0
    };
    if (ioctl(vm->vmfd, KVM_SET_USER_MEMORY_REGION, &mem_region) < 0) err(1, "VMM: KVM_SET_USER_MEMORY_REGION");

    // Copy guest code to VM's RAM
    memcpy(vm->guest_mem, guest_code, sizeof(guest_code));

    // Create the vCPU
    vm->vcpufd = ioctl(vm->vmfd, KVM_CREATE_VCPU, 0);
    if (vm->vcpufd < 0) err(1, "VMM: KVM_CREATE_VCPU");

    // Setup memory for the vCPU
    vm->vcpu_mmap_size = ioctl(vm->kvmfd, KVM_GET_VCPU_MMAP_SIZE, NULL);
    if (vm->vcpu_mmap_size < 0) err(1, "VMM: KVM_GET_VCPU_MMAP_SIZE");

    if (vm->vcpu_mmap_size < (int)sizeof(struct kvm_run)) err(1, "VMM: KVM_GET_VCPU_MMAP_SIZE unexpectedly small");
    vm->run = mmap(NULL, (size_t)vm->vcpu_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vm->vcpufd, 0);
    if (!vm->run) err(1, "VMM: mmap vcpu");

    // Initialize segment registers to zero
    struct kvm_sregs sregs;
    if (ioctl(vm->vcpufd, KVM_GET_SREGS, &sregs) < 0) err(1, "VMM: KVM_GET_SREGS");
    sregs.cs.base = 0;  sregs.cs.selector = 0;
    sregs.ds.base = 0;  sregs.ds.selector = 0;
    sregs.es.base = 0;  sregs.es.selector = 0;
    sregs.ss.base = 0;  sregs.ss.selector = 0;
    if (ioctl(vm->vcpufd, KVM_SET_SREGS, &sregs) < 0) err(1, "VMM: KVM_SET_SREGS");

    // Initialize instruction pointer, stack pointer and flags register
    struct kvm_regs regs;
    memset(&regs, 0, sizeof(regs));
    regs.rip = 0;
    regs.rsp = vm->guest_mem_size;  // set stack pointer at the top of the guest's RAM
    regs.rflags = 0x2;  // bit 1 is reserved and should always bet set to 1
    if (ioctl(vm->vcpufd, KVM_SET_REGS, &regs) < 0) err(1, "VMM: KVM_SET_REGS");

    // Runs the VM (guest code) and handles VM exits
    bool done = false;
    while (!done) {
        // Runs the vCPU until encoutering a VM_EXIT
        if (ioctl(vm->vcpufd, KVM_RUN, NULL) < 0) err(1, "VMM: KVM_RUN");

        switch (vm->run->exit_reason) {
            // NOTE: KVM_EXIT_IO is significantly faster than KVM_EXIT_MMIO

            case KVM_EXIT_IO:    // encountered an I/O instruction
                handle_pmio(vm);
                break;
            case KVM_EXIT_MMIO:  // encountered a MMIO instruction which could not be satisfied
                handle_mmio(vm);
                break;
            case KVM_EXIT_HLT:   // encountered "hlt" instruction
                fprintf(stderr, "VMM: KVM_EXIT_HLT\n");
                done = true;
                break;
            case KVM_EXIT_FAIL_ENTRY:
                fprintf(stderr, "VMM: KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = 0x%llx\n",
                    (unsigned long long)vm->run->fail_entry.hardware_entry_failure_reason);
                break;
            case KVM_EXIT_INTERNAL_ERROR:
                fprintf(stderr, "VMM: KVM_EXIT_INTERNAL_ERROR: suberror = 0x%x\n", vm->run->internal.suberror);
                done = true;
                break;
            case KVM_EXIT_SHUTDOWN:
                fprintf(stderr, "VMM: KVM_EXIT_SHUTDOWN\n");
                done = true;
                break;
            default:
                fprintf(stderr, "VMM: unhandled exit reason (0x%x)\n", vm->run->exit_reason);
                done = true;
                break;
        }
    }

    // Free allocated ressources
    if (vm->guest_mem)
        munmap(vm->guest_mem, vm->guest_mem_size);

    if (vm->run)
        munmap(vm->run, vm->vcpu_mmap_size);

    close(vm->kvmfd);
    memset(vm, 0, sizeof(vm_t));
    free(vm);

    return EXIT_SUCCESS;
}
