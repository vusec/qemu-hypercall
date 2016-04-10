#include "hw/hw.h"
#include "hw/isa/isa.h"
#include "hw/i386/pc.h"
#include "sysemu/kvm.h"
#include "hw/qdev.h"
#include "qemu/config-file.h"
#include "qemu/option.h"

#include <qemu/hypermem-api.h>

#include "hypermem-edfi.h"
#include "hypermem.h"

int vaddr_to_laddr(HyperMemState *state, vaddr ptr, vaddr *result)
{
    X86CPU *cpu = X86_CPU(current_cpu);
    int segindex = R_DS;
    
    /* perform segment translation (cpu_get_phys_page_debug and
     * cpu_memory_rw_debug expect linear addresses)
     */
    if (ptr >= cpu->env.segs[segindex].limit) {
        logprinterr(state, "warning: ptr 0x%lx exceeds "
                "segment limit 0x%lx\n", (long) ptr,
                (long) cpu->env.segs[segindex].limit);
        *result = 0;
        return 0;
    }
    *result = ptr + cpu->env.segs[segindex].base;
    return 1;
}


char *read_string(HyperMemState *state, vaddr strptr, vaddr strlen)
{
    char *str;
    vaddr strptr_lin;

    str = CALLOC(strlen + 1, char);
    if (!str) return NULL;

    if (!vaddr_to_laddr(state, strptr, &strptr_lin)) {
        return NULL;
    }
    if (cpu_memory_rw_debug(current_cpu, strptr_lin, (uint8_t *) str,
        strlen, 0) < 0) {
        logprinterr(state, "warning: cannot read string\n");
        free(str);
        return NULL;
    }
    str[strlen] = 0;
    return str;
}

static uint32_t read_pagetable32_entry(hwaddr physaddr) {
    uint32_t value = 0;
    cpu_physical_memory_read(physaddr, &value, sizeof(value));
    return value;
}

static int read_pagetable32(uint32_t cr3, vaddr linaddr, hwaddr *physaddr) {
    uint32_t pde, pte;
    hwaddr pdeaddr, pteaddr;

    pdeaddr = (cr3 & 0xfffff000) | ((linaddr & 0xffc00000) >> 20);
    pde = read_pagetable32_entry(pdeaddr);
    if (!(pde & PG_PRESENT_MASK)) return -1;
    if (pde & PG_PSE_MASK) {
	*physaddr = ((hwaddr) (pde & 0x003fe000) << 19) |
	    (pde & 0xffc00000) | (linaddr & 0x003fffff);
	return 0;
    }
    pteaddr = (pde & 0xfffff000) | ((linaddr & 0x003ff000) >> 10);
    pte = read_pagetable32_entry(pteaddr);
    if (!(pte & PG_PRESENT_MASK)) return -1;
    *physaddr = (pte & 0xfffff000) | (linaddr & 0x00000fff);
    return 0;
}

static uint64_t read_pagetable32pae_entry(hwaddr physaddr) {
    uint64_t value = 0;
    cpu_physical_memory_read(physaddr, &value, sizeof(value));
    return value;
}

static int read_pagetable32pae(uint32_t cr3, vaddr linaddr, hwaddr *physaddr) {
    uint64_t pdpte, pde, pte;
    hwaddr pdpteaddr, pdeaddr, pteaddr;

    pdpteaddr = (cr3 & 0xffffffe0) | ((linaddr & 0xc0000000) >> 27);
    pdpte = read_pagetable32pae_entry(pdpteaddr);
    if (!(pdpte & PG_PRESENT_MASK)) return -1;
    pdeaddr = (pdpte & 0xfffffffffffff000ULL) |
        ((linaddr & 0x3fe00000) >> 18);
    pde = read_pagetable32pae_entry(pdeaddr);
    if (!(pde & PG_PRESENT_MASK)) return -1;
    if (pde & PG_PSE_MASK) {
	*physaddr = (pde & 0x7fffffffffe00000) | (linaddr & 0x001fffff);
	return 0;
    }
    pteaddr = (pde & 0x7ffffffffffff000) | ((linaddr & 0x001ff000) >> 9);
    pte = read_pagetable32pae_entry(pteaddr);
    if (!(pte & PG_PRESENT_MASK)) return -1;
    *physaddr = (pte & 0x7ffffffffffff000) | (linaddr & 0x00000fff);
    return 0;
}

static int read_pagetable(uint32_t cr3, uint32_t cr4, vaddr linaddr,
    hwaddr *physaddr) {
    /* NOTE: this only works with 32-bit page tables */
    if (cr4 & CR4_PAE_MASK) {
        return read_pagetable32pae(cr3, linaddr, physaddr);
    } else {
        return read_pagetable32(cr3, linaddr, physaddr);
    }
}

size_t read_with_pagetable(HyperMemState *state, uint32_t cr3, uint32_t cr4,
    vaddr linaddr, void *buffer, size_t size) {
    vaddr chunk;
    uint8_t *p;
    hwaddr physaddr;
    size_t sizedone = 0;

    /* load buffer from physical addresses, one page at a time */
    p = buffer;
    while (size > 0) {
        chunk = TARGET_PAGE_SIZE - linaddr % TARGET_PAGE_SIZE;
        if (chunk > size) chunk = size;

	if (read_pagetable(cr3, cr4, linaddr, &physaddr) < 0) break;
        if (physaddr < HYPERMEM_BASEADDR + HYPERMEM_SIZE &&
            physaddr + chunk > HYPERMEM_BASEADDR) {
            logprinterr(state, "warning: data to be loaded overlaps "
                    "with IO range (physaddr=0x%lx, chunk=0x%lx)\n",
                    (long) physaddr, (long) chunk);
        } else {
            cpu_physical_memory_read(physaddr, p, chunk);
        }
        linaddr += chunk;
        size -= chunk;
        sizedone += chunk;
        p += chunk;
    }
    return sizedone;
}
