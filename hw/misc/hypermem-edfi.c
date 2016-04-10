#include "hw/hw.h"
#include "hw/isa/isa.h"
#include "hw/i386/pc.h"
#include "sysemu/kvm.h"
#include "hw/qdev.h"
#include "qemu/config-file.h"
#include "qemu/option.h"

#include <qemu/hypermem-api.h>

#include "hypermem.h"

HyperMemEdfiContext *edfi_context_create(HyperMemState *state, const char *name)
{
    HyperMemEdfiContext *ec;

    dbgprintf("edfi_context_create: name=%s\n", name);

    /* allocate structure */
    ec = CALLOC(1, HyperMemEdfiContext);
    if (!ec) return NULL;
    ec->name = strdup(name);
    if (!ec->name) {
        logprinterr(state, "error: strdup failed: %s\n", strerror(errno));
        free(ec);
        return NULL;
    }

    /* add to linked list */
    ec->next = state->edfi_context;
    state->edfi_context = ec;
    return ec;
}

HyperMemEdfiContext *edfi_context_find(HyperMemState *state, const char *name)
{
    HyperMemEdfiContext *ec;

    for (ec = state->edfi_context; ec; ec = ec->next) {
        if (strcmp(ec->name, name) == 0) return ec;
    }
    return NULL;
}

static void edfi_context_release_internal(
	HyperMemState *state,
	uint32_t process_cr3,
	int all)
{
    HyperMemEdfiContext *ec, **ec_p;

    ec_p = &state->edfi_context;
    while ((ec = *ec_p)) {
        if (all || ec->cr3 == process_cr3) {
	    edfi_dump_stats_module_with_context(state, ec,
		all ? "edfi_context_release_all" : "edfi_context_release");
            logprintf(state, "EDFI context release module=%s\n", ec->name);
	    *ec_p = ec->next;
	    free(ec->name);
	    free(ec);
	} else {
	    ec_p = &ec->next;
	}
    }
}

void edfi_context_release(
	HyperMemState *state,
	uint32_t process_cr3)
{
    dbgprintf("edfi_context_release: cr3=0x%lx\n", (long) process_cr3);
    edfi_context_release_internal(state, process_cr3, 0);
}

void edfi_context_release_all(
	HyperMemState *state)
{
    dbgprintf("edfi_context_release_all\n");
    edfi_context_release_internal(state, 0, 1);
}

static uint32_t get_cr4(HyperMemState *state, const char *name) {
    CPUState *cs;
    X86CPU *cpu;
    bool kvm_vcpu_dirty;

    assert(state);

    /* assumption: CR4 is not changed after the first call;
     * this helps avoid trouble if current_cpu is ever NULL on later calls
     */
    if (state->cr4_ok) return state->cr4;

    /* retrieve registers */
    cs = current_cpu;
    assert(cs);
    kvm_vcpu_dirty = cs->kvm_vcpu_dirty;
    cpu_synchronize_state(cs);
    cs->kvm_vcpu_dirty = kvm_vcpu_dirty;

    /* check that paging is enabled */
    if (!cpu_paging_enabled(cs)) {
        logprinterr(state, "warning: cannot set page table with "
	    "paging disabled module=%s\n", name);
	return 0;
    }
 
    /* store CR4 */
    cpu = X86_CPU(cs);
    assert(cpu);
    state->cr4 = cpu->env.cr[4];
    state->cr4_ok = 1;
    return state->cr4;
}

void edfi_context_set(
        HyperMemState *state,
        const char *name,
        hypermem_entry_t contextptr,
        hypermem_entry_t ptroffset,
	uint32_t process_cr3)
{
    HyperMemEdfiContext *ec;
    vaddr contextptr_lin;
    uint32_t cr4;

    /* check paging and fetch CR4 */
    cr4 = get_cr4(state, name);
    if (!state->cr4_ok) return;

    /* overwrite if we've seen this module before */
    ec = edfi_context_find(state, name);
    if (ec) {
        logprintf(state, "EDFI context reset module=%s\n", name);
    } else {
        ec = edfi_context_create(state, name);
        if (!ec) return;
        logprintf(state, "EDFI context set module=%s\n", name);
    }
    ec->cr3 = process_cr3;
    ec->cr4 = cr4;
    dbgprintf("edfi_context_set: cr3=0x%lx cr4=0x%lx name=%s\n",
	(long) process_cr3, (long) cr4, name);

    /* read EDFI context */
    if (!vaddr_to_laddr(state, contextptr, &contextptr_lin)) {
        logprinterr(state, "warning: cannot convert contextptr to "
	    "linear address module=%s\n", name);
	return;
    }
    dbgprintf("edfi_context_set: contextptr_lin=0x%lx\n",
	(long) contextptr_lin);
    if (read_with_pagetable(state, ec->cr3, ec->cr4, contextptr_lin,
	&ec->context, sizeof(ec->context)) != sizeof(ec->context)) {
        logprinterr(state, "warning: cannot read EDFI context module=%s\n", name);
	return;
    }

    /* verify canary */
    dbgprintf("edfi_context_set: canary_value1=0x%x canary_value2=0x%x "
	"bb_num_executions=0x%lx num_bbs=%d\n", ec->context.canary_value1,
	ec->context.canary_value2, (long) ec->context.bb_num_executions,
	ec->context.num_bbs);
    if (ec->context.canary_value1 != EDFI_CANARY_VALUE ||
        ec->context.canary_value2 != EDFI_CANARY_VALUE) {
        logprinterr(state, "warning: EDFI context canaries incorrect "
	    "module=%s\n", name);
	return;
    }

    /* store linear addresses for bb_num_executions */
    if (!vaddr_to_laddr(state, (vaddr) ec->context.bb_num_executions,
        &ec->bb_num_executions_linaddr)) {
        logprinterr(state, "warning: cannot convert EDFI context "
	    "virtual address to linear address module=%s\n", name);
        ec->bb_num_executions_linaddr = 0;
	return;
    }
    dbgprintf("edfi_context_set: bb_num_executions_linaddr=0x%lx\n",
	(long) ec->bb_num_executions_linaddr);
}

void edfi_dump_stats_module_with_context(HyperMemState *state, HyperMemEdfiContext *ec, const char *msg)
{
    exec_count *bb_num_executions, count, countrep;
    size_t bb_num_executions_count;
    size_t bb_num_executions_size;
    int i, repeats;

    dbgprintf("edfi_dump_stats_module_with_context: "
	"name=%s msg=%s bb_num_executions_linaddr=0x%lx num_bbs=%d\n",
	ec->name, msg, (long) ec->bb_num_executions_linaddr,
	ec->context.num_bbs);

    if (!ec->bb_num_executions_linaddr) {
        logprinterr(state, "warning: cannot dump EDFI context due to "
		"missing address module=%s msg=%s\n", ec->name, msg);
        return;
    }

    /* copy bb_num_executions (including canaries) */
    bb_num_executions_count = ec->context.num_bbs + 2;
    bb_num_executions_size = bb_num_executions_count * sizeof(exec_count);
    bb_num_executions = CALLOC(bb_num_executions_count, exec_count);
    if (read_with_pagetable(state, ec->cr3, ec->cr4, ec->bb_num_executions_linaddr,
        bb_num_executions, bb_num_executions_size) != bb_num_executions_size) {
        logprinterr(state, "warning: cannot read EDFI context module=%s msg=%s\n",
	    ec->name, msg);
        goto cleanup;
    }

    /* check canaries */
    dbgprintf("edfi_dump_stats_module_with_context: "
	"bb_num_executions={ 0x%llx, ..., 0x%llx }\n",
	(long long) bb_num_executions[0],
	(long long) bb_num_executions[ec->context.num_bbs + 1]);
    if (bb_num_executions[0] != EDFI_CANARY_VALUE ||
        bb_num_executions[ec->context.num_bbs + 1] != EDFI_CANARY_VALUE) {
        logprinterr(state, "warning: bb_num_executions canaries incorrect "
	    "module=%s msg=%s\n", ec->name, msg);
        goto cleanup;
    }    

    /* dump execution counts with run-length encoding */
    logprintf(state, "edfi_dump_stats_module name=%s msg=%s bbs=", ec->name, msg);
    countrep = 0;
    repeats = 0;
    for (i = 1; i <= ec->context.num_bbs; i++) {
        count = bb_num_executions[i];
        if (countrep == count) {
            repeats++;
        } else {
            if (repeats == 1) {
                logprintf(state, " %lu", (long) countrep);
            } else if (repeats != 0) {
                logprintf(state, " %lux%u", (long) countrep, repeats);
            }
            countrep = count;
            repeats = 1;
        }
    }
    if (repeats == 1) {
        logprintf(state, " %lu", (long) countrep);
    } else if (repeats != 0) { 
        logprintf(state, " %lux%u", (long) countrep, repeats);
    }
    logprintf(state, "\n");

    /* clean up */
cleanup:
    free(bb_num_executions);
}

void edfi_dump_stats_all(HyperMemState *state, const char *msg)
{
    HyperMemEdfiContext *ec;

    logprintf(state, "edfi_dump_stats msg=%s\n", msg);
    for (ec = state->edfi_context; ec; ec = ec->next) {
        edfi_dump_stats_module_with_context(state, ec, msg);
    }
}

void edfi_dump_stats_module(HyperMemState *state, const char *name, const char *msg)
{
    HyperMemEdfiContext *ec = edfi_context_find(state, name);

    if (ec) {
        edfi_dump_stats_module_with_context(state, ec, msg);
    } else {
        logprintf(state, "edfi_dump_stats_module name=%s msg=%s no context known\n", name, msg);
    }
}

hypermem_entry_t edfi_faultindex_get(HyperMemState *state, const char *name)
{
    int bbindex;
    const char *faultspec, *next;
    size_t namelen;
    char *tmp;

    /* remove instance specification from module name */
    tmp = strchr(name, '@');
    if (tmp != NULL)
        *tmp = 0;

    /* faultspec parameter present? */
    if (!state->faultspec) {
        logprintf(state, "edfi_faultindex_get name=%s "
                  "fault injection disabled\n", name);
        return 0;
    }

    /* remove comment (=path:line of fault) from fault specification */
    tmp = strchr(state->faultspec, '@');
    if (tmp != NULL)
        *tmp = 0;

    /* find a matching pair in faultspec */
    namelen = strlen(name);
    faultspec = state->faultspec;
    while (*faultspec) {
        /* look for delimiter at end of module name */
        next = strchr(faultspec, ':');
        if (!next) break;

        /* is this the module we are looking for */
        if ((next - faultspec == namelen) &&
            (strncmp(faultspec, name, namelen) == 0)) {
            bbindex = atoi(next + 1);
            logprintf(state, "edfi_faultindex_get name=%s bbindex=%d\n",
                      name, bbindex);
            return bbindex;
        }

        /* skip to next pair */
        next = strchr(next + 1, ':');
        if (!next) break;
        faultspec = next + 1;
    }

    logprintf(state, "edfi_faultindex_get name=%s not selected "
                     "for fault injection\n", name);
    return 0;
}

#define FAULT_COUNT_DIRECT_TO_LOG 3

void flush_fault(struct logstate *state)
{
    if (!state->fault_name) return;

    if (state->fault_noflush) return;

    if (state->fault_count > FAULT_COUNT_DIRECT_TO_LOG) {
        state->fault_noflush = 1;
        logprintf_internal(state, "fault name=%s bbindex=0x%lx count=%ld\n",
            state->fault_name, (long) state->fault_bbindex,
            state->fault_count - FAULT_COUNT_DIRECT_TO_LOG);
        state->fault_noflush = 0;
    }

    free(state->fault_name);
    state->fault_name = NULL;
    state->fault_bbindex = 0;
    state->fault_count = 0;
}

void log_fault(
        HyperMemState *hmstate,
        const char *name,
        hypermem_entry_t bbindex)
{
    struct logstate *state = hmstate->logstate;

    if (state->fault_name && (
        strcmp(state->fault_name, name) != 0 || state->fault_bbindex != bbindex)) {
        flush_fault(state);
    }

    if (!state->fault_name) {
        state->fault_name = strdup(name);
	if (!state->fault_name) {
	    logprinterr(hmstate, "error: strdup failed: %s\n", strerror(errno));
	}
        state->fault_bbindex = bbindex;
    }

    /* log fault */
    state->fault_count++;
    if (gettimeofday(&state->fault_time, NULL) < 0) {
        perror("gettimofday failed");
        exit(-1);
    }
    if (state->fault_count <= FAULT_COUNT_DIRECT_TO_LOG) {
        assert(!state->fault_noflush);
        state->fault_noflush = 1;
        logprintf_internal(state, "fault name=%s bbindex=0x%lx\n",
            state->fault_name, (long) state->fault_bbindex);
        state->fault_noflush = 0;
    }
}



