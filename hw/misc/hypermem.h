#ifndef HYPERMEM_H
#define HYPERMEM_H

#include "hypermem-edfi.h"

#define HYPERMEM_ENTRIES        (HYPERMEM_SIZE / sizeof(hypermem_entry_t))
#define HYPERMEM_PRIO           3 /* 1 and 2 used by video memory */
#define HYPERMEM_PENDING_MAX    HYPERMEM_ENTRIES

#define TYPE_HYPERMEM           "hypermem"
#define HYPERMEM(obj)           OBJECT_CHECK(HyperMemState, (obj), TYPE_HYPERMEM)

#ifdef HYPERMEM_DEBUG
#define dbgprintf(format, ...) fprintf(stderr, "hypermem debug: " format, ##__VA_ARGS__)
#else
#define dbgprintf(format, ...)
#endif

/*
 * Structure Declarations
 */

/* Struct used to store a state for every session generated to hypermem
 * from inside the guest, and that stores data necessary for proper handling
 * since the protocol forced upon as has quite some restrictions
 */

#define HYPERMEM_STR_COUNT_MAX 2

enum hypermem_session_status {
	hss_closed,
	hss_preconnect,
	hss_connected,
};
 
typedef struct HyperMemSessionState {
    uint64_t badrw_last;
    uint64_t badrw_preconnect;
    enum hypermem_session_status status;
    int command;
    int state;

    /* command state */
    union {
        struct {
            hypermem_entry_t contextptr;
            hypermem_entry_t ptroffset;
        } edfi_context_set;
        struct {
            hypermem_entry_t bbindex;
        } fault;
    } command_state;
    hypermem_entry_t strlen;
    hypermem_entry_t strpos;
    char *strdata[HYPERMEM_STR_COUNT_MAX];

    /* the cr3 in case we need this to do page translation */
    uint32_t process_cr3;
} HyperMemSessionState;

typedef struct HyperMemPendingOperation {
    /* set for writes, clear for reads */
    int is_write;
    /* base address of operation aligned on hypermem_entry_t boundary */
    hwaddr baseaddr;
    /* bit mask of bytes valid in value */
    unsigned bytemask;
    /* value currently being read/written */
    hypermem_entry_t value;
} HyperMemPendingOperation;

typedef struct HyperMemState
{
    ISADevice parent_obj;

    /* properties */
    char *logpath;
    bool flushlog;
    char *faultspec;

    /* QEMU objects */
    MemoryRegion io;

    /* logging */
    struct logstate *logstate;
    int logfile_driveindex;

    /* CPU state */
    uint32_t cr4;
    int cr4_ok;

    /* EDFI contexts (linked list) */
    HyperMemEdfiContext *edfi_context;

    /* session state */
    uint64_t badrw_last;
    HyperMemSessionState sessions[HYPERMEM_ENTRIES];

    /* state for partial reads and writes */
    HyperMemPendingOperation pending[HYPERMEM_PENDING_MAX];
} HyperMemState;

struct logstate {
    /* log file */
    FILE *logfile;
    int logfile_partialline;
    bool flushlog;

    /* fault reporting aggregation */
    hypermem_entry_t fault_bbindex;
    unsigned long fault_count;
    char *fault_name;
    struct timeval fault_time;
    int fault_noflush;

    /* interrupt reporting */
    uint32_t interrupts;
};

/*
 * Utils Declarations
 */
#define CALLOC(count, type) ((type *) calloc_checked((count), sizeof(type), __FILE__, __LINE__))

static inline void *calloc_checked(size_t count, size_t size,
                                   const char *file, int line) {
    void *p;

    if (!count || !size) {
        return NULL;
    }

    p = calloc(count, size);
    if (!p) {
        fprintf(stderr, "hypermem: error: calloc(%lu, %lu) failed at %s:%d: %s\n",
                (long) count, (long) size,
                file, line, strerror(errno));
    }
    return p;
}

int vaddr_to_laddr(HyperMemState *state, vaddr ptr, vaddr *result);
char *read_string(HyperMemState *state, vaddr strptr, vaddr strlen);
size_t read_with_pagetable(HyperMemState *state, uint32_t cr3, uint32_t cr4,
    vaddr linaddr, void *buffer, size_t size);
void logprinterr(HyperMemState *state, const char *fmt, ...)
    __attribute__ ((__format__ (__printf__, 2, 3)));
void logprintf(HyperMemState *state, const char *fmt, ...)
    __attribute__ ((__format__ (__printf__, 2, 3)));
void logprintf_internal(struct logstate *state, const char *fmt, ...)
    __attribute__ ((__format__ (__printf__, 2, 3)));

/* EDFI Hypermem functions */
HyperMemEdfiContext *edfi_context_create(HyperMemState *state, const char *name);
HyperMemEdfiContext *edfi_context_find(HyperMemState *state, const char *name);
void edfi_context_release(HyperMemState *state, uint32_t process_cr3);
void edfi_context_release_all(HyperMemState *state);
void edfi_context_set(
        HyperMemState *state,
        const char *name,
        hypermem_entry_t contextptr,
        hypermem_entry_t ptroffset,
	uint32_t process_cr3);

void edfi_dump_stats_module_with_context(HyperMemState *state, HyperMemEdfiContext *ec, const char *msg);
void edfi_dump_stats_all(HyperMemState *state, const char *msg);
void edfi_dump_stats_module(HyperMemState *state, const char *name, const char *msg);

hypermem_entry_t edfi_faultindex_get(HyperMemState *state, const char *name);

void flush_fault(struct logstate *state);
void log_fault(
        HyperMemState *hmstate,
        const char *name,
        hypermem_entry_t bbindex);


#endif
