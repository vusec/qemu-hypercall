#ifndef HYPERMEM_EDFI_H
#define HYPERMEM_EDFI_H

#include <stdint.h>

/* from llvm-apps: llvm/include/edfi/common.h */

#ifndef PACKED
#define PACKED __attribute__((aligned(8),packed))
#endif

#define EDFI_DFLIB_PATH_MAX                     (512)
#define EDFI_CANARY_VALUE                       0xFF0A0011

/* this can be redefined to force pointer size to 32 or 64 bit */
#define POINTER(type) uint32_t

/* EDFI context definitions. */
typedef unsigned long long exec_count;
typedef struct {
    POINTER(char) name;
    POINTER(int) bb_num_injected;
    POINTER(int) bb_num_candidates;
} fault_type_stats;

typedef struct {
    float fault_prob;
    unsigned long fault_prob_randmax;
    int min_fdp_interval;
    int faulty_bb_index;
    unsigned int min_fault_time_interval;
    unsigned int max_time;
    unsigned long long max_faults;
    unsigned int rand_seed;
    char dflib_path[EDFI_DFLIB_PATH_MAX];
} PACKED edfi_context_conf_t;

typedef struct {
    unsigned int canary_value1;
    int fault_fdp_count;
    unsigned long long fault_time;
    unsigned long long start_time;
    unsigned long long total_faults;
    POINTER(fault_type_stats) fault_type_stats;
    POINTER(exec_count) bb_num_executions; /* canaries in first and last elements */
    POINTER(int) bb_num_faults;
    unsigned int num_bbs;
    unsigned int num_fault_types;
    int no_svr_thread;
    POINTER(char) output_dir;
    int num_requests_on_start;
    int verbosity;
    edfi_context_conf_t c;
    unsigned int canary_value2;
} PACKED edfi_context_t;

#undef POINTER

/* Structure that stores all the info needed to register a guest process EDFI context */
typedef struct HyperMemEdfiContext {
    struct HyperMemEdfiContext *next;

    char *name;
    edfi_context_t context;
    vaddr bb_num_executions_linaddr;
    uint32_t cr3;
    uint32_t cr4;
} HyperMemEdfiContext;


#endif /* !defined(HYPERMEM_EDFI_H) */
