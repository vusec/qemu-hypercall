#ifndef HYPERMEM_API_H
#define HYPERMEM_API_H

/*
 * hypermem protocol - session management
 * - read from HYPERMEM_BASEADDR (in physical memory) of a
 *   hypermem_entry_t-sized value initiates a session
 * - in case of success, the read returns the communication address for
 *   the session; it is within the range
 *   HYPERMEM_BASEADDR...HYPERMEM_BASEADDR+HYPERMEM_SIZE
 * - in case of failure because no more sessions are available,
 *   the read returns 0
 * - further communication within the session proceeds by reads and writes of
 *   hypermem_entry_t-sized values to/from the communication address
 * - each command starts by writing a command identifier to the communication
 *   address and the remainder of the sequence of operations is determined
 *   by the protocol specified for that command type
 * - after a command has been completed the session process take another command
 * - the first command issued over a connection is HYPERMEM_COMMAND_CONNECT
 * - the final command issued over a connection is HYPERMEM_COMMAND_DISCONNECT
 *
 * hypermem protocol - connect
 * - write command identifier HYPERMEM_COMMAND_CONNECT
 *
 * hypermem protocol - disconnect
 * - write command identifier HYPERMEM_COMMAND_DISCONNECT
 *
 * hypermem protocol - edfi context set
 * - write command identifier HYPERMEM_COMMAND_EDFI_CONTEXT_SET
 * - write a pointer to the EDFI context
 * - write pointer offset used to translate pointers within the context
 *   (normally 0xc0000000 for Linux, 0 otherwise)
 * - write length of the module name in bytes, excluding terminator
 * - write module name data, one hypermem_entry_t unit at a time
 *
 * hypermem protocol - edfi dump all statistics
 * - write command identifier HYPERMEM_COMMAND_EDFI_DUMP_STATS
 * - write length of the message in bytes, excluding terminator
 * - write message data, one hypermem_entry_t unit at a time
 *
 * hypermem protocol - edfi dump statistics for module
 * - write command identifier HYPERMEM_COMMAND_EDFI_DUMP_STATS_MODULE
 * - write length of the module name in bytes, excluding terminator
 * - write module name data, one hypermem_entry_t unit at a time
 * - write length of the message in bytes, excluding terminator
 * - write message data, one hypermem_entry_t unit at a time
 *
 * hypermem protocol - edfi faultindex get
 * - write command identifier HYPERMEM_COMMAND_EDFI_FAULTINDEX_GET
 * - write length of the module name in bytes, excluding terminator
 * - write module name data, one hypermem_entry_t unit at a time
 * - read back reply
 * - the reply is the absolute basic block index where a fault should be
 *   injected; 0 means no fault, 1 means inject a fault in the first block
 *
 * hypermem protocol - fault
 * - write command identifier HYPERMEM_COMMAND_FAULT
 * - write basic block index
 * - write length of the module name in bytes, excluding terminator
 * - write module name data, one hypermem_entry_t unit at a time
 *
 * hypermem protocol - nop
 * - write command identifier HYPERMEM_COMMAND_NOP
 * - read back reply
 * - if the reply is HYPERCALL_NOP_REPLY, the hypermem interface works
 *
 * hypermem protocol - print
 * - write command identifier HYPERMEM_COMMAND_PRINT
 * - write length of the string in bytes, excluding terminator
 * - write string data, one hypermem_entry_t unit at a time
 *
 * hypermem protocol - quit
 * - write command identifier HYPERMEM_COMMAND_QUIT
 *
 * hypermem protocol - release_cr3
 * - write command identifier HYPERMEM_COMMAND_RELEASE_CR3
 * - write the process cr3 value for which the associated context is to be
 *   released
 *
 * hypermem protocol - set_cr3
 * - write command identifier HYPERMEM_COMMAND_SET_CR3
 * - write the current process cr3 value, to be used for the rest of the session
 */
 
 #include <stdint.h>

typedef uint32_t hypermem_entry_t;
/* I don't know how to tell the OS a memory region is reserved so I'll just
 * steal part of the video memory and hope it won't be used
 *
 * note: more than 256 bytes risks a race condition if reads are not atomic 
 */
#define HYPERMEM_BASEADDR	0xb7000
#define HYPERMEM_SIZE		0x00100

#define HYPERMEM_COMMANDMAGIC 0x773e35dd

#define HYPERMEM_COMMAND_CONNECT		(HYPERMEM_COMMANDMAGIC ^  1)
#define HYPERMEM_COMMAND_DISCONNECT		(HYPERMEM_COMMANDMAGIC ^  2)
#define HYPERMEM_COMMAND_NOP			(HYPERMEM_COMMANDMAGIC ^  3)
#define HYPERMEM_COMMAND_FAULT			(HYPERMEM_COMMANDMAGIC ^  4)
#define HYPERMEM_COMMAND_EDFI_CONTEXT_SET	(HYPERMEM_COMMANDMAGIC ^  5)
#define HYPERMEM_COMMAND_PRINT			(HYPERMEM_COMMANDMAGIC ^  6)
#define HYPERMEM_COMMAND_EDFI_FAULTINDEX_GET	(HYPERMEM_COMMANDMAGIC ^  7)
#define HYPERMEM_COMMAND_EDFI_DUMP_STATS	(HYPERMEM_COMMANDMAGIC ^  8)
#define HYPERMEM_COMMAND_EDFI_DUMP_STATS_MODULE	(HYPERMEM_COMMANDMAGIC ^  9)
#define HYPERMEM_COMMAND_SET_CR3		(HYPERMEM_COMMANDMAGIC ^ 10)
#define HYPERMEM_COMMAND_QUIT			(HYPERMEM_COMMANDMAGIC ^ 14)
#define HYPERMEM_COMMAND_RELEASE_CR3		(HYPERMEM_COMMANDMAGIC ^ 15)

#define HYPERCALL_NOP_REPLY	0x4e6f7021

#endif /* !defined(HYPERMEM_API_H) */
