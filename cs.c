/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */
#if defined (WIN32) || defined (WIN64) || defined (_WIN32) || defined (_WIN64)
#pragma warning(disable:4996)
#endif
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <capstone.h>

#include "utils.h"
#include "MCRegisterInfo.h"

#ifdef CAPSTONE_USE_SYS_DYN_MEM
#define INSN_CACHE_SIZE 32
#else
// reduce stack variable size for kernel/firmware
#define INSN_CACHE_SIZE 8
#endif

// default SKIPDATA mnemonic
#define SKIPDATA_MNEM ".byte"

cs_err (*arch_init[MAX_ARCH])(cs_struct *) = { NULL };
cs_err (*arch_option[MAX_ARCH]) (cs_struct *, cs_opt_type, size_t value) = { NULL };
void (*arch_destroy[MAX_ARCH]) (cs_struct *) = { NULL };

extern void ARM_enable(void);
extern void AArch64_enable(void);
extern void Mips_enable(void);
extern void X86_enable(void);
extern void PPC_enable(void);
extern void Sparc_enable(void);
extern void SystemZ_enable(void);
extern void XCore_enable(void);

static void archs_enable(void)
{
	static bool initialized = false;

	if (initialized)
		return;


#ifdef CAPSTONE_HAS_ARM
#warning capstone has arm: 
	ARM_enable();
#else 
#error capstone doesnt have arm
#endif
#ifdef CAPSTONE_HAS_ARM64
	AArch64_enable();
#endif
#ifdef CAPSTONE_HAS_MIPS
	Mips_enable();
#endif
#ifdef CAPSTONE_HAS_POWERPC
	PPC_enable();
#endif
#ifdef CAPSTONE_HAS_SPARC
	Sparc_enable();
#endif
#ifdef CAPSTONE_HAS_SYSZ
	SystemZ_enable();
#endif
#ifdef CAPSTONE_HAS_X86
	X86_enable();
#endif
#ifdef CAPSTONE_HAS_XCORE
	XCore_enable();
#endif


	initialized = true;
}

unsigned int all_arch = 0;

#ifdef CAPSTONE_USE_SYS_DYN_MEM
cs_malloc_t cs_mem_malloc = malloc;
cs_calloc_t cs_mem_calloc = calloc;
cs_realloc_t cs_mem_realloc = realloc;
cs_free_t cs_mem_free = free;
cs_vsnprintf_t cs_vsnprintf = vsnprintf;
#else
cs_malloc_t cs_mem_malloc = NULL;
cs_calloc_t cs_mem_calloc = NULL;
cs_realloc_t cs_mem_realloc = NULL;
cs_free_t cs_mem_free = NULL;
cs_vsnprintf_t cs_vsnprintf = NULL;
#endif

CAPSTONE_EXPORT
unsigned int cs_version(int *major, int *minor)
{
	archs_enable();

	if (major != NULL && minor != NULL) {
		*major = CS_API_MAJOR;
		*minor = CS_API_MINOR;
	}

	return (CS_API_MAJOR << 8) + CS_API_MINOR;
}

CAPSTONE_EXPORT
bool cs_support(int query)
{
	archs_enable();

	if (query == CS_ARCH_ALL)
		return all_arch == ((1 << CS_ARCH_ARM) | (1 << CS_ARCH_ARM64) |
				(1 << CS_ARCH_MIPS) | (1 << CS_ARCH_X86) |
				(1 << CS_ARCH_PPC) | (1 << CS_ARCH_SPARC) |
				(1 << CS_ARCH_SYSZ) | (1 << CS_ARCH_XCORE));

	if ((unsigned int)query < CS_ARCH_MAX)
		return all_arch & (1 << query);

	if (query == CS_SUPPORT_DIET) {
#ifdef CAPSTONE_DIET
		return true;
#else
		return false;
#endif
	}

	if (query == CS_SUPPORT_X86_REDUCE) {
#if defined(CAPSTONE_HAS_X86) && defined(CAPSTONE_X86_REDUCE)
		return true;
#else
		return false;
#endif
	}

	// unsupported query
	return false;
}

CAPSTONE_EXPORT
cs_err cs_errno(csh handle)
{
	struct cs_struct *ud;
	if (!handle)
		return CS_ERR_CSH;

	ud = (struct cs_struct *)(uintptr_t)handle;

	return ud->errnum;
}

CAPSTONE_EXPORT
const char *cs_strerror(cs_err code)
{
	switch(code) {
	default:
		return "Unknown error code";
	case CS_ERR_OK:
		return "OK (CS_ERR_OK)";
	case CS_ERR_MEM:
		return "Out of memory (CS_ERR_MEM)";
	case CS_ERR_ARCH:
		return "Invalid architecture (CS_ERR_ARCH)";
	case CS_ERR_HANDLE:
		return "Invalid handle (CS_ERR_HANDLE)";
	case CS_ERR_CSH:
		return "Invalid csh (CS_ERR_CSH)";
	case CS_ERR_MODE:
		return "Invalid mode (CS_ERR_MODE)";
	case CS_ERR_OPTION:
		return "Invalid option (CS_ERR_OPTION)";
	case CS_ERR_DETAIL:
		return "Details are unavailable (CS_ERR_DETAIL)";
	case CS_ERR_MEMSETUP:
		return "Dynamic memory management uninitialized (CS_ERR_MEMSETUP)";
	case CS_ERR_VERSION:
		return "Different API version between core & binding (CS_ERR_VERSION)";
	case CS_ERR_DIET:
		return "Information irrelevant in diet engine (CS_ERR_DIET)";
	case CS_ERR_SKIPDATA:
		return "Information irrelevant for 'data' instruction in SKIPDATA mode (CS_ERR_SKIPDATA)";
	}
}

CAPSTONE_EXPORT
cs_err cs_open(cs_arch arch, cs_mode mode, csh *handle)
{
	cs_err err;
	struct cs_struct *ud;
	if (!cs_mem_malloc || !cs_mem_calloc || !cs_mem_realloc || !cs_mem_free || !cs_vsnprintf)
		// Error: before cs_open(), dynamic memory management must be initialized
		// with cs_option(CS_OPT_MEM)
		return CS_ERR_MEMSETUP;

	archs_enable();

	if (arch < CS_ARCH_MAX && arch_init[arch]) {
		ud = cs_mem_calloc(1, sizeof(*ud));
		if (!ud) {
			// memory insufficient
			return CS_ERR_MEM;
		}

		ud->errnum = CS_ERR_OK;
		ud->arch = arch;
		ud->mode = mode;
		ud->big_endian = mode & CS_MODE_BIG_ENDIAN;
		// by default, do not break instruction into details
		ud->detail = CS_OPT_OFF;

		// default skipdata setup
		ud->skipdata_setup.mnemonic = SKIPDATA_MNEM;

		err = arch_init[ud->arch](ud);
		if (err) {
			cs_mem_free(ud);
			*handle = 0;
			return err;
		}

		*handle = (uintptr_t)ud;

		return CS_ERR_OK;
	} else {
		*handle = 0;
		return CS_ERR_ARCH;
	}
}

CAPSTONE_EXPORT
cs_err cs_close(csh *handle)
{
	struct cs_struct *ud;

	if (*handle == 0)
		// invalid handle
		return CS_ERR_CSH;

	ud = (struct cs_struct *)(*handle);

	if (ud->printer_info)
		cs_mem_free(ud->printer_info);

	cs_mem_free(ud->insn_cache);

	memset(ud, 0, sizeof(*ud));
	cs_mem_free(ud);

	// invalidate this handle by ZERO out its value.
	// this is to make sure it is unusable after cs_close()
	*handle = 0;

	return CS_ERR_OK;
}

// fill insn with mnemonic & operands info
static void fill_insn(struct cs_struct *handle, cs_insn *insn, char *buffer, MCInst *mci,
		PostPrinter_t postprinter, const uint8_t *code)
{
#ifndef CAPSTONE_DIET
	char *sp, *mnem;
#endif
	unsigned int copy_size = MIN(sizeof(insn->bytes), insn->size);

	// fill the instruction bytes.
	// we might skip some redundant bytes in front in the case of X86
	memcpy(insn->bytes, code + insn->size - copy_size, copy_size);
	insn->size = copy_size;

	// alias instruction might have ID saved in OpcodePub
	if (MCInst_getOpcodePub(mci))
		insn->id = MCInst_getOpcodePub(mci);

	// post printer handles some corner cases (hacky)
	if (postprinter)
		postprinter((csh)handle, insn, buffer, mci);

#ifndef CAPSTONE_DIET
	// fill in mnemonic & operands
	// find first space or tab
	sp = buffer;
	mnem = insn->mnemonic;
	for (sp = buffer; *sp; sp++) {
		if (*sp == ' '|| *sp == '\t')
			break;
		if (*sp == '|')	// lock|rep prefix for x86
			*sp = ' ';
		// copy to @mnemonic
		*mnem = *sp;
		mnem++;
	}

	*mnem = '\0';

	// copy @op_str
	if (*sp) {
		// find the next non-space char
		sp++;
		for (; ((*sp == ' ') || (*sp == '\t')); sp++);
		strncpy(insn->op_str, sp, sizeof(insn->op_str) - 1);
		insn->op_str[sizeof(insn->op_str) - 1] = '\0';
	} else
		insn->op_str[0] = '\0';
#endif
}

// how many bytes will we skip when encountering data (CS_OPT_SKIPDATA)?
// this very much depends on instruction alignment requirement of each arch.
static uint8_t skipdata_size(cs_struct *handle)
{
	switch(handle->arch) {
	default:
		// should never reach
		return -1;
	case CS_ARCH_ARM:
		// skip 2 bytes on Thumb mode.
		if (handle->mode & CS_MODE_THUMB)
			return 2;
		// otherwise, skip 4 bytes
		return 4;
	case CS_ARCH_ARM64:
	case CS_ARCH_MIPS:
	case CS_ARCH_PPC:
	case CS_ARCH_SPARC:
		// skip 4 bytes
		return 4;
	case CS_ARCH_SYSZ:
		// SystemZ instruction's length can be 2, 4 or 6 bytes,
		// so we just skip 2 bytes
		return 2;
	case CS_ARCH_X86:
		// X86 has no restriction on instruction alignment
		return 1;
	case CS_ARCH_XCORE:
		// XCore instruction's length can be 2 or 4 bytes,
		// so we just skip 2 bytes
		return 2;
	}
}

CAPSTONE_EXPORT
cs_err cs_option(csh ud, cs_opt_type type, size_t value)
{
	struct cs_struct *handle;
	archs_enable();

	// cs_option() can be called with NULL handle just for CS_OPT_MEM
	// This is supposed to be executed before all other APIs (even cs_open())
	if (type == CS_OPT_MEM) {
		cs_opt_mem *mem = (cs_opt_mem *)value;

		cs_mem_malloc = mem->malloc;
		cs_mem_calloc = mem->calloc;
		cs_mem_realloc = mem->realloc;
		cs_mem_free = mem->free;
		cs_vsnprintf = mem->vsnprintf;

		return CS_ERR_OK;
	}

	handle = (struct cs_struct *)(uintptr_t)ud;
	if (!handle)
		return CS_ERR_CSH;

	switch(type) {
	default:
		break;
	case CS_OPT_DETAIL:
		handle->detail = value;
		return CS_ERR_OK;
	case CS_OPT_SKIPDATA:
		handle->skipdata = (value == CS_OPT_ON);
		if (handle->skipdata) {
			if (handle->skipdata_size == 0) {
				// set the default skipdata size
				handle->skipdata_size = skipdata_size(handle);
			}
		}
		return CS_ERR_OK;
	case CS_OPT_SKIPDATA_SETUP:
		if (value)
			handle->skipdata_setup = *((cs_opt_skipdata *)value);
		return CS_ERR_OK;
	}

	return arch_option[handle->arch](handle, type, value);
}

// generate @op_str for data instruction of SKIPDATA
static void skipdata_opstr(char *opstr, const uint8_t *buffer, size_t size)
{
	char *p = opstr;
	int len;
	size_t i;

	if (!size) {
		opstr[0] = '\0';
		return;
	}

	len = sprintf(p, "0x%02x", buffer[0]);
	p+= len;

	for(i = 1; i < size; i++) {
		len = sprintf(p, ", 0x%02x", buffer[i]);
		p+= len;
	}
}

// dynamicly allocate memory to contain disasm insn
// NOTE: caller must free() the allocated memory itself to avoid memory leaking
//ud is a pointer. a pointer. not the handle value itself
CAPSTONE_EXPORT
size_t cs_disasm(csh ud, const uint8_t *buffer, size_t size, uint64_t offset, size_t count, cs_insn **insn)
{
	struct cs_struct *handle;
	MCInst mci;
	uint16_t insn_size;
	size_t c = 0, i;
	unsigned int f = 0;	// index of the next instruction in the cache
	cs_insn *insn_cache;	// cache contains disassembled instructions
	void *total = NULL;
	size_t total_size = 0;	// total size of output buffer containing all insns
	bool r;
	void *tmp;
	size_t skipdata_bytes;
	uint64_t offset_org; // save all the original info of the buffer
	size_t size_org;
	const uint8_t *buffer_org;
	unsigned int cache_size = INSN_CACHE_SIZE;
	size_t next_offset;

	handle = (struct cs_struct *)(uintptr_t)ud;
	if (!handle) {
		// FIXME: how to handle this case:
		// handle->errnum = CS_ERR_HANDLE;
		return 0;
	}

	handle->errnum = CS_ERR_OK;

#ifdef CAPSTONE_USE_SYS_DYN_MEM
	if (count > 0 && count <= INSN_CACHE_SIZE)
		cache_size = (unsigned int) count;
#endif

	// save the original offset for SKIPDATA
	buffer_org = buffer;
	offset_org = offset;
	size_org = size;

	total_size = sizeof(cs_insn) * cache_size;
	total = cs_mem_malloc(total_size);
	if (total == NULL) {
		// insufficient memory
		handle->errnum = CS_ERR_MEM;
		return 0;
	}

	insn_cache = total;

	while (size > 0) {
		MCInst_Init(&mci);
		mci.csh = handle;

		// relative branches need to know the address & size of current insn
		mci.address = offset;

		if (handle->detail) {
			// allocate memory for @detail pointer
			insn_cache->detail = cs_mem_malloc(sizeof(cs_detail));
		} else {
			insn_cache->detail = NULL;
		}

		// save all the information for non-detailed mode
		mci.flat_insn = insn_cache;
		mci.flat_insn->address = offset;
#ifdef CAPSTONE_DIET
		// zero out mnemonic & op_str
		mci.flat_insn->mnemonic[0] = '\0';
		mci.flat_insn->op_str[0] = '\0';
#endif

		r = handle->disasm(ud, buffer, size, &mci, &insn_size, offset, handle->getinsn_info);
		if (r) {
			SStream ss;
			SStream_Init(&ss);

			mci.flat_insn->size = insn_size;

			// map internal instruction opcode to public insn ID
			handle->insn_id(handle, insn_cache, mci.Opcode);

			handle->printer(&mci, &ss, handle->printer_info);

			fill_insn(handle, insn_cache, ss.buffer, &mci, handle->post_printer, buffer);

			next_offset = insn_size;
		} else	{
			// encounter a broken instruction

			// free memory of @detail pointer
			if (handle->detail) {
				cs_mem_free(insn_cache->detail);
			}

			// if there is no request to skip data, or remaining data is too small,
			// then bail out
			if (!handle->skipdata || handle->skipdata_size > size)
				break;

			if (handle->skipdata_setup.callback) {
				skipdata_bytes = handle->skipdata_setup.callback(buffer_org, size_org,
						(size_t)(offset - offset_org), handle->skipdata_setup.user_data);
				if (skipdata_bytes > size)
					// remaining data is not enough
					break;

				if (!skipdata_bytes)
					// user requested not to skip data, so bail out
					break;
			} else
				skipdata_bytes = handle->skipdata_size;

			// we have to skip some amount of data, depending on arch & mode
			insn_cache->id = 0;	// invalid ID for this "data" instruction
			insn_cache->address = offset;
			insn_cache->size = (uint16_t)skipdata_bytes;
			memcpy(insn_cache->bytes, buffer, skipdata_bytes);
			strncpy(insn_cache->mnemonic, handle->skipdata_setup.mnemonic,
					sizeof(insn_cache->mnemonic) - 1);
			skipdata_opstr(insn_cache->op_str, buffer, skipdata_bytes);
			insn_cache->detail = NULL;

			next_offset = skipdata_bytes;
		}

		// one more instruction entering the cache
		f++;

		// one more instruction disassembled
		c++;
		if (count > 0 && c == count)
			// already got requested number of instructions
			break;

		if (f == cache_size) {
			// full cache, so expand the cache to contain incoming insns
			cache_size = cache_size * 8 / 5; // * 1.6 ~ golden ratio
			total_size += (sizeof(cs_insn) * cache_size);
			tmp = cs_mem_realloc(total, total_size);
			if (tmp == NULL) {	// insufficient memory
				if (handle->detail) {
					insn_cache = (cs_insn *)total;
					for (i = 0; i < c; i++, insn_cache++)
						cs_mem_free(insn_cache->detail);
				}

				cs_mem_free(total);
				*insn = NULL;
				handle->errnum = CS_ERR_MEM;
				return 0;
			}

			total = tmp;
			// continue to fill in the cache after the last instruction
			insn_cache = (cs_insn *)((char *)total + sizeof(cs_insn) * c);

			// reset f back to 0, so we fill in the cache from begining
			f = 0;
		} else
			insn_cache++;

		buffer += next_offset;
		size -= next_offset;
		offset += next_offset;
	}

	if (!c) {
		// we did not disassemble any instruction
		cs_mem_free(total);
		total = NULL;
	} else if (f != cache_size) {
		// total did not fully use the last cache, so downsize it
		void *tmp = cs_mem_realloc(total, total_size - (cache_size - f) * sizeof(*insn_cache));
		if (tmp == NULL) {	// insufficient memory
			// free all detail pointers
			if (handle->detail) {
				insn_cache = (cs_insn *)total;
				for (i = 0; i < c; i++, insn_cache++)
					cs_mem_free(insn_cache->detail);
			}

			cs_mem_free(total);
			*insn = NULL;

			handle->errnum = CS_ERR_MEM;
			return 0;
		}

		total = tmp;
	}

	*insn = total;

	return c;
}

CAPSTONE_EXPORT
CAPSTONE_DEPRECATED
size_t cs_disasm_ex(csh ud, const uint8_t *buffer, size_t size, uint64_t offset, size_t count, cs_insn **insn)
{
	return cs_disasm(ud, buffer, size, offset, count, insn);
}

CAPSTONE_EXPORT
void cs_free(cs_insn *insn, size_t count)
{
	size_t i;

	// free all detail pointers
	for (i = 0; i < count; i++)
		cs_mem_free(insn[i].detail);

	// then free pointer to cs_insn array
	cs_mem_free(insn);
}

CAPSTONE_EXPORT
cs_insn *cs_malloc(csh ud)
{
	cs_insn *insn;
	struct cs_struct *handle = (struct cs_struct *)(uintptr_t)ud;

	insn = cs_mem_malloc(sizeof(cs_insn));
	if (!insn) {
		// insufficient memory
		handle->errnum = CS_ERR_MEM;
		return NULL;
	} else {
		if (handle->detail) {
			// allocate memory for @detail pointer
			insn->detail = cs_mem_malloc(sizeof(cs_detail));
			if (insn->detail == NULL) {	// insufficient memory
				cs_mem_free(insn);
				handle->errnum = CS_ERR_MEM;
				return NULL;
			}
		} else
			insn->detail = NULL;
	}

	return insn;
}

// iterator for instruction "single-stepping"
CAPSTONE_EXPORT
bool cs_disasm_iter(csh ud, const uint8_t **code, size_t *size,
		uint64_t *address, cs_insn *insn)
{
	struct cs_struct *handle;
	uint16_t insn_size;
	MCInst mci;
	bool r;

	handle = (struct cs_struct *)(uintptr_t)ud;
	if (!handle) {
		return false;
	}

	handle->errnum = CS_ERR_OK;

	MCInst_Init(&mci);
	mci.csh = handle;

	// relative branches need to know the address & size of current insn
	mci.address = *address;

	// save all the information for non-detailed mode
	mci.flat_insn = insn;
	mci.flat_insn->address = *address;
#ifdef CAPSTONE_DIET
	// zero out mnemonic & op_str
	mci.flat_insn->mnemonic[0] = '\0';
	mci.flat_insn->op_str[0] = '\0';
#endif

	r = handle->disasm(ud, *code, *size, &mci, &insn_size, *address, handle->getinsn_info);
	if (r) {
		SStream ss;
		SStream_Init(&ss);

		mci.flat_insn->size = insn_size;

		// map internal instruction opcode to public insn ID
		handle->insn_id(handle, insn, mci.Opcode);

		handle->printer(&mci, &ss, handle->printer_info);

		fill_insn(handle, insn, ss.buffer, &mci, handle->post_printer, *code);

		*code += insn_size;
		*size -= insn_size;
		*address += insn_size;
	} else { 	// encounter a broken instruction
		size_t skipdata_bytes;

		// if there is no request to skip data, or remaining data is too small,
		// then bail out
		if (!handle->skipdata || handle->skipdata_size > *size)
			return false;

		if (handle->skipdata_setup.callback) {
			skipdata_bytes = handle->skipdata_setup.callback(*code, *size,
					0, handle->skipdata_setup.user_data);
			if (skipdata_bytes > *size)
				// remaining data is not enough
				return false;

			if (!skipdata_bytes)
				// user requested not to skip data, so bail out
				return false;
		} else
			skipdata_bytes = handle->skipdata_size;

		// we have to skip some amount of data, depending on arch & mode
		insn->id = 0;	// invalid ID for this "data" instruction
		insn->address = *address;
		insn->size = (uint16_t)skipdata_bytes;
		memcpy(insn->bytes, *code, skipdata_bytes);
		strncpy(insn->mnemonic, handle->skipdata_setup.mnemonic,
				sizeof(insn->mnemonic) - 1);
		skipdata_opstr(insn->op_str, *code, skipdata_bytes);

		*code += skipdata_bytes;
		*size -= skipdata_bytes;
		*address += skipdata_bytes;
	}

	return true;
}

// return friendly name of regiser in a string
CAPSTONE_EXPORT
const char *cs_reg_name(csh ud, unsigned int reg)
{
	struct cs_struct *handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle || handle->reg_name == NULL) {
		return NULL;
	}

	return handle->reg_name(ud, reg);
}

CAPSTONE_EXPORT
const char *cs_insn_name(csh ud, unsigned int insn)
{
	struct cs_struct *handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle || handle->insn_name == NULL) {
		return NULL;
	}

	return handle->insn_name(ud, insn);
}

CAPSTONE_EXPORT
const char *cs_group_name(csh ud, unsigned int group)
{
	struct cs_struct *handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle || handle->group_name == NULL) {
		return NULL;
	}

	return handle->group_name(ud, group);
}

static bool arr_exist(unsigned char *arr, unsigned char max, unsigned int id)
{
	int i;

	for (i = 0; i < max; i++) {
		if (arr[i] == id)
			return true;
	}

	return false;
}

CAPSTONE_EXPORT
bool cs_insn_group(csh ud, const cs_insn *insn, unsigned int group_id)
{
	struct cs_struct *handle;
	if (!ud)
		return false;

	handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return false;
	}

	if(!insn->id) {
		handle->errnum = CS_ERR_SKIPDATA;
		return false;
	}

	if(!insn->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return false;
	}

	return arr_exist(insn->detail->groups, insn->detail->groups_count, group_id);
}

CAPSTONE_EXPORT
bool cs_reg_read(csh ud, const cs_insn *insn, unsigned int reg_id)
{
	struct cs_struct *handle;
	if (!ud)
		return false;

	handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return false;
	}

	if(!insn->id) {
		handle->errnum = CS_ERR_SKIPDATA;
		return false;
	}

	if(!insn->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return false;
	}

	return arr_exist(insn->detail->regs_read, insn->detail->regs_read_count, reg_id);
}

CAPSTONE_EXPORT
bool cs_reg_write(csh ud, const cs_insn *insn, unsigned int reg_id)
{
	struct cs_struct *handle;
	if (!ud)
		return false;

	handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return false;
	}

	if(!insn->id) {
		handle->errnum = CS_ERR_SKIPDATA;
		return false;
	}

	if(!insn->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return false;
	}

	return arr_exist(insn->detail->regs_write, insn->detail->regs_write_count, reg_id);
}

CAPSTONE_EXPORT
int cs_op_count(csh ud, const cs_insn *insn, unsigned int op_type)
{
	struct cs_struct *handle;
	unsigned int count = 0, i;
	if (!ud)
		return -1;

	handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return -1;
	}

	if(!insn->id) {
		handle->errnum = CS_ERR_SKIPDATA;
		return -1;
	}

	if(!insn->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return -1;
	}

	handle->errnum = CS_ERR_OK;

	switch (handle->arch) {
	default:
		handle->errnum = CS_ERR_HANDLE;
		return -1;
	case CS_ARCH_ARM:
		for (i = 0; i < insn->detail->arm.op_count; i++)
			if (insn->detail->arm.operands[i].type == (arm_op_type)op_type)
				count++;
		break;
	case CS_ARCH_ARM64:
		for (i = 0; i < insn->detail->arm64.op_count; i++)
			if (insn->detail->arm64.operands[i].type == (arm64_op_type)op_type)
				count++;
		break;
	case CS_ARCH_X86:
		for (i = 0; i < insn->detail->x86.op_count; i++)
			if (insn->detail->x86.operands[i].type == (x86_op_type)op_type)
				count++;
		break;
	case CS_ARCH_MIPS:
		for (i = 0; i < insn->detail->mips.op_count; i++)
			if (insn->detail->mips.operands[i].type == (mips_op_type)op_type)
				count++;
		break;
	case CS_ARCH_PPC:
		for (i = 0; i < insn->detail->ppc.op_count; i++)
			if (insn->detail->ppc.operands[i].type == (ppc_op_type)op_type)
				count++;
		break;
	case CS_ARCH_SPARC:
		for (i = 0; i < insn->detail->sparc.op_count; i++)
			if (insn->detail->sparc.operands[i].type == (sparc_op_type)op_type)
				count++;
		break;
	case CS_ARCH_SYSZ:
		for (i = 0; i < insn->detail->sysz.op_count; i++)
			if (insn->detail->sysz.operands[i].type == (sysz_op_type)op_type)
				count++;
		break;
	case CS_ARCH_XCORE:
		for (i = 0; i < insn->detail->xcore.op_count; i++)
			if (insn->detail->xcore.operands[i].type == (xcore_op_type)op_type)
				count++;
		break;
	}

	return count;
}

CAPSTONE_EXPORT
int cs_op_index(csh ud, const cs_insn *insn, unsigned int op_type,
		unsigned int post)
{
	struct cs_struct *handle;
	unsigned int count = 0, i;
	if (!ud)
		return -1;

	handle = (struct cs_struct *)(uintptr_t)ud;

	if (!handle->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return -1;
	}

	if(!insn->id) {
		handle->errnum = CS_ERR_SKIPDATA;
		return -1;
	}

	if(!insn->detail) {
		handle->errnum = CS_ERR_DETAIL;
		return -1;
	}

	handle->errnum = CS_ERR_OK;

	switch (handle->arch) {
	default:
		handle->errnum = CS_ERR_HANDLE;
		return -1;
	case CS_ARCH_ARM:
		for (i = 0; i < insn->detail->arm.op_count; i++) {
			if (insn->detail->arm.operands[i].type == (arm_op_type)op_type)
				count++;
			if (count == post)
				return i;
		}
		break;
	case CS_ARCH_ARM64:
		for (i = 0; i < insn->detail->arm64.op_count; i++) {
			if (insn->detail->arm64.operands[i].type == (arm64_op_type)op_type)
				count++;
			if (count == post)
				return i;
		}
		break;
	case CS_ARCH_X86:
		for (i = 0; i < insn->detail->x86.op_count; i++) {
			if (insn->detail->x86.operands[i].type == (x86_op_type)op_type)
				count++;
			if (count == post)
				return i;
		}
		break;
	case CS_ARCH_MIPS:
		for (i = 0; i < insn->detail->mips.op_count; i++) {
			if (insn->detail->mips.operands[i].type == (mips_op_type)op_type)
				count++;
			if (count == post)
				return i;
		}
		break;
	case CS_ARCH_PPC:
		for (i = 0; i < insn->detail->ppc.op_count; i++) {
			if (insn->detail->ppc.operands[i].type == (ppc_op_type)op_type)
				count++;
			if (count == post)
				return i;
		}
		break;
	case CS_ARCH_SPARC:
		for (i = 0; i < insn->detail->sparc.op_count; i++) {
			if (insn->detail->sparc.operands[i].type == (sparc_op_type)op_type)
				count++;
			if (count == post)
				return i;
		}
		break;
	case CS_ARCH_SYSZ:
		for (i = 0; i < insn->detail->sysz.op_count; i++) {
			if (insn->detail->sysz.operands[i].type == (sysz_op_type)op_type)
				count++;
			if (count == post)
				return i;
		}
		break;
	case CS_ARCH_XCORE:
		for (i = 0; i < insn->detail->xcore.op_count; i++) {
			if (insn->detail->xcore.operands[i].type == (xcore_op_type)op_type)
				count++;
			if (count == post)
				return i;
		}
		break;
	}

	return -1;
}

uint32_t get_instr_bytes_32bit(cs_insn* ins){

	uint32_t toRet = 0;
	int i = (ins->size - 1);

		volatile uint32_t msb = (uint32_t) ins->bytes[i]<<24 ;
		volatile uint32_t lmsb = (uint32_t) ins->bytes[i-1]<<16;
		volatile uint32_t llmsb = (uint32_t) ins->bytes[i-2]<<8;
		volatile uint32_t lsb = (uint32_t) ins->bytes[i-3];

		toRet = msb+ lmsb + llmsb + lsb;

	return toRet;
}

void cs_dump(csh handle, cs_insn* ins, int fd)
{
	cs_arm *arm;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	arm = &(ins->detail->arm);
	//lprintf(STDOUT_FILENO, "0x%"PRIx64":\t%s\t%s\n", curinst[0].address, curinst[0].mnemonic, curinst[0].op_str);
	lprintf(STDOUT_FILENO, "Address: 0x%08llx\n", ins->address);

	int j;

	for (j = (ins->size -1); j >= 0; j -=4)
	{

	    lprintf(fd, "Encoding: 0x%02x%02x%02x%02x", ins->bytes[j], ins->bytes[j-1], ins->bytes[j-2], ins->bytes[j-3]);
	}

	lprintf(fd, "\n");

	lprintf(fd, "disassembled instruction: %s  %s", ins->mnemonic, ins->op_str);
	lprintf(fd, "capstone enumerated type: %u", ins->id);

	if (arm->op_count)
		lprintf(fd,"\top_count: %u\n", arm->op_count);

	for (i = 0; i < arm->op_count; i++) {
		cs_arm_op *op = &(arm->operands[i]);
		switch((int)op->type) {
		default:
			break;
		case ARM_OP_REG:
			lprintf(fd,"\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
			break;
		case ARM_OP_IMM:
			lprintf(fd,"\t\toperands[%u].type: IMM = 0x%x\n", i, op->imm);
			break;
		case ARM_OP_FP:
			lprintf(fd,"\t\toperands[%u].type: FP = %f\n", i, op->fp);
			break;
		case ARM_OP_MEM:
			lprintf(fd,"\t\toperands[%u].type: MEM\n", i);
			if (op->mem.base != X86_REG_INVALID)
				lprintf(fd,"\t\t\toperands[%u].mem.base: REG = %s\n",
						i, cs_reg_name(handle, op->mem.base));
			if (op->mem.index != X86_REG_INVALID)
				lprintf(fd,"\t\t\toperands[%u].mem.index: REG = %s\n",
						i, cs_reg_name(handle, op->mem.index));
			if (op->mem.scale != 1)
				lprintf(fd,"\t\t\toperands[%u].mem.scale: %u\n", i, op->mem.scale);
			if (op->mem.disp != 0)
				lprintf(fd,"\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);

			break;
		case ARM_OP_PIMM:
			lprintf(fd,"\t\toperands[%u].type: P-IMM = %u\n", i, op->imm);
			break;
		case ARM_OP_CIMM:
			lprintf(fd,"\t\toperands[%u].type: C-IMM = %u\n", i, op->imm);
			break;
		case ARM_OP_SETEND:
			lprintf(fd,"\t\toperands[%u].type: SETEND = %s\n", i, op->setend == ARM_SETEND_BE? "be" : "le");
			break;
		case ARM_OP_SYSREG:
			lprintf(fd,"\t\toperands[%u].type: SYSREG = %u\n", i, op->reg);
			break;
		}

		if (op->shift.type != ARM_SFT_INVALID && op->shift.value) {
			if (op->shift.type < ARM_SFT_ASR_REG){
				// shift with constant value
				lprintf(fd,"\t\t\tShift: %u = %u\n", op->shift.type, op->shift.value);
			}else{
				// shift with register
				lprintf(fd,"\t\t\tShift: %u = %s\n", op->shift.type,
						cs_reg_name(handle, op->shift.value));}
		}

		if (op->vector_index != -1) {
			lprintf(fd,"\t\toperands[%u].vector_index = %u\n", i, op->vector_index);
		}

		if (op->subtracted)
			lprintf(fd,"\t\tSubtracted: True\n");
	}

	if (arm->cc != ARM_CC_AL && arm->cc != ARM_CC_INVALID)
		lprintf(fd,"\tCode condition: %u\n", arm->cc);

	if (arm->update_flags)
		lprintf(fd,"\tUpdate-flags: True\n");

	if (arm->writeback)
		lprintf(fd,"\tWrite-back: True\n");

	if (arm->cps_mode)
		lprintf(fd,"\tCPSI-mode: %u\n", arm->cps_mode);

	if (arm->cps_flag)
		lprintf(fd,"\tCPSI-flag: %u\n", arm->cps_flag);

	if (arm->vector_data)
		lprintf(fd,"\tVector-data: %u\n", arm->vector_data);

	if (arm->vector_size)
		lprintf(fd,"\tVector-size: %u\n", arm->vector_size);

	if (arm->usermode)
		lprintf(fd,"\tUser-mode: True\n");

	if (arm->mem_barrier){
		lprintf(fd,"\tMemory-barrier: %u\n", arm->mem_barrier);
	}

	lprintf(fd, "\n");

}
