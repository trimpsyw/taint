﻿/* **********************************************************
 * Copyright (c) 2013 YAO Wei.  All rights reserved.
 * **********************************************************/


/*Taint analysis 
 * taintcheck.cpp
 */

#include "dr_api.h"
#include "drsyms.h"
#include "hashtable.h"
#include "taintcheck.hpp"
#ifdef USE_DRMGR
#include "drmgr.h"
#include "drwrap.h"
#include "utils.h"
#include "replace.h"
#endif
#include <string>
#include <stddef.h>
#ifdef WINDOWS
# include "windefs.h"
#endif

static const char * const build_date = __DATE__ " " __TIME__;

#define MAX_CLEAN_INSTR_COUNT 64

typedef enum{
	SHOW_INSTR			= 0x01,
	SHOW_SYM			= 0x02,
	SHOW_FUNC_TREE		= 0x04,
	SHOW_PROPAGATION	= 0x08,
	SHOW_TAINTING		= 0x10,
	SHOW_SHADOW_MEMORY	= 0x20,
}show_mask_t;

#ifdef WINDOWS
# define DISPLAY_STRING(msg) dr_messagebox(msg)
# define IF_WINDOWS(x) x
#else
# define DISPLAY_STRING(msg) dr_printf("%s\n", msg);
# define IF_WINDOWS(x) /* nothing */

#endif

const char* white_dll[] = {
	"user32.dll","gdi32.dll", "shell32.dll",  "ole32.dll", "oleaut32.dll",
	"comdlg32.dll","advapi32.dll", "imm32.dll", "rpcrt4.dll",
	"secur32.dll", "usp10.dll", "shlwapi.dll", "comctl32.dll",
	"UxTheme.dll", "gdiplus.dll", "WINMM.dll", "LPK.dll",
	"WindowsCodecs.dll", "MSCTF.dll", "WinUsb.dll", "SETUPAPI.dll",
	"NSI.dll", "sechost.dll", "DEVOBJ.dll", "CFGMGR32.dll",
	"cryptbase.dll", "normaliz.dll", "version.dll","urlmon.dll",
	"msimg32.dll", "crypt32.dll",
	"netapi32.dll", "WININET.dll", "iphlpapi.dll", "mswsock.dll", "wshtcpip.dll",
	"netutils.dll", "srvcli.dll", "wkscli.dll", "netbios.dll",
	"snxhk.dll", "safemon.dll", "sepro.dll", "360safemonpro.tpi"		//anti-virus
};

const char* black_dll[] = {
	"msvc*.dll", "kernel32.dll", "ntdll.dll", "KERNELBASE.dll",// "ws2_32.dll", "wsock32.dll",
};

typedef enum api_call_type_t
{
	CALL_UNDEFINED					= 0x0000,
	CALL_TAINTED_NORMAL_BUFFER		= 0x0010,
	CALL_TAINTED_NETWORK_BUFFER		= 0x0011,
	CALL_ALLOCATE_HEAP				= 0x0020,
	CALL_REALLOCATE_HEAP			= 0x0021,
	CALL_FREE_HEAP					= 0x0022,
}api_call_type;

struct api_call_rule_t
{
	char modname[64];				/* 模块名 */
	char function[64];				/* 函数名 */
	
	int param_count:16;				/* 函数参数总个数 */
	
	int buffer_id:8;				/* 参数索引从1开始计数，0代表返回值 */
	int buffer_is_char:8;			/* 是否为普通char数组 */
	
	int size_id:8;					/* In buffer大小 */
	int size_is_reference:8;		/* 是否为指针 */

	int read_size_id:8;				/* 返回buffer的大小， 0表示在返回值*/
	int read_size_is_reference:8;	/* 是否为指针 */

	int succeed_return_status;		/* 函数调用成功返回0还是非0*/ 

	api_call_type call_type;		/* 函数调用类型 */

}rules[] = {
	{"MSVC*.dll",		"fgets",			3, 1, 1, 2, 0, -1, 0, 1, CALL_TAINTED_NORMAL_BUFFER},
	{"Kernel32.dll",	"ReadFile",			5, 2, 1, 3, 0, 4,	1, 1, CALL_TAINTED_NORMAL_BUFFER},
	{"MSVC*.dll",		"fread",			4, 1, 1, 2, 0, -1, 0, 1, CALL_TAINTED_NORMAL_BUFFER},
	{"ws2_32.dll",		"WSARecvFrom",		9, 2, 0, 3, 0, 4, 1, 0, CALL_TAINTED_NETWORK_BUFFER},
	{"ws2_32.dll",		"WSARecv",			7, 2, 0, 3, 0, 4, 1, 0, CALL_TAINTED_NETWORK_BUFFER},
	{"ws2_32.dll",		"recvfrom",			4, 2, 1, 3, 0, 0, 0, 1, CALL_TAINTED_NORMAL_BUFFER},
	{"ws2_32.dll",		"recv",				4, 2, 1, 3, 0, 0, 0, 1, CALL_TAINTED_NORMAL_BUFFER},
	{"wsock32.dll",		"recvfrom",			4, 2, 1, 3, 0, 0, 0, 1, CALL_TAINTED_NORMAL_BUFFER},
	{"wsock32.dll",		"recv",				4, 2, 1, 3, 0, 0, 0, 1, CALL_TAINTED_NORMAL_BUFFER},
	{"ntdll.dll",		"RtlAllocateHeap",	3, 0, 1, 3, 0, -1, 0, 1, CALL_ALLOCATE_HEAP},
	/* BOOLEAN RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID HeapBase);*/
	{"ntdll.dll",		"RtlFreeHeap",		3, 3, 1, -1, 0, -1, 0, 1, CALL_FREE_HEAP},
	/* RtlReAllocateHeap(PVOID HeapHandle, ULONG Flags, PVOID MemoryPointer, ULONG Size );*/
	{"ntdll.dll",		"RtlReAllocateHeap",4, 3, 1, -1, 0, 4, 0, 1, CALL_REALLOCATE_HEAP},
};

#define CALL_RULES_NUM sizeof(rules)/sizeof(rules[0])

typedef struct call_routine_entry_t {
    app_pc pc;
	const module_data_t *mod;	/* 模块*/
	char* modname;				/* 模块名称*/
	char* function;				/* 函数名称*/
	api_call_rule_t rule;
}call_routine_entry;


typedef std::vector<std::string> function_tables;

typedef unsigned int reg_status;

typedef struct thread_data_t
{
	file_t f;					/* 日志文件fd */
	int thread_id;				/* 线程ID */
	api_call_type call_type;	/* 函数调用类型 */
	app_pc call_address, into_address, return_address;
	int buffer_idx;				/* 索引：缓冲区*/
	int size_id;				/* 索引：In Buffer的大小 */
	int read_size_id;			/* 索引：Out Buffer的大小 */
	int read_size_ref;			/* 是否为指针 */
	int succeed_return_status;	/* 调用返回0/非0*/
	app_pc read_size_offset;	/* 相对于esp的偏移量 */
	app_pc read_buffer;			/* 最终的缓冲区地址 */
	int read_size;				/* 最终的缓冲区大小 */
	int instr_count;			/* 指令块计数 */
	app_pc stack_bottom;		/* 栈底部 */
	app_pc stack_top;			/* 栈顶最小值 (stack_bottom > stack_top)*/
	reg_status taint_regs[DR_REG_LAST_ENUM];	/* 寄存器污染状态*/

	int enter_function;
	int leave_function;
	
	memory_list taint_memory;
	memory_list taint_memory_stack;
	std::string this_function; 
	function_tables funcs;
}thread_data;

static memory_list skip_list;

static void *stats_mutex; /* for multithread support */
static uint num_threads;
static client_id_t my_id;
static int tls_index;

file_t f_global;
file_t f_results;
client_id_t client_id;
app_pc ntdll_base;

static hashtable_t call_routine_table;
static const char* appnm;
char logsubdir[MAXIMUM_PATH];
char whitelist_lib[MAXIMUM_PATH];
app_pc app_base;
app_pc app_end;
char app_path[MAXIMUM_PATH];
show_mask_t verbose;

#undef ELOGF
#define ELOGF(mask, f, ...) do {   \
    if (verbose & (mask)) \
        dr_fprintf(f, __VA_ARGS__); \
} while (0)

#undef DOLOG
# define DOLOG(mask, stmt)  do {	\
    if (verbose & (mask))			\
        stmt                        \
} while (0)


static void
call_routine_entry_free(void* p)
{
	call_routine_entry* e = (call_routine_entry*)p;
	if(e->modname) free(e->modname);
	if(e->function)	free(e->function);
	dr_global_free(p, sizeof(*e));
}

static bool
within_whitelist(app_pc pc)
{
	if(skip_list.size() && skip_list.find(pc))
		return true;		
	return false;
}

static bool
opcode_is_arith(int opc)
{
    return (opc == OP_add || opc == OP_sub ||
            opc == OP_inc || opc == OP_dec ||
			opc == OP_xor || opc == OP_or || opc == OP_and ||
			opc == OP_mul || opc == OP_div ||
			opc == OP_sbb || opc == OP_adc || 
			opc == OP_neg || opc == OP_not ||
			/* opc_is_gpr_shift_src0 count is in src #0 */
			opc == OP_shl || opc == OP_shr || opc == OP_sar ||
            opc == OP_rol || opc == OP_ror || 
            opc == OP_rcl || opc == OP_rcr ||
			/* opc_is_gpr_shift_src1 count is in src #1 */
			opc == OP_shld || opc == OP_shrd);
}

static bool
opc_is_push(int opc)
{
    return (opc == OP_push || opc == OP_push_imm ||
            opc == OP_pushf || opc == OP_pusha || opc == OP_enter);
}

static bool
opc_is_pop(int opc)
{
    return (opc == OP_pop || opc == OP_popf || 
		opc == OP_popa || opc == OP_leave);
}

static bool
opc_is_move(int opc)
{
    return (opc == OP_mov_st || opc == OP_mov_ld ||
            opc == OP_mov_imm || opc == OP_mov_seg ||
            opc == OP_mov_priv || opc == OP_movzx || opc == OP_movsx ||
			opc == OP_lea || opc == OP_movs);
}

static bool
within_function(app_pc pc, dr_mcontext_t* mc)
{
	return (pc >= (app_pc)mc->esp && pc <= (app_pc)mc->ebp);
}

static bool
within_global_stack(app_pc pc, app_pc stack_bottom, app_pc stack_top)
{
	return (pc >= stack_top && pc <= stack_bottom);
}

#define MAX_OPTION_LEN DR_MAX_OPTIONS_LENGTH

static void 
process_options(const char* opstr)
{
	const char *s;
	char word[MAX_OPTION_LEN];
	for (s = get_option_word(opstr, word); s != NULL; s = get_option_word(s, word)) 
	{
		if(strcmp(word, "-logdir") == 0)
		{
			if(s = get_option_word(s, word))
				strncpy(logsubdir, word, sizeof(logsubdir));
			else break;
		}
		else if(strcmp(word, "-lib_whitelist") == 0)
		{
			if(s = get_option_word(s, word))
				strncpy(whitelist_lib, word, sizeof(whitelist_lib));
			else break;
		}
		else if(strcmp(word, "-verbose") == 0)
		{
			if(s = get_option_word(s, word))
				verbose = (show_mask_t)atoi(word);
			else break;
		}
	}
}

#define BUFFER_SIZE_BYTES(buf)      sizeof(buf)
#define BUFFER_SIZE_ELEMENTS(buf)   (BUFFER_SIZE_BYTES(buf) / sizeof((buf)[0]))
#define BUFFER_LAST_ELEMENT(buf)    (buf)[BUFFER_SIZE_ELEMENTS(buf) - 1]
#define NULL_TERMINATE_BUFFER(buf)  BUFFER_LAST_ELEMENT(buf) = 0

static void
close_file(file_t f)
{
    dr_close_file(f);
}

#define dr_close_file DO_NOT_USE_dr_close_file

static file_t
open_logfile(const char *name, bool pid_log, int which_thread)
{
    file_t f;
    char logname[MAXIMUM_PATH];
    if (pid_log) {
       dr_snprintf(logname, BUFFER_SIZE_ELEMENTS(logname),
		   "%s\\%s.%d.log", logsubdir, name, dr_get_process_id());
    } else if (which_thread >= 0) {
        dr_snprintf(logname, BUFFER_SIZE_ELEMENTS(logname), 
                        "%s\\%s.%d.%d.log", logsubdir, name,
                        which_thread, dr_get_thread_id(dr_get_current_drcontext()));
	} else {
        dr_snprintf(logname, BUFFER_SIZE_ELEMENTS(logname),
                        "%s\\%s", logsubdir, name);
    }
    NULL_TERMINATE_BUFFER(logname);
    
	f = dr_open_file(logname, DR_FILE_WRITE_OVERWRITE);
    return f;
}

static void
create_f_globalfile(const char* logdir)
{
    uint count = 0;
    const char *appnm = dr_get_application_name();
    const uint LOGDIR_TRY_MAX = 1000;
    do {
        dr_snprintf(logsubdir, sizeof(logsubdir), 
                    "%s/DrTaint-%s.%d.%03d",
                    logdir, appnm == NULL ? "null" : appnm,
                    dr_get_process_id(), count);
        NULL_TERMINATE_BUFFER(logsubdir);
    } while (!dr_create_dir(logsubdir) && ++count < LOGDIR_TRY_MAX);
    if (count >= LOGDIR_TRY_MAX) {
		dr_log(NULL, LOG_ALL, 1, "Unable to create subdir in log base dir %s\n", logdir);
        dr_abort();
    }

    f_global = open_logfile("global", true/*pid suffix*/, -1);

	dr_fprintf(f_global, "Dr. TaintCheck built on %s\n", build_date);
}

static file_t
create_thread_logfile(void *drcontext)
{
    file_t f;
    uint which_thread = atomic_add32_return_sum((volatile int *)&num_threads, 1) - 1;
    dr_fprintf(f_global, "new thread #%d id=%d\n",
          which_thread, dr_get_thread_id(drcontext));

    f = open_logfile("thread", false, which_thread/*tid suffix*/);
    dr_fprintf(f, "log for thread %d\n", dr_get_thread_id(drcontext));

    return f;
}

static void
print_function_tables(file_t f, const char* msg, function_tables& funcs)
{
	DOLOG(SHOW_FUNC_TREE, {
		dr_fprintf(f, "%s ", msg);
		for(function_tables::iterator it = funcs.begin();
			it != funcs.end(); it++)
			dr_fprintf(f, "%s:", it->c_str());
		dr_fprintf(f, "\n");
	});
}

static void
print_instr(void* drcontext, file_t f, instr_t* instr, app_pc pc)
{
	DOLOG(SHOW_INSTR,{
		int n1 = instr_num_srcs(instr);
		int n2 = instr_num_dsts(instr);

		dr_fprintf(f, PFX" ",  pc);
		instr_disassemble(drcontext, instr, f);
		dr_fprintf(f, "\t[%d, %d]\n",  n1, n2);
	});
}

#define MAX_SYM_RESULT 256
static int 
lookup_symbols_by_pc(app_pc addr, char* module, char* function, int size, size_t* modoff = NULL)
{
	module_data_t *data = dr_lookup_module(addr);
    if (data == NULL) 
	{
		strcpy(module, "<nomodule>");
		sprintf(function, "<noname>", addr); 
		return -1;
	}

	drsym_info_t sym;
    char file[MAXIMUM_PATH];
	sym.struct_size = sizeof(sym);
    sym.name = function;
    sym.name_size = size;
    sym.file = file;
    sym.file_size = MAXIMUM_PATH;

	const char *modname = dr_module_preferred_name(data);
    if (modname == NULL)
        modname = "<noname>";	
	
	drsym_error_t symres = drsym_lookup_address(data->full_path, addr - data->start, 
							&sym, DRSYM_DEFAULT_FLAGS);
	if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
		strncpy(module, modname, size);
		strncpy(function, sym.name, size);
		dr_free_module_data(data);
		return 1;
	} else {
		strncpy(module, modname, size);
		sprintf(function, "%x", addr); 
		dr_free_module_data(data);
		return 0;
	}
}

static int lookup_syms(app_pc addr, char* module, char *function, int size)
{
	drsym_error_t symres;
	drsym_info_t sym;
    char file[MAXIMUM_PATH];
	module_data_t *data;

	data = dr_lookup_module(addr);
    if (data == NULL) 
	{
		strcpy(module, "<nomodule>");
		sprintf(function, "<noname>", addr); 
		return -1;
	}

	sym.struct_size = sizeof(sym);
    sym.name = function;
    sym.name_size = size;
    sym.file = file;
    sym.file_size = MAXIMUM_PATH;

	const char *modname = dr_module_preferred_name(data);
    if (modname == NULL)
        modname = "<noname>";	
	
	symres = drsym_lookup_address(data->full_path, addr - data->start, &sym,
                                DRSYM_DEFAULT_FLAGS);
	
	if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
		strncpy(module, modname, size);
		strncpy(function, sym.name, size);
	} else {
		strncpy(module, modname, size);
		sprintf(function, "%x", addr); 
	}
			
	dr_free_module_data(data);

	return 0;
}

static app_pc
lookup_symbol_or_export(const module_data_t *mod, const char *name, bool internal)
{
#ifdef USE_DRSYMS
    app_pc res;
    if (mod->full_path != NULL) {
        if (internal)
            res = lookup_internal_symbol(mod, name);
        else
            res = lookup_symbol(mod, name);
        if (res != NULL)
            return res;
    }
    res = (app_pc) dr_get_proc_address(mod->handle, name);
    return res;
#else
    return (app_pc) dr_get_proc_address(mod->handle, name);
#endif
}


static void
print_propagation(file_t f, int n1, int n2, instr_t* instr, dr_mcontext_t *mc)
{
	DOLOG(SHOW_PROPAGATION, {
		if(n1 > 0) dr_fprintf(f, "src_opnd(");
		for(int i = 0; i < n1; i++)
		{
			if(i > 0) dr_fprintf(f, ", ");
			opnd_t src_opnd = instr_get_src(instr, i);
			if(opnd_is_reg(src_opnd))
				dr_fprintf(f, "reg:%d",  opnd_get_reg(src_opnd));
			else if(opnd_is_memory_reference(src_opnd))
				dr_fprintf(f, "mem:0x%08x", opnd_compute_address(src_opnd, mc));
			else if(opnd_is_pc(src_opnd))
				dr_fprintf(f, "pc:0x%08x", opnd_get_pc(src_opnd));//模块内部调用
			else if(opnd_is_abs_addr(src_opnd))
				dr_fprintf(f, "abs:0x%08x", opnd_get_addr(src_opnd));
			else if(opnd_is_immed_int(src_opnd))
				dr_fprintf(f, "imm:%d", opnd_get_immed_int(src_opnd));
			/*else if(opnd_is_base_disp(src_opnd))
				dr_fprintf(f, "%d:base+disp %d ", i);
			else if(opnd_is_instr(src_opnd))
				dr_fprintf(f, "%d:instr %d ", i);*/
		}
		if(n1 > 0) dr_fprintf(f, ") ");

		if(n2 > 0) dr_fprintf(f, "dst_opnd(");
		for(int i = 0; i < n2; i++)
		{
			if(i > 0) dr_fprintf(f, ", ");
			opnd_t dst_opnd = instr_get_dst(instr, i);
			if(opnd_is_reg(dst_opnd))
				dr_fprintf(f, "reg:%d",  opnd_get_reg(dst_opnd));
			else if(opnd_is_memory_reference(dst_opnd))
				dr_fprintf(f, "mem:0x%08x", opnd_compute_address(dst_opnd, mc));
			else if(opnd_is_pc(dst_opnd))
				dr_fprintf(f, "pc:0x%08x", opnd_get_pc(dst_opnd));
			else if(opnd_is_abs_addr(dst_opnd))
				dr_fprintf(f, "abs:0x%08x", opnd_get_addr(dst_opnd));
			else if(opnd_is_immed_int(dst_opnd))
				dr_fprintf(f, "imm:%d", opnd_get_immed_int(dst_opnd));
			/*else if(opnd_is_base_disp(dst_opnd))
				dr_fprintf(f, "%d:base+disp %d ", i);
			else if(opnd_is_instr(dst_opnd))
				dr_fprintf(f, "%d:instr %d ", i);*/
		}
		if(n2 > 0) dr_fprintf(f, ")");

		if(n1 || n2) dr_fprintf(f, "\n");
	});
}

#define LOG_REG_LIST(f, regs, mc)							\
	if(verbose&SHOW_TAINTING){								\
		dr_fprintf(f, "\tregs:");							\
		for(int i = DR_REG_EAX; i <= DR_REG_EDI; i++)		\
			if(regs[i])	dr_fprintf(f, "("PFX")", (regs[i]==1)?reg_get_value(i, mc):regs[i]);	\
			else dr_fprintf(f, "(nil)");					\
		dr_fprintf(f, "\n");								\
	}

#define LOG_MEMORY_LIST(s, f, m)										\
	if(verbose&SHOW_SHADOW_MEMORY){										\
		dr_fprintf(f, "%s(%d):", s, m.size());							\
		for(memory_list::iterator it = m.begin(); it != m.end(); it++)	\
			dr_fprintf(f, "[0x%x, 0x%x) %s ", it->start, it->end, (char*)it->start);				\
		dr_fprintf(f, "\n");											\
	}

static bool 
process_stack_shrink(memory_list& taint_memory, memory_list& stack_memory,
					 app_pc stack_top, app_pc current_esp)
{
	if(stack_memory.remove(stack_top, current_esp))
	{
		taint_memory.remove(stack_top, current_esp);
		return true;
	}
	return false;
}

static bool 
is_tags_clean(reg_status* regs)
{
	static reg_status clean_regs[DR_REG_LAST_ENUM] = {0};
	return !memcmp(regs, clean_regs, sizeof(clean_regs));
}

static void
clear_tag_eacbdx(reg_id_t reg, reg_status* taint_regs)
{
	if(reg == DR_REG_EAX){
		taint_regs[DR_REG_AX] = 0;
		taint_regs[DR_REG_AL] = 0;
		taint_regs[DR_REG_AH] = 0;
	} else if(reg == DR_REG_ECX){
		taint_regs[DR_REG_CX] = 0;
		taint_regs[DR_REG_CL] = 0;
		taint_regs[DR_REG_CH] = 0;
	} else if(reg == DR_REG_EBX){
		taint_regs[DR_REG_BX] = 0;
		taint_regs[DR_REG_BL] = 0;
		taint_regs[DR_REG_BH] = 0;
	} else if(reg == DR_REG_EDX){
		taint_regs[DR_REG_DX] = 0;
		taint_regs[DR_REG_DL] = 0;
		taint_regs[DR_REG_DH] = 0;
	}
}

static void
add_tag_eacbdx(reg_id_t reg, reg_status* taint_regs)
{
	if(reg == DR_REG_EAX){
		taint_regs[DR_REG_AX] = 1;
		taint_regs[DR_REG_AL] = 1;
		taint_regs[DR_REG_AH] = 1;
	} else if(reg == DR_REG_ECX){
		taint_regs[DR_REG_CX] = 1;
		taint_regs[DR_REG_CL] = 1;
		taint_regs[DR_REG_CH] = 1;
	} else if(reg == DR_REG_EBX){
		taint_regs[DR_REG_BX] = 1;
		taint_regs[DR_REG_BL] = 1;
		taint_regs[DR_REG_BH] = 1;
	} else if(reg == DR_REG_EDX){
		taint_regs[DR_REG_DX] = 1;
		taint_regs[DR_REG_DL] = 1;
		taint_regs[DR_REG_DH] = 1;
	}
}

static void 
taint_seed(app_pc pc, void* drcontext, dr_mcontext_t* mc)
{
#ifndef USE_DRMGR
	thread_data* data = (thread_data*)dr_get_tls_field(drcontext);
#else
	thread_data* data = (thread_data*)drmgr_get_tls_field(drcontext, tls_index);
#endif
	api_call_type& call_type = data->call_type;
	app_pc& return_address = data->return_address;
	
	if(call_type == CALL_UNDEFINED || return_address != pc)	
		return;

	file_t f = data->f;
	int& read_size_id = data->read_size_id;
	int& read_size_ref = data->read_size_ref;
	int& return_status = data->succeed_return_status;
	app_pc& read_size_offset = data->read_size_offset;
	app_pc& read_buffer = data->read_buffer;
	int& read_size = data->read_size;
	int in_size = data->read_size;
	memory_list& taint_memory = data->taint_memory;
	memory_list& stack_memory = data->taint_memory_stack;
	
	dr_fprintf(f, "Thread %d: function return status "PFX "\n", data->thread_id, mc->eax);
	
	//通过返回值判断函数调用是否失败
	if((return_status > 0 && (int)mc->eax <= 0) || (return_status == 0 && mc->eax != 0))
	{
		dr_fprintf(f, "Failed to call function\n");
		goto exit;
	}

	if(call_type == CALL_ALLOCATE_HEAP){
		read_buffer = (app_pc)mc->eax;
		dr_fprintf(f_global, "Alloc buffer %d:"PFX"-"PFX"\n", read_size, read_buffer, read_buffer+read_size);
		goto exit;
	} else if(call_type == CALL_FREE_HEAP){
		dr_fprintf(f_global, "Free buffer %d:"PFX"-"PFX"\n", read_size, read_buffer, read_buffer+read_size);
		goto exit;
	} else if(call_type == CALL_REALLOCATE_HEAP){
		dr_fprintf(f_global, "Free buffer %d:"PFX"-"PFX"\n", read_size, read_buffer, read_buffer+read_size);
		app_pc new_addr = (app_pc)mc->eax;
		dr_fprintf(f_global, "Alloc buffer %d:"PFX"-"PFX"\n", read_size_ref, new_addr, new_addr+read_size_ref);
		goto exit;
	}

	int value;
	size_t size;
		
	if(read_size_id >= 0)
	{
		if(read_size_id == 0)
			value = mc->eax;
		else
			dr_safe_read(read_size_offset, 4, &value, &size);

		if(read_size_ref)
			dr_safe_read((void *)value, 4, &value, &size);

		read_size = value;
	}
	else
	{
		//对于向fgets之类的函数，直接strlen获取长度
		read_size = strlen((char*)read_buffer) + 1;
	}

	if(read_size <= 0)	goto exit;//没有数据

	if(call_type == CALL_TAINTED_NORMAL_BUFFER)//普通的字符串，无需特别处理
	{
		range r(read_buffer, read_buffer+read_size);
		taint_memory.insert(r);
		dr_fprintf(f, "[Out] Read Size "PFX"\n", read_size);
		LOG_MEMORY_LIST("[+] global_memory", f, taint_memory);

		if(within_global_stack(read_buffer, data->stack_bottom, (app_pc)mc->esp))
		{
			stack_memory.insert(r);
			ELOGF(SHOW_SHADOW_MEMORY, f, "[+] stack_seed [0x%x, 0x%x)\n", r.start, r.end);
			LOG_MEMORY_LIST("[+] stack_memory", f, stack_memory);
		}
	}
	else if(call_type == CALL_TAINTED_NETWORK_BUFFER)
	{
		//处理其他缓冲区，这里处理_WSABUF的情况
		//struct WSABUF { ULONG len; CHAR *buf; }
		size_t n = 0; 
		app_pc addr;
		for(int i = 0; i < in_size; i++) //in_size UDP一般为2，TCP为1
		{
			dr_safe_read(read_buffer+i*8, 4, &value, &size);
			if(value <= 0) continue;
			if(i > 0)	value = read_size - n;

			dr_fprintf(f, "[Out] len "PFX"\n", value);

			n += (size_t)value;

			dr_safe_read(read_buffer+i*8+4, 4, &addr, &size);
			dr_fprintf(f, "[Out] buf "PFX"\n", addr);

			if(in_size == 1 || (in_size == 2 && i > 0))
			{
				range r(addr, addr+value);
				taint_memory.insert(r);
				dr_fprintf(f, "[Out] Taint memory "PFX" %d\n", addr, value);
				LOG_MEMORY_LIST("[+] global_memory", f, taint_memory);

				if(within_global_stack(addr, data->stack_bottom, (app_pc)mc->esp))
				{
					stack_memory.insert(r);
					ELOGF(SHOW_SHADOW_MEMORY, f, "[+] stack_seed [0x%x, 0x%x)\n", r.start, r.end);
					LOG_MEMORY_LIST("[+] stack_memory", f, stack_memory);
				}
			}

		}
	}

exit:
	call_type = CALL_UNDEFINED;
}

static int
taint_alert(instr_t* instr, app_pc target_addr, void* drcontext, dr_mcontext_t *mc)
{
#ifndef USE_DRMGR
	thread_data* data = (thread_data*)dr_get_tls_field(drcontext);
#else
	thread_data* data = (thread_data*)drmgr_get_tls_field(drcontext, tls_index);
#endif
	file_t f = data->f;
	reg_status* taint_regs = data->taint_regs;
	memory_list& taint_memory = data->taint_memory;

	int num = instr_num_srcs(instr);
	reg_t taint_reg = 0;
	app_pc taint_addr = 0;
	bool is_taint = false;
	int type;

	for(int i = 0; i < num; i++)
	{
		opnd_t src_opnd = instr_get_src(instr, i);		

		//call $0x02f9e3e2 %esp -> %esp 0xfffffffc(%esp)
		if(opnd_is_immed_int(src_opnd))
			break;

		if(opnd_is_reg(src_opnd) && 
			taint_regs[taint_reg = opnd_get_reg(src_opnd)])
		{
			is_taint = true;
			type = 0;
			break;
		}
		else if(opnd_is_memory_reference(src_opnd) &&
			taint_memory.find(taint_addr = opnd_compute_address(src_opnd, mc)))
		{
			is_taint = true;
			type = 1;
			break;
		}
		else if(opnd_is_pc(src_opnd) && 
			taint_memory.find(taint_addr = opnd_get_pc(src_opnd)))
		{
			is_taint = true;
			type = 1;
			break;
		}
	}

	if(is_taint)
	{
		char msg[512];
		if(type == 1)
			dr_snprintf(msg, sizeof(msg), "Calling taint memory %08x $%08x", taint_addr, target_addr);
		else
			dr_snprintf(msg, sizeof(msg), "Calling tainted reg %d $%08x\n", taint_reg, target_addr);

		dr_fprintf(f, msg);
	}

	return is_taint;
}
#define CONSTRUCT_INSTR_BEGIN(pc, drcontext)	\
	instr_t instr;								\
	instr_init(drcontext, &instr);				\
	instr_reuse(drcontext, &instr);				\
	decode(drcontext, pc, &instr);				

#define CONSTRUCT_INSTR_END(drcontext)			\
	instr_free(drcontext, &instr);				

#define SRC_OPND_IS_REG(instr, i, opnd, reg) opnd_is_reg(opnd = instr_get_src(instr, i)) && (reg = opnd_get_reg(opnd))
#define DST_OPND_IS_REG(instr, i, opnd, reg) opnd_is_reg(opnd = instr_get_dst(instr, i)) && (reg = opnd_get_reg(opnd))

static int 
get_reg_size(reg_id_t reg)
{
	if(reg>=DR_REG_START_64 && reg<=DR_REG_STOP_64)
		return 8;
	else if(reg>=DR_REG_START_32 && reg<=DR_REG_STOP_32)
		return 4;
	else if(reg>=DR_REG_START_16 && reg<=DR_REG_STOP_16)
		return 2;
	else if(reg>=DR_REG_START_8 && reg<=DR_REG_STOP_8)
		return 1;
	return 4;
}

static void 
taint_propagation(app_pc pc)
{
	void* drcontext = dr_get_current_drcontext();
#ifndef USE_DRMGR
	thread_data* data = (thread_data*)dr_get_tls_field(drcontext);
#else
	thread_data* data = (thread_data*)drmgr_get_tls_field(drcontext, tls_index);
#endif
	api_call_type& call_type = data->call_type;
	
	if(call_type) return;

	file_t f = data->f;
	reg_status* taint_regs = data->taint_regs;
	memory_list& taint_memory = data->taint_memory;
	memory_list& stack_memory = data->taint_memory_stack;
	
    dr_mcontext_t mc = {sizeof(mc),DR_MC_ALL};
    dr_get_mcontext(drcontext, &mc);

	CONSTRUCT_INSTR_BEGIN(pc, drcontext);
	
	print_instr(drcontext, f, &instr, pc);

	int opcode = instr_get_opcode(&instr);
	int n1 = instr_num_srcs(&instr);
	int n2 = instr_num_dsts(&instr);

	print_propagation(f, n1, n2, &instr, &mc);

	if(opcode == OP_sub && n1 == 2 && n2 == 1){//sub $0x00000010 %esp -> %esp
		opnd_t opnd, opnd2;
		if(opnd_is_reg(opnd=instr_get_src(&instr,1)) && opnd_get_reg(opnd)==DR_REG_ESP &&
			opnd_is_immed_int(opnd2=instr_get_src(&instr,0))){
			app_pc top = (app_pc)mc.esp - opnd_get_immed_int(opnd2);
			if(top < data->stack_top)	data->stack_top = top;
		}
	} else if(taint_memory.size() == 0 && is_tags_clean(taint_regs)){
		//没有污染源，直接跳过
		goto exit0;
	} else if(opc_is_pop(opcode)){
		if(opcode == OP_leave) goto shrink;//mov %esp,%ebp+pop ebp == leave
		
		if(n2 <= 0)	goto exit0;
		
		opnd_t dst_opnd = instr_get_dst(&instr, 0);
		if(!opnd_is_reg(dst_opnd)) goto exit0;
		
		reg_id_t reg = opnd_get_reg(dst_opnd);
		
		app_pc value;
		size_t size;
		dr_safe_read((void *)mc.esp, 4, &value, &size);
	
		if(taint_memory.find(value))
			taint_regs[reg] = value == 0 ? 1 : (reg_status)value;
		else
		{
			taint_regs[reg] = 0;
			clear_tag_eacbdx(reg, taint_regs);
		}
		goto exit0;
	} else if(opcode == OP_xor){ /* xor eax, eax */
		if(n1 != 2)	goto exit0;

		opnd_t opnd1 = instr_get_src(&instr, 0);
		opnd_t opnd2 = instr_get_src(&instr, 1);
		reg_id_t reg1, reg2;
		if(opnd_is_reg(opnd1) && opnd_is_reg(opnd2) && 
			(reg1=opnd_get_reg(opnd1)) == (reg2=opnd_get_reg(opnd2)))
		{
			taint_regs[reg1] = 0;
			clear_tag_eacbdx(reg1, taint_regs);
			goto exit0;
		}
	} else  if(opc_is_move(opcode) && n1==1 && n2==1){//mov %esp,%ebp
		opnd_t src_opnd, dst_opnd;
		if(opnd_is_reg(src_opnd=instr_get_src(&instr,0)) && opnd_get_reg(src_opnd)==DR_REG_EBP && 
			opnd_is_reg(dst_opnd=instr_get_dst(&instr,0)) && opnd_get_reg(dst_opnd)==DR_REG_ESP){
shrink:
			if(process_stack_shrink(taint_memory, stack_memory, data->stack_top, (app_pc)mc.ebp+4))
				ELOGF(SHOW_SHADOW_MEMORY, f, "[-] taint_propagation [0x%x, 0x%x)\n", (app_pc)mc.esp, (app_pc)mc.ebp);					
			
			app_pc top = (app_pc)mc.ebp+4;
			if(top < data->stack_top)	data->stack_top = top;
			LOG_MEMORY_LIST("[-] global_memory", f, taint_memory);
			LOG_MEMORY_LIST("[-] stack_memory", f, stack_memory);
			goto exit0;
		}
	}

propagation:
	//以下是污点传播
	bool src_tainted = false;
	reg_t taint_reg = 0, tainting_reg = 0;
	app_pc taint_addr = 0, tainting_addr = 0;
	if(n1 && n2)
	{
		int type = -1;
		opnd_t src_opnd;
		int taint_size = 4;
		
		for(int i = 0; i < n1; i++)
		{
			src_opnd = instr_get_src(&instr, i);
			if(opnd_is_reg(src_opnd) && 
				(taint_size = get_reg_size(taint_reg=opnd_get_reg(src_opnd))) &&
				taint_regs[taint_reg])
			{
				src_tainted = true;
				type = 0;
				break;
			}
			else if(opnd_is_memory_reference(src_opnd)) 
			{
				taint_addr = opnd_compute_address(src_opnd, &mc);
				app_pc mem_addr;
				dr_safe_read(taint_addr, 4, &mem_addr, NULL);
				if(taint_memory.find(taint_addr) || 
					(opc_is_move(opcode) && opcode != OP_lea && taint_memory.find(taint_addr=mem_addr)))
				{
					src_tainted = true;
					type = 1;
					break;
				}
			}
			else if(opnd_is_pc(src_opnd) && 
				taint_memory.find(taint_addr = opnd_get_pc(src_opnd)))
			{
				src_tainted = true;
				type = 2;
				break;
			}
		}

		int nn = 0;
dest:
		opnd_t dst_opnd = instr_get_dst(&instr, nn);
		if(src_tainted)//污染标记
		{
			DOLOG(SHOW_TAINTING, {
				dr_fprintf(f, "\t$$$$ taint ");
				if(type == 0)
				{
					opnd_disassemble(drcontext, src_opnd, f);
					dr_fprintf(f, "("PFX")", reg_get_value(taint_reg, &mc));
				}
				else if(type == 1)
					dr_fprintf(f, "$mem:0x%08x ", taint_addr);
				else if(type == 2)
					dr_fprintf(f, "mem:0x%08x ", taint_addr);
			});

			if(opnd_is_reg(dst_opnd))
			{
				taint_regs[tainting_reg = opnd_get_reg(dst_opnd)] = 
					(type == 0) ? 1 : (reg_status)taint_addr;
				add_tag_eacbdx(tainting_reg, taint_regs);
			}

			else if(opnd_is_memory_reference(dst_opnd))
			{
				if(type == 0 && reg_get_value(taint_reg, &mc))
				{
					tainting_addr = opnd_compute_address(dst_opnd, &mc);
					range r(tainting_addr, tainting_addr+taint_size);
					taint_memory.insert(r);
					LOG_MEMORY_LIST("[+] global_memory", f, taint_memory);
					
					if(within_global_stack(tainting_addr, data->stack_bottom, (app_pc)mc.esp))
					{
						stack_memory.insert(r);
						ELOGF(SHOW_SHADOW_MEMORY, f, "[+] taint_propagation [0x%x, 0x%x)\n", r.start, r.end);					
						LOG_MEMORY_LIST("[+] stack_memory", f, stack_memory);
					}
				}
			}

		
			else if(opnd_is_pc(dst_opnd))
			{
				tainting_addr = opnd_get_pc(dst_opnd);
				range r(tainting_addr, tainting_addr+taint_size);
				taint_memory.insert(r);
				LOG_MEMORY_LIST("[+] global_memory", f, taint_memory);
				
				if(within_global_stack(tainting_addr, data->stack_bottom, (app_pc)mc.esp))
				{
					stack_memory.insert(r);
					ELOGF(SHOW_SHADOW_MEMORY, f, "[+] taint_propagation [0x%x, 0x%x)\n", r.start, r.end);					
					LOG_MEMORY_LIST("[+] stack_memory", f, stack_memory);
				}
			}

			DOLOG(SHOW_TAINTING, {	
				if(tainting_addr == 0)
				{
					dr_fprintf(f, "---> ");
					opnd_disassemble(drcontext, dst_opnd, f);
					LOG_REG_LIST(f, taint_regs,  &mc);
				}
				else
					dr_fprintf(f, "---> mem:0x%08x\n", tainting_addr);
			});
		} 
		else//清除标记
		{
			if(opnd_is_reg(dst_opnd))
			{
				tainting_reg = opnd_get_reg(dst_opnd);
				if(taint_regs[tainting_reg])
				{
					taint_regs[tainting_reg] = 0;
					clear_tag_eacbdx(tainting_reg, taint_regs);
					LOG_REG_LIST(f, taint_regs, &mc);
				}
			}
			else if(opnd_is_memory_reference(dst_opnd))
			{
				app_pc addr = opnd_compute_address(dst_opnd, &mc);
				if(taint_memory.remove(addr, addr+taint_size))
				{
					ELOGF(SHOW_SHADOW_MEMORY, f, "[-] taint_propagation [0x%x, 0x%x)\n", addr, addr+taint_size);					
					LOG_MEMORY_LIST("[-] global_memory", f, taint_memory);
				}
				if(stack_memory.remove(addr, addr+taint_size))
					LOG_MEMORY_LIST("[-] stack_memory", f, stack_memory);
			}
		}
		if(++nn < n2) goto dest;
	}

exit0:
	CONSTRUCT_INSTR_END(drcontext);
}

static void
at_call(app_pc instr_addr, app_pc target_addr)
{
	void* drcontext = dr_get_current_drcontext();
#ifndef USE_DRMGR
	thread_data* data = (thread_data*)dr_get_tls_field(drcontext);
#else
	thread_data* data = (thread_data*)drmgr_get_tls_field(drcontext, tls_index);
#endif
	api_call_type& call_type = data->call_type;

	if(call_type) return;

	file_t f = data->f;
	app_pc& call_address = data->call_address;
	app_pc& return_address = data->return_address;
	int& buffer_idx = data->buffer_idx;
	int& size_id = data->size_id;
	int& read_size_id = data->read_size_id;
	int& read_size_ref = data->read_size_ref;
	int& succeed_return_status = data->succeed_return_status;
	app_pc& read_size_offset = data->read_size_offset;
	app_pc& read_buffer = data->read_buffer;
	int& read_size = data->read_size;
	function_tables& funcs = data->funcs;

    dr_mcontext_t mc = {sizeof(mc),DR_MC_ALL};
    dr_get_mcontext(drcontext, &mc);

	CONSTRUCT_INSTR_BEGIN(instr_addr, drcontext);

	print_instr(drcontext, f, &instr, instr_addr);

	int length = instr_length(drcontext, &instr);

	taint_alert(&instr, target_addr, drcontext, &mc);
	
	CONSTRUCT_INSTR_END(drcontext);
    
	char modname1[MAX_SYM_RESULT], func1[MAX_SYM_RESULT];
	char modname2[MAX_SYM_RESULT], func2[MAX_SYM_RESULT];
	int t1 = lookup_symbols_by_pc(instr_addr, modname1, func1, MAX_SYM_RESULT);
	int t2 = lookup_symbols_by_pc(target_addr, modname2, func2, MAX_SYM_RESULT);
	DOLOG(SHOW_SYM,
		if(t1 < 0)	dr_fprintf(f, "[CALL @ ] "PFX" unknown ??:0\n", instr_addr);
		else if(t1 > 0) dr_fprintf(f, "[CALL @ ] "PFX" %s:!%s\n", instr_addr, modname1, func1);
		else dr_fprintf(f, "[CALL @ ] "PFX" %s:!??\n", instr_addr, modname1);

		if(t2 < 0)	dr_fprintf(f, "\tInto "PFX" unknown ??:0\n", target_addr);
		else if(t2 > 0) dr_fprintf(f, "\tInto "PFX" %s:!%s\n", target_addr, modname2, func2);
		else dr_fprintf(f, "\tInto "PFX" %s:!??\n", target_addr, modname2);
		);

	call_address = instr_addr;
	return_address = instr_addr + length;
	data->into_address = target_addr;

	if(call_type == CALL_UNDEFINED){
		call_routine_entry *e;
		e = (call_routine_entry*)hashtable_lookup(&call_routine_table, target_addr);
		if(e!= NULL){
			call_type = e->rule.call_type;
			call_address = instr_addr;
			return_address = instr_addr + length;
			buffer_idx = e->rule.buffer_id;
			size_id = e->rule.size_id;
			read_size_id = e->rule.read_size_id;
			read_size_ref = e->rule.read_size_is_reference;
			succeed_return_status = e->rule.succeed_return_status;

			dr_fprintf(f,	"-----------------Thread %d-----------------------\n"
							PFX" call %s:!%s "PFX " and return "PFX"\n"
							"-------------------------------------------\n", 
							data->thread_id, 
							instr_addr, e->modname, e->function, target_addr, return_address);
		}

		if(call_type == CALL_TAINTED_NORMAL_BUFFER ||
			call_type == CALL_TAINTED_NETWORK_BUFFER){
			app_pc boffset, soffset;
			size_t size;

			boffset = (app_pc)mc.esp+(buffer_idx-1)*4;
			soffset = (app_pc)mc.esp+(size_id-1)*4;
			read_size_offset = (app_pc)mc.esp+(read_size_id-1)*4;

			dr_safe_read(boffset, 4, &read_buffer, &size);
			dr_fprintf(f, "[In] Buffer address "PFX"\n", read_buffer);

			dr_safe_read(soffset, 4, &read_size, &size);
			dr_fprintf(f, "[In] Buffer size "PFX"\n", read_size);
		} else if(call_type == CALL_ALLOCATE_HEAP){
			dr_safe_read((app_pc)mc.esp+(size_id-1)*4, 4, &read_size, NULL);
			dr_fprintf(f, "[In] Allocate size "PFX"\n", read_size);
		} else if(call_type == CALL_REALLOCATE_HEAP){
			dr_safe_read((app_pc)mc.esp+(buffer_idx-1)*4, 4, &read_buffer, NULL);
			dr_fprintf(f, "[In] Original address "PFX"\n", read_buffer);

			app_pc heapHandle;
			dr_safe_read((app_pc)mc.esp+(buffer_idx-1-2)*4, 4, &heapHandle, NULL);
			read_size = HeapSize(heapHandle, 0, read_buffer);
			dr_fprintf(f, "[In] Original size "PFX"\n", read_size);
			
			dr_safe_read((app_pc)mc.esp+(read_size_id-1)*4, 4, &read_size_ref, NULL);
			dr_fprintf(f, "[In] ReAllocate size "PFX"\n", read_size_ref);
		} else if(call_type == CALL_FREE_HEAP){
			dr_safe_read((app_pc)mc.esp+(buffer_idx-1)*4, 4, &read_buffer, NULL);
			dr_fprintf(f, "[In] Free address "PFX"\n", read_buffer);
			
			app_pc heapHandle;
			dr_safe_read((app_pc)mc.esp+(buffer_idx-1-2)*4, 4, &heapHandle, NULL);
			read_size = HeapSize(heapHandle, 0, read_buffer);
			dr_fprintf(f, "[In] Free size "PFX"\n", read_size);
		}
	}
}

static void
at_return(app_pc instr_addr, app_pc target_addr)
{
	void* drcontext = dr_get_current_drcontext();
#ifndef USE_DRMGR
	thread_data* data = (thread_data*)dr_get_tls_field(drcontext);
#else
	thread_data* data = (thread_data*)drmgr_get_tls_field(drcontext, tls_index);
#endif
	api_call_type& call_type = data->call_type;

	if(call_type) 
	{
		if(data->return_address == target_addr)
		{
			dr_mcontext_t mc = {sizeof(mc),DR_MC_ALL};
			dr_get_mcontext(drcontext, &mc);
			taint_seed(target_addr, drcontext, &mc);
		}
		return;
	}

	file_t f = data->f;
	function_tables& funcs = data->funcs;
	memory_list& taint_memory = data->taint_memory;
	memory_list& stack_memory = data->taint_memory_stack;
	dr_mcontext_t mc = {sizeof(mc),DR_MC_ALL};
	dr_get_mcontext(drcontext, &mc);

	CONSTRUCT_INSTR_BEGIN(instr_addr, drcontext);
	print_instr(drcontext, f, &instr, instr_addr);
	CONSTRUCT_INSTR_END(drcontext);
		
	if(process_stack_shrink(taint_memory, stack_memory, data->stack_top, (app_pc)mc.esp))
	{
		ELOGF(SHOW_SHADOW_MEMORY, f, "[-] at_return "PFX"-"PFX"\n", data->stack_top, (app_pc)mc.esp);

		LOG_MEMORY_LIST("[-] global_memory", f, taint_memory);
		LOG_MEMORY_LIST("[-] stack_memory", f, stack_memory);
	}

	char modname1[MAX_SYM_RESULT], func1[MAX_SYM_RESULT];
	char modname2[MAX_SYM_RESULT], func2[MAX_SYM_RESULT];
	int t1 = lookup_symbols_by_pc(instr_addr, modname1, func1, MAX_SYM_RESULT);
	int t2 = lookup_symbols_by_pc(target_addr, modname2, func2, MAX_SYM_RESULT);
	DOLOG(SHOW_SYM,
		if(t1 < 0)	dr_fprintf(f, "[RETURN @ ] "PFX" unknown ??:0\n", instr_addr);
		else if(t1 > 0) dr_fprintf(f, "[CALL @ ] "PFX" %s:!%s\n", instr_addr, modname1, func1);
		else dr_fprintf(f, "[RETURN @ ] "PFX" %s:!??\n", instr_addr, modname1);

		if(t2 < 0)	dr_fprintf(f, "\tInto "PFX" unknown ??:0\n", target_addr);
		else if(t2 > 0) dr_fprintf(f, "\tInto "PFX" %s:!%s\n", target_addr, modname2, func2);
		else dr_fprintf(f, "\tInto "PFX" %s:!??\n", target_addr, modname2);
		);


	if(call_type == CALL_UNDEFINED)
	{
		print_function_tables(f, "Leaving\t", funcs);
		
		//从内部跳转到外部白名单dll,啥事情都不做
		if(within_whitelist(instr_addr) == false && within_whitelist(target_addr) == true)
			;

		else
			funcs.pop_back();

		print_function_tables(f, "Return\t", funcs);
	}
}


static void
at_jmp(app_pc instr_addr, app_pc target_addr)
{
	void* drcontext = dr_get_current_drcontext();
#ifndef USE_DRMGR
	thread_data* data = (thread_data*)dr_get_tls_field(drcontext);
#else
	thread_data* data = (thread_data*)drmgr_get_tls_field(drcontext, tls_index);
#endif
	api_call_type& call_type = data->call_type;

	if(call_type) return;

	file_t f = data->f;

	CONSTRUCT_INSTR_BEGIN(instr_addr, drcontext);
	print_instr(drcontext, f, &instr, instr_addr);
	CONSTRUCT_INSTR_END(drcontext);

	char modname1[MAX_SYM_RESULT], func1[MAX_SYM_RESULT];
	char modname2[MAX_SYM_RESULT], func2[MAX_SYM_RESULT];
	int t1 = lookup_symbols_by_pc(instr_addr, modname1, func1, MAX_SYM_RESULT);
	int t2 = lookup_symbols_by_pc(target_addr, modname2, func2, MAX_SYM_RESULT);

	DOLOG(SHOW_SYM,
		if(t1 < 0)	dr_fprintf(f, "[JMP @ ] "PFX" unknown ??:0\n", instr_addr);
		else if(t1 > 0) dr_fprintf(f, "[JMP @ ] "PFX" %s:!%s\n", instr_addr, modname1, func1);
		else dr_fprintf(f, "[JMP @ ] "PFX" %s:!??\n", instr_addr, modname1);

		if(t2 < 0)	dr_fprintf(f, "\tInto "PFX" unknown ??:0\n", target_addr);
		else if(t2 > 0) dr_fprintf(f, "\tInto "PFX" %s:!%s\n", target_addr, modname2, func2);
		else dr_fprintf(f, "\tInto "PFX" %s:!??\n", target_addr, modname2);
		);

	//if(skip_list.at(instr_addr) == skip_list.at(target_addr))
	{
		data->funcs.pop_back();
		data->funcs.push_back(func2);
	} 
	//else if(within_whitelist(target_addr)){
	//	data->funcs.pop_back();
	//}
	print_function_tables(f, "JmpTo\t", data->funcs);
}

static void 
at_jmp_ind(app_pc instr_addr, app_pc target_addr)
{
	void* drcontext = dr_get_current_drcontext();
#ifndef USE_DRMGR
	thread_data* data = (thread_data*)dr_get_tls_field(drcontext);
#else
	thread_data* data = (thread_data*)drmgr_get_tls_field(drcontext, tls_index);
#endif
	api_call_type& call_type = data->call_type;

	if(call_type) return;

	file_t f = data->f;
	
	CONSTRUCT_INSTR_BEGIN(instr_addr, drcontext);
	print_instr(drcontext, f, &instr, instr_addr);
	CONSTRUCT_INSTR_END(drcontext);

	char modname1[MAX_SYM_RESULT], func1[MAX_SYM_RESULT];
	char modname2[MAX_SYM_RESULT], func2[MAX_SYM_RESULT];
	int t1 = lookup_symbols_by_pc(instr_addr, modname1, func1, MAX_SYM_RESULT);
	int t2 = lookup_symbols_by_pc(target_addr, modname2, func2, MAX_SYM_RESULT);
	DOLOG(SHOW_SYM,
		if(t1 < 0)	dr_fprintf(f, "[JMPInd @ ] "PFX" unknown ??:0\n", instr_addr);
		else if(t1 > 0) dr_fprintf(f, "[JMPInd @ ] "PFX" %s:!%s\n", instr_addr, modname1, func1);
		else dr_fprintf(f, "[JMPInd @ ] "PFX" %s:!??\n", instr_addr, modname1);

		if(t2 < 0)	dr_fprintf(f, "\tInto "PFX" unknown ??:0\n", target_addr);
		else if(t2 > 0) dr_fprintf(f, "\tInto "PFX" %s:!%s\n", target_addr, modname2, func2);
		else dr_fprintf(f, "\tInto "PFX" %s:!??\n", target_addr, modname2);
		);
	
	if(within_whitelist(target_addr)|| data->return_address == target_addr) 
	{
		data->funcs.pop_back();
		print_function_tables(f, "FixIt\t", data->funcs);
	}
}

static void 
at_others(app_pc pc)
{
	void* drcontext = dr_get_current_drcontext();
#ifndef USE_DRMGR
	thread_data* data = (thread_data*)dr_get_tls_field(drcontext);
#else
	thread_data* data = (thread_data*)drmgr_get_tls_field(drcontext, tls_index);
#endif
	api_call_type& call_type = data->call_type;

	if(call_type) return;

	file_t f = data->f;

	CONSTRUCT_INSTR_BEGIN(pc, drcontext);
	print_instr(drcontext, f, &instr, pc);
	CONSTRUCT_INSTR_END(drcontext);
}

#ifndef USE_DRMGR
static dr_emit_flags_t
event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
                  bool for_trace, bool translating)
{
    instr_t *instr;
	int instr_count = 0;
	thread_data* data = (thread_data*)dr_get_tls_field(drcontext);
	int& block_cnt = data->instr_count;
	file_t f = data->f;
	dr_mcontext_t mc = {sizeof(mc),DR_MC_ALL};
	dr_get_mcontext(drcontext, &mc);
	block_cnt ++;
	int insert_count = 0;

	if(data->stack_bottom == 0)
	{
		data->stack_bottom = (app_pc)mc.ebp;
		data->stack_top = (app_pc)mc.esp;
	}

	//如果没有调用可疑函数，则可以直接跳过白名单
	if(data->call_type == CALL_UNDEFINED && within_whitelist((app_pc)tag))
		return DR_EMIT_DEFAULT;

	//正在调用了可疑函数，可以从两个地方获取函数返回结果
	//1 .在该函数return时候
	//2. 在basic block开始处检测
	if(data->call_type)
	{
		if(data->return_address == (app_pc)tag)
			taint_seed((app_pc)tag, drcontext, &mc);
		else if(!instr_is_return(instrlist_last(bb)))
			return DR_EMIT_DEFAULT;
	}
	
	for (instr = instrlist_first(bb); instr != NULL; instr = instr_get_next(instr))
		instr_count++;
	
	dr_fprintf(f, "\nin dr_basic_block #%d (tag="PFX") esp="PFX" instr_count=%d\n", 
			block_cnt, tag, mc.esp, instr_count);

	for (instr = instrlist_first(bb); instr != NULL; instr =  instr_get_next(instr)) {
		int opcode = instr_get_opcode(instr);
		if(opcode == OP_INVALID)	continue;

		 /* instrument calls and returns  */
        if (instr_is_call_direct(instr)) {
			dr_insert_call_instrumentation(drcontext, bb, instr, at_call);
        } else if (instr_is_call_indirect(instr)) {
            dr_insert_mbr_instrumentation(drcontext, bb, instr, at_call, SPILL_SLOT_1);
        } else if (instr_is_return(instr)) {
            dr_insert_mbr_instrumentation(drcontext, bb, instr, at_return, SPILL_SLOT_1);
        } else if (instr_is_ubr(instr)) {
            dr_insert_ubr_instrumentation(drcontext, bb, instr, (app_pc)at_jmp);	
		} else if(opcode == OP_jmp_ind || opcode == OP_jmp_far_ind){
			dr_insert_mbr_instrumentation(drcontext, bb, instr, at_jmp_ind, SPILL_SLOT_1);
		} else if(opc_is_move(opcode) || opc_is_pop(opcode) || opcode_is_arith(opcode)){
			dr_insert_clean_call(drcontext, bb, instr, taint_propagation, false, 1, 
				OPND_CREATE_INTPTR(instr_get_app_pc(instr)));
		} else {
			insert_count --;
			//dr_insert_clean_call(drcontext, bb, instr, at_others, false, 1, 
			//		OPND_CREATE_INTPTR(instr_get_app_pc(instr)));
		}

		if(++insert_count >= MAX_CLEAN_INSTR_COUNT) break;
    }

    //dr_mutex_lock(stats_mutex);
    //dr_mutex_unlock(stats_mutex);

    return DR_EMIT_DEFAULT;
}
#else
typedef struct shared_data_t
{
	int skip;
	int insert_count;
}shared_data;

static dr_emit_flags_t
event_bb_app2app(void *drcontext, void *tag, instrlist_t *bb,
                 bool for_trace, bool translating, OUT void **user_data)
{
	shared_data* sd = (shared_data*)dr_thread_alloc(drcontext, sizeof(*sd));
    memset(sd, 0, sizeof(*sd));
    *user_data = (void *)sd;

    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb,
                  bool for_trace, bool translating, void *user_data)
{
	thread_data* data = (thread_data*)drmgr_get_tls_field(drcontext, tls_index);
	shared_data *sd = (shared_data *) user_data;
	instr_t *instr;
	int instr_count = 0;
	int& block_cnt = data->instr_count;
	file_t f = data->f;
	dr_mcontext_t mc = {sizeof(mc),DR_MC_ALL};
	dr_get_mcontext(drcontext, &mc);
	block_cnt ++;

	if(data->stack_bottom == 0)
	{
		data->stack_bottom = (app_pc)mc.ebp;
		data->stack_top = (app_pc)mc.esp;
	}

	//如果没有调用可疑函数，则可以直接跳过白名单
	if(data->call_type == CALL_UNDEFINED && within_whitelist((app_pc)tag))
	{
		sd->skip = 1;
		return DR_EMIT_DEFAULT;
	}

	//正在调用了可疑函数，可以从两个地方获取函数返回结果
	//1 .在该函数return时候
	//2. 在basic block开始处检测
	if(data->call_type)
	{
		if(data->return_address == (app_pc)tag)
			taint_seed((app_pc)tag, drcontext, &mc);
		else if(!instr_is_return(instrlist_last(bb)))
		{
			sd->skip = 1;
			return DR_EMIT_DEFAULT;
		}
	}

	app_pc pc = (app_pc)tag;
	for (instr = instrlist_first(bb); instr != NULL; instr = instr_get_next(instr))
	{
		if(pc != instr_get_app_pc(instr))
			sd->skip = 1;
		instr_count++;
		pc += instr_length(drcontext, instr);
	}
	
	dr_fprintf(f, "\nin dr_basic_block #%d (tag="PFX") esp="PFX" instr_count=%d\n", 
			block_cnt, tag, mc.esp, instr_count);

	return DR_EMIT_DEFAULT;
}

/* event_bb_insert calls instrument_mem to instrument every
 * application memory reference.
 */
static dr_emit_flags_t
event_bb_insert(void *drcontext, void *tag, instrlist_t *bb,
                instr_t *instr, bool for_trace, bool translating,
                void *user_data)
{
	shared_data *sd = (shared_data *) user_data;
	int& insert_count = sd->insert_count;
	app_pc pc = instr_get_app_pc(instr);
	//thread_data* data = (thread_data*)drmgr_get_tls_field(drcontext, tls_index);
	//dr_fprintf(data->f, "(tag="PFX") pc="PFX"\n", tag, pc);
	//return DR_EMIT_DEFAULT;	
	
	if(pc == 0 || sd->skip == 1 || insert_count >= MAX_CLEAN_INSTR_COUNT)
		return DR_EMIT_DEFAULT;

	int opcode = instr_get_opcode(instr);
	if(opcode == OP_INVALID)	
		return DR_EMIT_DEFAULT;
	
	if (instr_is_call_direct(instr)) {
		dr_insert_call_instrumentation(drcontext, bb, instr, at_call);
    } else if (instr_is_call_indirect(instr)) {
        dr_insert_mbr_instrumentation(drcontext, bb, instr, at_call, SPILL_SLOT_1);
    } else if (instr_is_return(instr)) {
        dr_insert_mbr_instrumentation(drcontext, bb, instr, at_return, SPILL_SLOT_1);
    } else if (instr_is_ubr(instr)) {
        dr_insert_ubr_instrumentation(drcontext, bb, instr, (app_pc)at_jmp);	
	} else if(opcode == OP_jmp_ind || opcode == OP_jmp_far_ind){
		dr_insert_mbr_instrumentation(drcontext, bb, instr, at_jmp_ind, SPILL_SLOT_1);
	} else if(opc_is_move(opcode) || opc_is_pop(opcode) || opcode_is_arith(opcode)){
		dr_insert_clean_call(drcontext, bb, instr, taint_propagation, false, 1, 
			OPND_CREATE_INTPTR(instr_get_app_pc(instr)));
	} else {
		insert_count --;
		//dr_insert_clean_call(drcontext, bb, instr, at_others, false, 1, 
		//		OPND_CREATE_INTPTR(instr_get_app_pc(instr)));
	}
	++insert_count;

    return DR_EMIT_DEFAULT;	
}

static dr_emit_flags_t
event_bb_instru2instru(void *drcontext, void *tag, instrlist_t *bb,
                              bool for_trace, bool translating, void *user_data)
{
	shared_data *sd = (shared_data *) user_data;
	dr_thread_free(drcontext, sd, sizeof(*sd));
	return DR_EMIT_DEFAULT;
}
#endif

static void
module_is_libc(const module_data_t *mod, bool *is_libc, bool *is_libcpp, bool *is_debug)
{
    const char *modname = dr_module_preferred_name(mod);
    *is_debug = false;
    *is_libc = false;
    *is_libcpp = false;
    if (modname != NULL) {
#ifdef LINUX
        if (text_matches_pattern(modname, "libc*", false))
            *is_libc = true;
#else
        if (text_matches_pattern(modname, "msvcr*.dll", true/*ignore case*/)) {
            *is_libc = true;
            if (text_matches_pattern(modname, "msvcr*d.dll", true/*ignore case*/))
                *is_debug = true;
        } else if (text_matches_pattern(modname, "msvcp*.dll", true/*ignore case*/)) {
            *is_libcpp = true;
            if (text_matches_pattern(modname, "msvcp*d.dll", true/*ignore case*/))
                *is_debug = true;
        }
#endif
    }
}

static void 
event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
	const char *name = dr_module_preferred_name(info);
	bool search_syms = true;
	bool is_libc, is_libcpp, is_debug;
    module_is_libc(info, &is_libc, &is_libcpp, &is_debug);

	dr_fprintf(f_global, "\nmodule load event: \"%s\" "PFX"-"PFX" %s\n",
		name, info->start, info->end, info->full_path);

	if (name != NULL && 
		(strcmp(name, DYNAMORIO_LIBNAME) == 0 || strcmp(name, DRMEMORY_LIBNAME) == 0))
		 search_syms = false;

	if(search_syms){
		for(int i = 0; i < CALL_RULES_NUM; i++){
			if(dr_get_main_module()->start == info->start || 
				text_matches_any_pattern(name, rules[i].modname, true)){
					app_pc pc = lookup_symbol(info, rules[i].function);
					if(pc == NULL) continue;
					
					call_routine_entry* e = (call_routine_entry *)dr_global_alloc(sizeof(*e));
					e->pc = pc;
					e->mod = info;
					e->modname = _strdup(name);
					e->function = _strdup(rules[i].function);
					memcpy(&e->rule, &rules[i], sizeof(rules[i]));
					hashtable_add(&call_routine_table, (void *)pc, (void *)e);
					dr_fprintf(f_global, "%s!%s "PFX"\n", name, rules[i].function, pc);
			}
		}
	}
#ifdef USE_DRMGR
	replace_module_load(drcontext, info, loaded);
#endif

	for(int i = 0; i < sizeof(black_dll)/sizeof(black_dll[0]); i++)
	{
		if(text_matches_any_pattern(name, black_dll[i], true))
		{
			dr_fprintf(f_global, "couldnot skip this module\n");
			return;
		}
	}

	if(text_matches_any_pattern(info->full_path, whitelist_lib, true))
	{
		dr_fprintf(f_global, "lib_whitelist module %s\n", info->names.module_name);
		skip_list.insert(range(info->start, info->end));
	}
	else
	{
		for(int i = 0; i < sizeof(white_dll)/sizeof(white_dll[0]); i++)
		{
			if(_stricmp(white_dll[i], name) == 0)
			{
				dr_fprintf(f_global, "whitelist module %s\n", name);
				skip_list.insert(range(info->start, info->end));
				break;
			}
		}
	}
}

static void
event_thread_init(void *drcontext)
{
	int id = dr_get_thread_id(drcontext);
    file_t f = create_thread_logfile(drcontext);
	thread_data* data = new thread_data();

	memset(data, 0, (byte*)data->taint_regs-(byte*)data);
	memset(data->taint_regs, 0, sizeof(data->taint_regs));
	data->f = f;
	data->thread_id = id;

#ifdef WINDOWS
	TEB* teb = get_TEB_from_tid(id);
	data->stack_bottom = (app_pc)teb->StackBase;
	data->stack_top = (app_pc)teb->StackLimit;
	dr_fprintf(f_global, "stack is "PFX"-"PFX"\n", data->stack_bottom, data->stack_top);
	dr_fprintf(f, "stack is "PFX"-"PFX"\n", data->stack_bottom, data->stack_top);
#else
	data->stack_bottom = 0;
	data->stack_top = 0;
#endif

    /* store it in the slot provided in the drcontext */
#ifndef USE_DRMGR
	dr_set_tls_field(drcontext, data);
#else
	drmgr_set_tls_field(drcontext, tls_index, data);
#endif
}

static void
event_thread_exit(void *drcontext)
{
#ifndef USE_DRMGR
    thread_data* data = (thread_data*)dr_get_tls_field(drcontext);
#else
	thread_data* data = (thread_data*)drmgr_get_tls_field(drcontext, tls_index);
#endif
	file_t f = data->f;

	for(memory_list::iterator it = data->taint_memory.begin();
		it != data->taint_memory.end(); it++)
		dr_fprintf(f, PFX"-"PFX" Size:%d\n", it->start, it->end, it->end-it->start);

	dr_fprintf(f, "---- log end for thread %d ----\n", data->thread_id);
	close_file(f);

	delete data;
}

static void 
event_exit(void)
{
    dr_mutex_destroy(stats_mutex);

	dr_fprintf(f_global, "====== log end ======\n");
	close_file(f_global);
}

DR_EXPORT void 
dr_init(client_id_t id)
{
    const char* opstr;
	module_data_t *data;

	client_id = my_id = id;
	process_options(opstr = dr_get_options(my_id));
	appnm = dr_get_application_name();
	stats_mutex = dr_mutex_create();

#ifdef WINDOWS
	TEB* teb = get_TEB();
    data = dr_lookup_module((byte*)teb->ProcessEnvironmentBlock->ImageBaseAddress);
#else
    if (appnm == NULL)
        data = NULL;
    else
        data = dr_lookup_module_by_name(appnm);
#endif
    if (data) {
        app_base = data->start;
        app_end = data->end;
        dr_snprintf(app_path, BUFFER_SIZE_ELEMENTS(app_path), data->full_path);
        NULL_TERMINATE_BUFFER(app_path);
        dr_free_module_data(data);
    }

	create_f_globalfile(logsubdir);

	dr_fprintf(f_global, "options are \"%s\"\n", opstr);
	dr_fprintf(f_global, "executable \"%s\" is "PFX"-"PFX"\n", app_path, app_base, app_end);
	dr_fprintf(f_global, "verbose is "PFX"\n", verbose);

#ifdef USE_DRMGR
	drmgr_init();
	drwrap_init();
	tls_index = drmgr_register_tls_field();
#endif

	if (drsym_init(IF_WINDOWS_ELSE(NULL, 0)) != DRSYM_SUCCESS) {
        LOG(1, "WARNING: unable to initialize symbol translation\n");
    }
    dr_enable_console_printing();

	dr_register_exit_event(event_exit);

#ifdef USE_DRMGR
	drmgr_priority_t priority = {sizeof(priority), "taintcheck", NULL, NULL, 0};
	drmgr_register_bb_instrumentation_ex_event(event_bb_app2app, event_bb_analysis,
		event_bb_insert, event_bb_instru2instru, &priority);
	drmgr_register_module_load_event(event_module_load);
	drmgr_register_thread_init_event(event_thread_init);
	drmgr_register_thread_exit_event(event_thread_exit);
#else
	dr_register_module_load_event(event_module_load);
    dr_register_thread_init_event(event_thread_init);
	dr_register_thread_exit_event(event_thread_exit);
	dr_register_bb_event(event_basic_block);
#endif	

	hashtable_init_ex(&call_routine_table, 8, HASH_INTPTR, false/*!str_dup*/, false/*!synch*/,
					call_routine_entry_free, NULL, NULL);

#ifdef USE_DRMGR
#ifdef WINDOWS
	data = dr_lookup_module_by_name("ntdll.dll");
	if(data)
	{
		ntdll_base = data->start;
		dr_fprintf(f_global, "ntdll_base is "PFX"\n", ntdll_base);
	}
#endif
	replace_init();
#endif
}
