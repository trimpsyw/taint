/* **********************************************************
 * Copyright (c) 2013 YAO Wei.  All rights reserved.
 * **********************************************************/


/*Taint analysis 
 * taint2.cpp
 */

#include "dr_api.h"
# include "drsyms.h"

#include <vector>
#include <algorithm>
#include <string>

//#define SHOW_INSTR
//#define SHOW_PROPAGATION
//#define SHOW_FUNCTION_TREE

#ifdef WINDOWS
# define DISPLAY_STRING(msg) dr_messagebox(msg)
# define IF_WINDOWS(x) x
#else
# define DISPLAY_STRING(msg) dr_printf("%s\n", msg);
# define IF_WINDOWS(x) /* nothing */
#endif

const char* white_dll[] = {
	"ntdll.dll", "kernel32.dll", "KERNELBASE.dll", "user32.dll", "msvcrt.dll",
	"gdi32.dll", "shell32.dll",  "ole32.dll", "oleaut32.dll",
	"comdlg32.dll","advapi32.dll", "imm32.dll", "rpcrt4.dll",
	"secur32.dll", "usp10.dll", "shlwapi.dll", "comctl32.dll",
	"UxTheme.dll", "gdiplus.dll", "WINMM.dll", "LPK.dll",
	"WindowsCodecs.dll", "MSCTF.dll", "WinUsb.dll", "SETUPAPI.dll",
	"NSI.dll", "sechost.dll", "DEVOBJ.dll", "CFGMGR32.dll",
	"cryptbase.dll", "normaliz.dll", "version.dll",
	"ws2_32.dll", "netapi32.dll",
	//"msvcr90.dll", "msvcr80.dll", "msvcr70.dll", "msvcr60.dll",
	//"msvcp90.dll", "msvcp80.dll", "msvcp70.dll", "msvcp60.dll",
	"snxhk.dll", "sepro.dll", "360safemonpro.tpi"		//anti-virus
};

struct api_call_rule_t
{
	char module[64];
	char name[64];
	
	int param_count;
	
	int buffer_id;
	
	int size_id:8;
	int size_is_reference:8;

	int read_size_id:8;
	int read_size_is_reference:8;

}rules[] = {
	{"MSVCRT.dll",		"fgets",	3, 1, 2, 0, -1, 0},
	{"Kernel32.dll",	"ReadFile", 5, 2, 3, 0, 4,	1}
};

struct range {
	app_pc start, end;

	range(app_pc start, app_pc end) : start(start),end(end) {}

	range(app_pc pc) : start(pc), end(pc){}

	bool operator<(const range &range) const {
		return (this->start<range.start) | (this->start==range.start && this->end<range.end);
	}
	bool operator>(const range &range) const {
		return (this->start>range.start) | (this->start==range.start && this->end>range.end);
	}
	bool operator==(const range &range) const {
		return (this->start>=range.start && this->end<=range.end);
	}

};

template<class T>
inline bool is_between(const T &low, const T &value, const T &high) {
	return (low<=value && value<=high);
}

template<class T>
inline bool is_between(const T &low, const T &value_low, const T &value_high, const T &high) {
	return (low<=value_low && value_high<=high);
}

class merge_pred {
private:
	bool aggressive;

	inline static bool is_adjacent(const range &left, const range &right) {
		return (left.end==right.start-1);
	}

	inline static bool is_semiadjacent(const range &left, const range &right) {
		return (left.end==right.start-2);
	}

public:
	merge_pred(bool a) : aggressive(a) {}

	bool operator()(range &left, const range &right) const {
		if(
			is_between(left.start, right.start, left.end)
			|| is_adjacent(left, right)
		) {
			left.start=min(left.start, right.start);
			left.end=max(left.end, right.end);
			return true;
		}
		else return false;
	}
};

class memory_list {
public:
	typedef range range_type;
	typedef std::vector<range_type> list_type;
	typedef list_type::size_type size_type;
	typedef list_type::iterator iterator;
	typedef list_type::const_iterator const_iterator;

private:
	list_type _ranges;

	iterator within(app_pc pc, iterator* which = NULL){
		iterator p = _ranges.begin();
		iterator m = _ranges.end();
		int num = _ranges.size();
		app_pc s1, s2;

		while(num > 0)
		{
			m = p + (num >> 1);
			s1 = m->start;
			s2 = m->end;

			if(s1 <= pc && pc <= s2)
				return m;

			if(s1 > pc)		num >>= 1;
			else			{p = m+1, num = (num-1) >> 1;}
		}

		if(which) *which = p;
		return _ranges.end();
	}

	const_iterator within(app_pc pc, const_iterator* which = NULL)const{
		const_iterator p = _ranges.begin();
		const_iterator m = _ranges.end();
		int num = _ranges.size();
		app_pc s1, s2;

		while(num > 0)
		{
			m = p + (num >> 1);
			s1 = m->start;
			s2 = m->end;

			if(s1 <= pc && pc <= s2)
				return m;

			if(s1 > pc)		num >>= 1;
			else			{p = m+1, num = (num-1) >> 1;}
		}

		if(which) *which = p;
		return _ranges.end();
	}

public:
	void insert(const range &r) {
		this->_ranges.push_back(r);
	}

	void insert_sort(const range &r){
		const_iterator which;
		const_iterator it = within(r.start, &which);
		
		if(it == _ranges.end())
			_ranges.insert(which, r);
		else
			_ranges.insert(++it, r);

		iterator here = std::unique(_ranges.begin(), _ranges.end(), merge_pred(true));
		_ranges.erase(here, _ranges.end());
	}

	void optimize(bool aggressive=false){
		std::sort(_ranges.begin(), _ranges.end());
		iterator end = std::unique(_ranges.begin(), _ranges.end(), merge_pred(aggressive));
		if(end != _ranges.end())
			_ranges.erase(end, _ranges.end());
	}

	bool find(app_pc pc){
		if(_ranges.size() == 0) return false;
		return within(pc) != _ranges.end();
	}

	iterator at(app_pc pc){
		return within(pc);
	}
	
	iterator begin() {
		return this->_ranges.begin();
	}
	iterator end() {
		return this->_ranges.end();
	}

	const_iterator begin() const {
		return this->_ranges.begin();
	}
	const_iterator end() const {
		return this->_ranges.end();
	}

	size_type size() const {
		return this->_ranges.size();
	}
	void clear() {
		this->_ranges.clear();
	}

	memory_list() {}
};

typedef std::vector<std::string> function_tables;

typedef struct thread_data_t
{
	file_t f;

	int untrusted_function_calling;
	app_pc call_address, into_address, return_address;
	int buffer_idx;
	int size_id;
	int read_size_id;
	int read_size_ref;
	app_pc read_size_offset;
	app_pc read_buffer;
	int read_size;

	memory_list taint_memory;
	byte taint_regs[DR_REG_INVALID];

	function_tables funcs;
	int enter_function;
	int leave_function;
	std::string this_function; 
}thread_data;

static memory_list skip_list;

static bool
within_whitelist(app_pc pc)
{
	if(skip_list.size() && skip_list.find(pc))
		return true;		
	return false;
}

static void
print_function_tables(file_t f, const char* msg, function_tables& funcs)
{
#ifdef SHOW_FUNCTION_TREE
	dr_fprintf(f, "%s ", msg);
	for(function_tables::iterator it = funcs.begin();
		it != funcs.end(); it++)
		dr_fprintf(f, "%s:", it->c_str());
	dr_fprintf(f, "\n");
#endif
}

static void *stats_mutex; /* for multithread support */
static client_id_t my_id;
static file_t module_log;

static void event_thread_init(void *drcontext);
static void event_thread_exit(void *drcontext);
static void event_exit(void);
static dr_emit_flags_t event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
                                         bool for_trace, bool translating);
static void event_module_load(void *drcontext, const module_data_t *info, bool loaded);


static bool
opcode_is_arith(int opc)
{
    return (opc == OP_add || opc == OP_sub ||
            opc == OP_inc || opc == OP_dec ||
			opc == OP_xor || opc == OP_or || opc == OP_and ||
			opc == OP_mul || opc == OP_div);
}

DR_EXPORT void 
dr_init(client_id_t id)
{
	my_id = id;
    
	stats_mutex = dr_mutex_create();
    
	dr_register_bb_event(event_basic_block);
    dr_register_exit_event(event_exit);
	dr_register_module_load_event(event_module_load);
    dr_register_thread_init_event(event_thread_init);
    dr_register_thread_exit_event(event_thread_exit);

    if (drsym_init(0) != DRSYM_SUCCESS) {
        dr_log(NULL, LOG_ALL, 1, "WARNING: unable to initialize symbol translation\n");
    }

    if (dr_is_notify_on()) 
	{
# ifdef WINDOWS
        /* ask for best-effort printing to cmd window.  must be called in dr_init(). */
        dr_enable_console_printing();
# endif
        dr_fprintf(STDOUT, "Client bbsize is running\n");
    }

	char logname[512];
    char *dirsep;
    int len;
    
	len = dr_snprintf(logname, sizeof(logname)/sizeof(logname[0]),
                      "%s", dr_get_client_path(my_id));
    for (dirsep = logname + len; *dirsep != '/' IF_WINDOWS(&& *dirsep != '\\'); dirsep--)
        DR_ASSERT(dirsep > logname);
    len = dr_snprintf(dirsep + 1,
                      (sizeof(logname)-(dirsep-logname))/sizeof(logname[0]) - 1,
                      "load_module.log");

	module_log = dr_open_file(logname, DR_FILE_WRITE_OVERWRITE);
}

static void 
event_exit(void)
{
    dr_mutex_destroy(stats_mutex);

	if(module_log != INVALID_FILE)	dr_close_file(module_log);
}

static void
print_instr(void* drcontext, file_t f, instr_t* instr, app_pc pc)
{
#ifdef SHOW_INSTR
	int n1 = instr_num_srcs(instr);
	int n2 = instr_num_dsts(instr);

	dr_fprintf(f, PFX" ",  pc);
	instr_disassemble(drcontext, instr, f);
	dr_fprintf(f, "\t[%d, %d]\n",  n1, n2);
#endif
}

# define MAX_SYM_RESULT 256
static int
print_address(file_t f, app_pc addr, const char *prefix, char* function = NULL, int size = 0)
{
    drsym_info_t sym;
    char name[MAX_SYM_RESULT];
    char file[MAXIMUM_PATH];
	module_data_t *data;
	function = (function == NULL) ? name : function;
	size = (size == 0) ? MAX_SYM_RESULT : size;

    data = dr_lookup_module(addr);
    if (data == NULL) {
        dr_fprintf(f, "%s "PFX" unknown ??:0\n", prefix, addr);
		strcpy(function, "unknown");
        return 0;
    }
    sym.struct_size = sizeof(sym);
    sym.name = function;
    sym.name_size = size;
    sym.file = file;
    sym.file_size = MAXIMUM_PATH;

	drsym_error_t symres;
    symres = drsym_lookup_address(data->full_path, addr - data->start, &sym,
                                DRSYM_DEFAULT_FLAGS);

    const char *modname = dr_module_preferred_name(data);
    if (modname == NULL)
        modname = "<noname>";
    
	if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {

        dr_fprintf(f, "%s "PFX" %s:%s", prefix, addr, modname, sym.name);

        if (symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
            dr_fprintf(f, " ??:0\n");
        } else {
            dr_fprintf(f, " %s:%"UINT64_FORMAT_CODE"+"PIFX"\n",
                       sym.file, sym.line, sym.line_offs);
        }
	} else {
		sprintf(function, "%x", addr);
		dr_fprintf(f, "%s "PFX" %s:%s ??:0\n", prefix, addr, modname, function);
	}

    dr_free_module_data(data);
	return 1;
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

static int
taint_alert(instr_t* instr, app_pc target_addr, void* drcontext, dr_mcontext_t *mc)
{
	thread_data* data = (thread_data*)dr_get_tls_field(drcontext);
	file_t f = data->f;
	byte* taint_regs = data->taint_regs;
	memory_list& taint_memory = data->taint_memory;

	int num = instr_num_srcs(instr);
	reg_t taint_reg = 0;
	app_pc taint_addr = 0;
	bool is_taint = false;
	int type;

	for(int i = 0; i < num; i++)
	{
		opnd_t src_opnd = instr_get_src(instr, i);		
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

		//DISPLAY_STRING(msg);
		dr_fprintf(f, msg);
	}

	return is_taint;
}

static void
at_call(app_pc instr_addr, app_pc target_addr)
{
	void* drcontext = dr_get_current_drcontext();
	thread_data* data = (thread_data*)dr_get_tls_field(drcontext);
	int& untrusted_function_calling = data->untrusted_function_calling;

	if(untrusted_function_calling) return;

	file_t f = data->f;
	app_pc& call_address = data->call_address;
	app_pc& return_address = data->return_address;
	int& buffer_idx = data->buffer_idx;
	int& size_id = data->size_id;
	int& read_size_id = data->read_size_id;
	int& read_size_ref = data->read_size_ref;
	app_pc& read_size_offset = data->read_size_offset;
	app_pc& read_buffer = data->read_buffer;
	int& read_size = data->read_size;
	function_tables& funcs = data->funcs;

    dr_mcontext_t mc = {sizeof(mc),DR_MC_ALL};
    dr_get_mcontext(drcontext, &mc);

	instr_t instr;
	instr_init(drcontext, &instr);
	instr_reuse(drcontext, &instr);
	decode(drcontext, instr_addr, &instr);

	print_instr(drcontext, f, &instr, instr_addr);

	int length = instr_length(drcontext, &instr);

	taint_alert(&instr, target_addr, drcontext, &mc);
	
	instr_free(drcontext, &instr);
    
	print_address(f, instr_addr, "[CALL @ ]");
	print_address(f, target_addr, "\tInto");

	char mod[MAX_SYM_RESULT], func1[MAX_SYM_RESULT], func2[MAX_SYM_RESULT];
	lookup_syms(instr_addr, mod, func1, MAX_SYM_RESULT);
	lookup_syms(target_addr, mod, func2, MAX_SYM_RESULT);
	//data->this_function = func2;
	//data->enter_function = 1;
	//data->leave_function = 0;

	call_address = instr_addr;
	return_address = instr_addr + length;
	data->into_address = target_addr;

	if(untrusted_function_calling == 0){
		for(int j = 0; j < sizeof(rules)/sizeof(struct api_call_rule_t); j++){
			if(_stricmp(func2, rules[j].name) == 0 ){
				untrusted_function_calling = 1;
				call_address = instr_addr;
				return_address = instr_addr + length;
				buffer_idx = rules[j].buffer_id;
				size_id = rules[j].size_id;
				read_size_id = rules[j].read_size_id;
				read_size_ref = rules[j].read_size_is_reference;

				dr_fprintf(f,	"-------------------------------------------\n"
								PFX" call %s:%s "PFX " and return "PFX"\n"
								"-------------------------------------------\n", 
								instr_addr, mod, func2, target_addr, return_address);
				break;
			}
		}
		if(untrusted_function_calling){
			app_pc boffset, soffset;
			size_t size;

			boffset = (app_pc)mc.esp+(buffer_idx-1)*4;
			soffset = (app_pc)mc.esp+(size_id-1)*4;
			read_size_offset = (app_pc)mc.esp+(read_size_id-1)*4;

			dr_safe_read(boffset, 4, &read_buffer, &size);
			dr_fprintf(f, "Buffer address "PFX"\n", read_buffer);

			dr_safe_read(soffset, 4, &read_size, &size);
			dr_fprintf(f, "Buffer size "PFX"\n", read_size);
		} 
	}

	if(untrusted_function_calling == 0)
	{
		if(!within_whitelist(target_addr)){
			/*
			for(int i = funcs.size() - 1; i >= 0; i--){
				if(_stricmp(funcs[i].c_str(), func1) == 0){
					break;
				}
				funcs.pop_back();
			}//*/
			if(funcs.size() == 0)
				funcs.push_back(func1);

			print_function_tables(f, "NowAt\t", funcs);
			funcs.push_back(func2);
			print_function_tables(f, "Call\t", funcs);
		}
	}
}

static void
at_return(app_pc instr_addr, app_pc target_addr)
{
	void* drcontext = dr_get_current_drcontext();
	thread_data* data = (thread_data*)dr_get_tls_field(drcontext);
	int& untrusted_function_calling = data->untrusted_function_calling;

	if(untrusted_function_calling) return;

	file_t f = data->f;
	function_tables& funcs = data->funcs;

	char func1[MAX_SYM_RESULT], func2[MAX_SYM_RESULT];
    print_address(f, instr_addr, "[RETURN @ ]", func1, MAX_SYM_RESULT);
	print_address(f, target_addr, "\tInto", func2, MAX_SYM_RESULT);

	//data->this_function = func1;
	//data->leave_function = 1;
	//data->enter_function = 0;

	if(untrusted_function_calling == 0)
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
	thread_data* data = (thread_data*)dr_get_tls_field(drcontext);
	int& untrusted_function_calling = data->untrusted_function_calling;

	if(untrusted_function_calling) return;

	file_t f = data->f;

	instr_t instr;
	instr_init(drcontext, &instr);
	instr_reuse(drcontext, &instr);
	decode(drcontext, instr_addr, &instr);
	dr_fprintf(f, "opcode %d\n", instr_get_opcode(&instr));
	print_instr(drcontext, f, &instr, instr_addr);
	instr_free(drcontext, &instr);

	char func1[MAX_SYM_RESULT], func2[MAX_SYM_RESULT];
    print_address(f, instr_addr, "JMP @ ", func1, MAX_SYM_RESULT);
    print_address(f, target_addr, "\tInto ", func2, MAX_SYM_RESULT);

	/*if(!within_whitelist(target_addr)){
	} else {
		data->funcs.pop_back();
	}*/
	data->funcs.pop_back();
	data->funcs.push_back(func2);
	print_function_tables(f, "JmpTo\t", data->funcs);
}

static void 
at_jmp_ind(app_pc instr_addr, app_pc target_addr)
{
	void* drcontext = dr_get_current_drcontext();
	thread_data* data = (thread_data*)dr_get_tls_field(drcontext);
	int& untrusted_function_calling = data->untrusted_function_calling;

	if(untrusted_function_calling) return;

	file_t f = data->f;
	
	instr_t instr;
	instr_init(drcontext, &instr);
	instr_reuse(drcontext, &instr);
	decode(drcontext, instr_addr, &instr);

	print_instr(drcontext, f, &instr, instr_addr);
	//dr_fprintf(f, "opcode %d\n", instr_get_opcode(&instr));
	instr_free(drcontext, &instr);

	print_address(f, instr_addr, "JMP Ind @ ");
    print_address(f, target_addr, "\tInto ");
	
	if(within_whitelist(target_addr))// && within_whitelist(instr_addr) == false) 
	{
		data->funcs.pop_back();
		print_function_tables(f, "FixIt\t", data->funcs);
	}
}

static void 
at_others(app_pc pc)
{
	void* drcontext = dr_get_current_drcontext();
	thread_data* data = (thread_data*)dr_get_tls_field(drcontext);
	int& untrusted_function_calling = data->untrusted_function_calling;

	if(untrusted_function_calling) return;

	file_t f = data->f;
	instr_t instr;

	instr_init(drcontext, &instr);
	instr_reuse(drcontext, &instr);
	decode(drcontext, pc, &instr);

	print_instr(drcontext, f, &instr, pc);

	instr_free(drcontext, &instr);
}


static void 
taint_propagation(app_pc pc)
{
	void* drcontext = dr_get_current_drcontext();
	thread_data* data = (thread_data*)dr_get_tls_field(drcontext);
	int& untrusted_function_calling = data->untrusted_function_calling;

	if(untrusted_function_calling) return;

	file_t f = data->f;
	byte* taint_regs = data->taint_regs;
	memory_list& taint_memory = data->taint_memory;
	
    dr_mcontext_t mc = {sizeof(mc),DR_MC_ALL};
    dr_get_mcontext(drcontext, &mc);

	instr_t instr;
	instr_init(drcontext, &instr);
	instr_reuse(drcontext, &instr);
	decode(drcontext, pc, &instr);

	print_instr(drcontext, f, &instr, pc);

	int n1 = instr_num_srcs(&instr);
	int n2 = instr_num_dsts(&instr);
	bool src_tainted = false;
	reg_t taint_reg = 0, tainting_reg = 0;
	app_pc taint_addr = 0, tainting_addr = 0;

#ifdef SHOW_PROPAGATION
	//以下是打印源和目标数
	if(n1 > 0) dr_fprintf(f, "src_opnd(");
	for(int i = 0; i < n1; i++)
	{
		if(i > 0) dr_fprintf(f, ", ");
		opnd_t src_opnd = instr_get_src(&instr, i);
		if(opnd_is_reg(src_opnd))
			dr_fprintf(f, "reg:%d",  opnd_get_reg(src_opnd));
		else if(opnd_is_memory_reference(src_opnd))
			dr_fprintf(f, "mem:0x%08x", opnd_compute_address(src_opnd, &mc));
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
		opnd_t dst_opnd = instr_get_dst(&instr, i);
		if(opnd_is_reg(dst_opnd))
			dr_fprintf(f, "reg:%d",  opnd_get_reg(dst_opnd));
		else if(opnd_is_memory_reference(dst_opnd))
			dr_fprintf(f, "mem:0x%08x", opnd_compute_address(dst_opnd, &mc));
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
#endif

	//以下是污点传播
	if(n1 && n2)
	{
		for(int i = 0; i < n1; i++)
		{
			opnd_t src_opnd = instr_get_src(&instr, i);
			if(opnd_is_reg(src_opnd) && 
				taint_regs[taint_reg = opnd_get_reg(src_opnd)] == 1)
			{
				src_tainted = true;
				break;
			}
			else if(opnd_is_memory_reference(src_opnd) && 
				taint_memory.find(taint_addr = opnd_compute_address(src_opnd, &mc)))
			{
				src_tainted = true;
				break;
			}
			else if(opnd_is_pc(src_opnd) && 
				taint_memory.find(taint_addr = opnd_get_pc(src_opnd)))
			{
				src_tainted = true;
				break;
			}
		}

		if(src_tainted)
		{
			dr_fprintf(f, "\t$$$$ taint ");

			if(taint_addr == 0)
				dr_fprintf(f, "reg:%d ", taint_reg);
			else
				dr_fprintf(f, "mem:0x%08x ", taint_addr);

			opnd_t dst_opnd = instr_get_dst(&instr, 0);
			
			if(opnd_is_reg(dst_opnd))
				taint_regs[tainting_reg = opnd_get_reg(dst_opnd)] = 1;

			else if(opnd_is_memory_reference(dst_opnd))
				taint_memory.insert_sort(tainting_addr = opnd_compute_address(dst_opnd, &mc));
		
			else if(opnd_is_pc(dst_opnd))
				taint_memory.insert_sort(tainting_addr = opnd_get_pc(dst_opnd));

			if(tainting_addr == 0)
				dr_fprintf(f, "---> reg:%d ", tainting_reg);
			else
				dr_fprintf(f, "---> mem:0x%08x ", tainting_addr);

			dr_fprintf(f, " $$$$\n");
		}
	}

	instr_free(drcontext, &instr);
}

static void 
taint_seed(app_pc pc, void* drcontext, dr_mcontext_t* mc)
{
	thread_data* data = (thread_data*)dr_get_tls_field(drcontext);
	int& untrusted_function_calling = data->untrusted_function_calling;
	app_pc& return_address = data->return_address;
	
	if(untrusted_function_calling == 0 || return_address != pc)	
		return;

	file_t f = data->f;
	int& read_size_id = data->read_size_id;
	int& read_size_ref = data->read_size_ref;
	app_pc& read_size_offset = data->read_size_offset;
	app_pc& read_buffer = data->read_buffer;
	int& read_size = data->read_size;
	memory_list& taint_memory = data->taint_memory;
	
	//在返回地址处处理函数调用结果
	app_pc value;
	size_t size;

	dr_fprintf(f, "Function return status "PFX "\n",mc->eax);

	if(read_size_id >= 0)
	{
		if(read_size_id == 0)
			value = (app_pc)mc->eax;
		else
			dr_safe_read(read_size_offset, 4, &value, &size);

		if(read_size_ref)
			dr_safe_read(value, 4, &value, &size);
		
		read_size = (int)value;
	}

	if(mc->eax)
	{
		dr_fprintf(f, "Read Size "PFX"\n", read_size);
		taint_memory.insert_sort(range(read_buffer, read_buffer+read_size));
	}

	untrusted_function_calling = 0;
}

static dr_emit_flags_t
event_basic_block(void *drcontext, void *tag, instrlist_t *bb,
                  bool for_trace, bool translating)
{
    instr_t *instr;
	static int block_cnt = 0;
	int instr_count = 0;
	thread_data* data = (thread_data*)dr_get_tls_field(drcontext);
	file_t f = data->f;
	dr_mcontext_t mc = {sizeof(mc),DR_MC_ALL};
	bool is_return = data->return_address == (app_pc)tag;
	dr_get_mcontext(drcontext, &mc);
	block_cnt ++;

	//跳过白名单
	if(within_whitelist((app_pc)tag))
		return DR_EMIT_DEFAULT;

	//检测到过滤函数调用
	if(data->untrusted_function_calling)
	{
		if(!is_return) //准备调用该函数了，直接该函数内部的一切细节
			return DR_EMIT_DEFAULT;

		taint_seed((app_pc)tag, drcontext, &mc);
	}//*/

	for (instr = instrlist_first(bb); instr != NULL; instr = instr_get_next(instr))
	{
		//dr_print_instr(drcontext, f, instr, NULL);
		instr_count++;
	}
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
		} else if(instr_is_mov(instr) || opcode == OP_lea || opcode == OP_movsx ){
			dr_insert_clean_call(drcontext, bb, instr, taint_propagation, false, 1, 
				OPND_CREATE_INTPTR(instr_get_app_pc(instr)));
		} else if(opcode_is_arith(instr_get_opcode(instr))) {
			dr_insert_clean_call(drcontext, bb, instr, taint_propagation, false, 1, 
				OPND_CREATE_INTPTR(instr_get_app_pc(instr)));
		} else {
			if(instr_count < 100)
				dr_insert_clean_call(drcontext, bb, instr, at_others, false, 1, 
					OPND_CREATE_INTPTR(instr_get_app_pc(instr)));
		}
    }

    //dr_mutex_lock(stats_mutex);
    //dr_mutex_unlock(stats_mutex);

    return DR_EMIT_DEFAULT;
}

static void 
event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
	if(module_log != INVALID_FILE)
	{
		dr_fprintf(module_log, "%s module_load event %s %s %s %s %s "PFX"-"PFX"\n", 
			dr_get_application_name(), info->full_path, info->names.file_name, info->names.exe_name, 
			info->names.module_name, info->names.rsrc_name,
			info->start, info->end);
	}

	for(int i = 0; i < sizeof(white_dll)/sizeof(white_dll[0]); i++)
	{
		if(info->names.module_name &&
			_stricmp(white_dll[i], info->names.module_name) == 0)
		{
			dr_fprintf(module_log, "whitelist module %s\n", info->names.module_name);
			skip_list.insert_sort(range(info->start, info->end));
			break;
		}
	}
}

static void
event_thread_init(void *drcontext)
{
    file_t f;
    char logname[512];
    char *dirsep;
    int len;
    /* We're going to dump our data to a per-thread file.
     * On Windows we need an absolute path so we place it in
     * the same directory as our library. We could also pass
     * in a path and retrieve with dr_get_options().
     */
    len = dr_snprintf(logname, sizeof(logname)/sizeof(logname[0]),
                      "%s", dr_get_client_path(my_id));
    DR_ASSERT(len > 0);
    for (dirsep = logname + len; *dirsep != '/' IF_WINDOWS(&& *dirsep != '\\'); dirsep--)
        DR_ASSERT(dirsep > logname);
    len = dr_snprintf(dirsep + 1,
                      (sizeof(logname)-(dirsep-logname))/sizeof(logname[0]) - 1,
                      "%s-instrs-%d.log", 
					  dr_get_application_name(), 
					  dr_get_thread_id(drcontext)/*0xffff*/);
    DR_ASSERT(len > 0);
    logname[sizeof(logname)/sizeof(logname[0])-1] = '\0';
    f = dr_open_file(logname, DR_FILE_WRITE_OVERWRITE);
    if(f == INVALID_FILE)	
		f = dr_get_stderr_file();

	thread_data* data = new thread_data();
	//(thread_data*)dr_thread_alloc(drcontext, sizeof(thread_data));
	//memset(data, 0, sizeof(thread_data));
	data->f = f;
	data->untrusted_function_calling = 0;
	data->return_address = 0;

    /* store it in the slot provided in the drcontext */
    dr_set_tls_field(drcontext, data);
    dr_log(drcontext, LOG_ALL, 1, 
           "instrcalls: log for thread %d is instrcalls.%03d\n",
           dr_get_thread_id(drcontext), dr_get_thread_id(drcontext));
}

static void
event_thread_exit(void *drcontext)
{
    thread_data* data = (thread_data*)dr_get_tls_field(drcontext);
	file_t f = data->f;

	for(memory_list::iterator it = data->taint_memory.begin();
		it != data->taint_memory.end(); it++)
		dr_fprintf(f, PFX"-"PFX"\n", it->start, it->end);

    dr_close_file(f);

	//dr_thread_free(drcontext, data, sizeof(*data));
	delete data;
}