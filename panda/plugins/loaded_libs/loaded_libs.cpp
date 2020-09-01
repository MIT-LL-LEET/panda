#define __STDC_FORMAT_MACROS

#include <cstdio>

#include "panda/plugin.h"

#include "syscalls2/syscalls_ext_typedefs.h"
#include "syscalls2/syscalls2_info.h"
#include "syscalls2/syscalls2_ext.h"

extern "C" {

    bool init_plugin(void *);
    void uninit_plugin(void *);

#include "osi/osi_types.h"
#include "osi/osi_ext.h"
} 


#include<map>
#include<vector> 
#include<set>
#include<iostream>
using namespace std; 

typedef target_ulong Asid;



uint64_t get_libs_count = 0;
uint64_t get_libs_failed_count = 0;

void get_libs(CPUState *env) {

  //  cout << "instr = " << rr_get_guest_instr_count() << "\n";   

    get_libs_count ++;

    bool fail = false;
    OsiProc *current =  get_current_process(env); 
    if (current == NULL) fail=true;
    if (current->pid == 0) fail=true;
    Asid asid = panda_current_asid(env); 
    GArray *ms = get_mappings(env, current); 
    if (ms == NULL) fail=true;
    OsiThread *thread = get_current_thread(env);
    if (thread == NULL) fail=true;

    assert (pandalog);

    Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT; 

    Panda__LoadedLibs *ll = (Panda__LoadedLibs *) malloc (sizeof (Panda__LoadedLibs)); 
    *ll = PANDA__LOADED_LIBS__INIT; 

    if (fail) {
        ll->succeeded = false;
//        cout << "get_libs fails\n";
        ple.asid_libraries = ll;
        pandalog_write_entry(&ple);         
        get_libs_failed_count ++;
    }
    else {
        ll->succeeded = true;
/*
        cout << "instr= " << rr_get_guest_instr_count() << " get_libs works! panda_in_kernel=" << panda_in_kernel(env) 
            << " |mappings| = " << (ms->len)
             << " pid=" << current->pid << " create_time=" << current->create_time 
             << " tid=" << thread->tid << " proc_name=" << current-> name << "\n";
*/
        Panda__Module** m = (Panda__Module **) malloc (sizeof (Panda__Module *) * ms->len);  
        for (int i = 0; i < ms->len; i++) { 
            OsiModule *module = &g_array_index(ms, OsiModule, i); 
            m[i] = (Panda__Module *) malloc (sizeof (Panda__Module)); 
            *(m[i]) = PANDA__MODULE__INIT; 
            m[i]->name = strdup(module->name); 
            if (module->file == 0x0) 
                m[i]->file = strdup("none");
            else 
                m[i]->file = strdup(module->file);
            m[i]->base_addr = module->base; 
            m[i]->size = module->size; 
        }
        ll->modules = m;  
        ll->n_modules = ms->len;
        ll->has_pid = true;
        ll->has_ppid = true;
        ll->has_create_time = true;
        ll->has_tid = true;
        ll->proc_name = strdup(current->name);
        ll->pid = current->pid;
        ll->ppid = current->ppid; 
        ll->create_time = current->create_time;
        ll->tid = thread->tid;
    
        ple.has_asid = true;
        ple.asid = asid;    
        ple.asid_libraries = ll;
        pandalog_write_entry(&ple);         
        
        for (int i=0; i<ms->len; i++) {
            free(m[i]->name);
            free(m[i]->file);
        }
        free(m);
    }

    free(ll);
}



// 9 long sys_mmap(

void mmap_return(CPUState *cpu, target_ulong pc, unsigned long addr, unsigned long length, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long offset) {
    get_libs(cpu);
}


uint64_t bb_count = 0;

void before_block(CPUState *env, TranslationBlock *tb) {

    // check up on module list every 50 bb
    bb_count ++;
    if ((bb_count % 2) == 0) {
        get_libs(env);
    }

}


bool init_plugin(void *self) {
    panda_require("osi"); 
    assert(init_osi_api());
    panda_require("syscalls2");
    
    PPP_REG_CB("syscalls2", on_sys_mmap_return, mmap_return);

    panda_cb pcb;    
    pcb.before_block_exec = before_block;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
  
    return true;
}

void uninit_plugin(void *self) { 

    cout << "get_libs_count = " << get_libs_count << "\n";
    cout << "get_libs_failed_count = " << get_libs_failed_count << "\n";
    cout << "frac = " << ((float) get_libs_failed_count) / get_libs_count << "\n";

}
