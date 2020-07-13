
#define __STDC_FORMAT_MACROS

extern "C" {
#include <stdint.h>    
#include <sys/time.h>
#include <sys/resource.h>
}

#include "panda/plugin.h"
#include "taint2/taint2.h"

extern "C" {
#include "taint2/taint2_ext.h"
#include "osi/osi_types.h"
#include "osi/osi_ext.h"
}

#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <set>
#include <stack>

#include <bits/stdc++.h> 

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

    bool init_plugin(void *);
    void uninit_plugin(void *);
    void taint_change(void);

}

#include "callstack_instr/callstack_instr.h"
#include "callstack_instr/callstack_instr_ext.h"

#define TSM_PRE "tsm: "
using namespace std;

extern ram_addr_t ram_size;

typedef uint32_t Taintabel;


struct WriteInfo {
    target_ptr_t asid;
    target_ptr_t pc;
    bool in_kernel;

    // ignore fn name here
    bool operator <(const WriteInfo &other) const { 
        if (this->asid < other.asid) return true;
        if (this->asid > other.asid) return false;
        if (this->pc < other.pc) return true;
        if (this->pc > other.pc) return false;
        if (this->in_kernel < other.in_kernel) return true;
        return false;
    }

    friend std::ostream &operator<<(std::ostream &os, const WriteInfo &wi) {
        os << "(WriteInfo," << hex << "asid=" << wi.asid << ",pc=" << wi.pc;
        os << ",";
        if (wi.in_kernel) os << "kernel";
        else os << "user";
        os  << ")";
        return os;
    }

};


struct Flow {
    TaintLabel src; // label of write source
    target_ptr_t dest_asid; 
    target_ptr_t dest_pc;

    bool operator <(const Flow &other) const {
        if (this->src < other.src) return true;
        if (this->src > other.src) return false;
        if (this->dest_asid < other.dest_asid) return true;
        if (this->dest_asid > other.dest_asid) return false;
        if (this->dest_pc < other.dest_pc) return true;
        return false;
    }
};

    
map<WriteInfo, TaintLabel> wi2l;
map<uint32_t, WriteInfo> l2wi;

target_ptr_t the_asid = 0;
bool track_kernel = false;

uint64_t first_taint_instr = 0;


// count flows between src -> dest
map<Flow, uint64_t> flows;

double next_replay_percent = 0.0;

uint64_t num_flows = 0;


// XXX Need a fast way to do this...
void clear_taint() {
/*
    coutm << "Clearing taint\n";
    for (uint32_t pa=0; pa<ram_size; pa++)
        taint2_delete_ram(pa);
*/
}        


// used to collect labels via iterator
set<TaintLabel> all_labels;

// taint2_labelset_ram_iter  helper
int collect_labels(TaintLabel l, void *stuff) {
    all_labels.insert(l);
    return 0;
}



/*   For every asid change, if new asid is the one we are monitoring,
     collect vector of libraries.  These will be used to convert pc to
     libname/offset on output.  NB: We collect, in sequence, all of the
     module lists osi finds.  Idea is first few and last few are likely
     to be inaccurate. But somewhere in the middle might be good? */

vector<vector<OsiModule>> module_list_lists;

bool asid_changed(CPUState *cpu, target_ulong old_asid, target_ulong new_asid) {

    if (old_asid == the_asid) 
        cout << TSM_PRE "asid_changed: old_asid is the_asid\n";

    if (new_asid == the_asid) 
        cout << TSM_PRE "asid_changed: new_asid is the_asid\n";

    OsiProc *current = get_current_process(cpu);
    if (current->asid != the_asid) return false;

    GArray *ms = get_mappings(cpu, current);
    if (ms == NULL) 
        return false;

    // We are in the right process & we have at least some libs.
    // Time to turn on taint.
    if (!taint2_enabled()) taint2_enable_taint();

    // add another list of modules to the list of lists we
    // are maintaining
    vector<OsiModule> module_list;
    for (int i=0; i<ms->len; i++) {
        OsiModule *m = &g_array_index(ms, OsiModule, i);
        OsiModule mm;
        mm.modd = m->modd;
        mm.base = m->base;
        mm.size = m->size;
        if (m->file)
            mm.file = strdup(m->file);
        else
            mm.file = strdup("Unknown_file");
        if (m->name)
            mm.name = strdup(m->name);
        else
            mm.name = strdup("Unknown_name");
        module_list.push_back(mm);
    }
    module_list_lists.push_back(module_list);

    return false;
}

    

void after_write(CPUState *env, target_ptr_t pc, target_ptr_t addr, size_t size, uint8_t *buf) {
    if (!taint2_enabled()
        || (the_asid !=0 && panda_current_asid(env) != the_asid)
        || (track_kernel && !panda_in_kernel(env))) {         
        return;
    }

    WriteInfo wi;
    wi.pc = pc;
    wi.asid = panda_current_asid(env);
    wi.in_kernel = panda_in_kernel(env);

    TaintLabel l;
    if (wi2l.count(wi) == 0) {
        // new label since this is first time we've seen this WriteInfo
        l = 1 + wi2l.size();
        wi2l[wi] = l;
        l2wi[l] = wi;
        cout << TSM_PRE "New tsm label: " << dec << l << " " << wi << "\n";
    }
    else  {
        // old label
        l = wi2l[wi];
    }

    // NB: yes, we just discard / overwrite any existing taint labels 
    // on this memory exetent
    for (int i=0; i<size; i++) {
        hwaddr pa = panda_virt_to_phys(env, addr + i);
        if (pa == (hwaddr)(-1) || pa >= ram_size)
            continue;
        taint2_label_ram(pa, l);
        if (first_taint_instr == 0) {
            first_taint_instr = rr_get_guest_instr_count();
            cout << TSM_PRE "first taint instr is " << first_taint_instr << "\n";
        }
    }            
}


void before_read(CPUState *env, target_ptr_t pc, target_ptr_t addr, size_t size) {
    if (first_taint_instr == 0 
        || (the_asid !=0 && panda_current_asid(env) != the_asid)
        || (track_kernel && !panda_in_kernel(env))) {         
        return;
    }

    // collect labels for this read
    all_labels.clear();
    for (int i=0; i<size; i++) {
        hwaddr pa = panda_virt_to_phys(env, addr + i);
        if (pa == (hwaddr)(-1) || pa >= ram_size) 
            continue;
        if (taint2_query_ram(pa)) 
            taint2_labelset_ram_iter(pa, collect_labels, NULL);
    }                

    // every label observed on this read indicates a flow from a prior labeled write
    for (auto l : all_labels) {
        // there is a flow from write that is label l to this read
        target_ptr_t asid = panda_current_asid(env);
        Flow f = {l,asid,pc}; 
        flows[f]++;
        num_flows ++;
    }

    double replay_percent = rr_get_percentage();

    if (replay_percent > next_replay_percent) {        
        
        struct rusage rusage;
        getrusage(RUSAGE_SELF, &rusage);
        
        struct timeval* time = &rusage.ru_utime;
        float secs =
            ((float)time->tv_sec * 1000000 + (float)time->tv_usec) /
            1000000.0;

        uint64_t instr = rr_get_guest_instr_count();
        
        cout << TSM_PRE << dec << "replay: " << replay_percent << " instr: " << instr
             << " labels: " << wi2l.size() << " num_flows: " << num_flows 
             << " u_flows: " << flows.size() << hex 
             << " secs: " << dec << secs 
             << " mem_GB: " << rusage.ru_maxrss / 1024.0 / 1024.0
             << "\n";
        
        while (replay_percent > next_replay_percent) 
            next_replay_percent += 1;
        cout << TSM_PRE << "next_replay_percent = " << next_replay_percent << "\n";
    }
    

}



bool init_plugin(void *self) {

    panda_require("taint2");
    assert (init_taint2_api());

    panda_require("callstack_instr");
    assert(init_callstack_instr_api());

    panda_require("osi");
    assert(init_osi_api());
  
    panda_arg_list *args = panda_get_args("tsm");

    const char *asid_s = nullptr;
    asid_s = 
        panda_parse_string_opt(args, "asid", nullptr,
                               "asid of the process for which to build taint semantic map (if missing, all asids will be tracked)");
    
    if (asid_s == nullptr) {
        cout << TSM_PRE << "tracking all asids\n";
        the_asid = 0;
    }
    else {
        the_asid = strtoul(asid_s, NULL, 16);
        cout << TSM_PRE << "tracking only asid = " << hex << the_asid << dec << "\n";
     }
   
     track_kernel = panda_parse_bool_opt(args, "debug", "turn on debug output");
     if (track_kernel) 
         cout << TSM_PRE << "tracking kernel writes & reads too\n";


    panda_cb pcb; 

    // to monitor osi libs for asid of interest
    pcb.asid_changed = asid_changed;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);
    // to label writes to memory
    pcb.virt_mem_after_write = after_write;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_WRITE, pcb);
    // to query reads from memory
    pcb.virt_mem_before_read = before_read;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_READ, pcb);
  

    panda_enable_precise_pc();

    return true;
}


typedef pair<string, uint32_t> CodeOffset;

bool getCodeOffset(target_ptr_t pc, vector<OsiModule> &modules, Panda__CodeOffset *co) {
    for (auto module : modules) {
        if (pc > module.base && pc < (module.base + module.size)) {
            co->name = strdup(module.name);
            co->offset = pc - module.base;
            return true;
        }
    }
    return false;
}

    

// you have a sequence of lists of libraries loaded for the_asid We'll
// choose to believe that the one this far down (temporally) in the
// sequence is correct.  yes, this is horrible.
#define BELIEVE_IT_FRACTION 0.75

void uninit_plugin(void *) {
    size_t nm = module_list_lists.size();
    int b = nm * BELIEVE_IT_FRACTION;
    cout << TSM_PRE << "Collected " << dec << nm << " module lists for asid=" << hex << the_asid << "\n";
    cout << TSM_PRE << dec << "... selecting i=" << b << "\n";
    vector<OsiModule> modules = module_list_lists[b];
    Panda__CodeOffset *co_src  = (Panda__CodeOffset *) malloc(sizeof(Panda__CodeOffset));
    *co_src = PANDA__CODE_OFFSET__INIT;
    Panda__CodeOffset *co_dest  = (Panda__CodeOffset *) malloc(sizeof(Panda__CodeOffset));
    *co_dest = PANDA__CODE_OFFSET__INIT;
    for (auto kvp : flows) {
        auto flow = kvp.first;
        TaintLabel src_label = flow.src;
        target_ptr_t dest_pc = flow.dest_pc;
        bool success = getCodeOffset(dest_pc, modules, co_src);
        if (!success) continue;
        WriteInfo wi = l2wi[src_label];
        target_ptr_t src_pc = wi.pc;
        success = getCodeOffset(src_pc, modules, co_dest);
        if (!success) continue;
        Panda__TaintFlow *tf = (Panda__TaintFlow *) malloc (sizeof(Panda__TaintFlow));
        *tf = PANDA__TAINT_FLOW__INIT;
        tf->src = co_src;
        tf->dest = co_dest;
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        ple.taint_flow = tf;
        pandalog_write_entry(&ple);
    }
}
