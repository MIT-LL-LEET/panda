
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

//#include "callstack_instr/callstack_instr.h"
//#include "callstack_instr/callstack_instr_ext.h"

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
    target_ptr_t src_asid;
    target_ptr_t src_pc;
    target_ptr_t dest_asid;
    target_ptr_t dest_pc;

    bool operator <(const Flow &other) const {
        if (this->src_asid < other.src_asid) return true;
        if (this->src_asid > other.src_asid) return false;
        if (this->src_pc < other.src_pc) return true;
        if (this->src_pc > other.src_pc) return false;
        if (this->dest_asid < other.dest_asid) return true;
        if (this->dest_asid > other.dest_asid) return false;
        if (this->dest_pc < other.dest_pc) return true;
        return false;
    }
};


// taint labels map to WriteInfo structs
map<WriteInfo, TaintLabel> wi2l;
map<uint32_t, WriteInfo> l2wi;

// true if we are tracking flows into / out of kernel code points
bool track_kernel = false;

// really just indicating if anything has a taint label yet
uint64_t first_taint_instr = 0;

// collect & count flows between src and dest code points
map<Flow, uint64_t> flows;

// used to spit out diag msg every 1% of replay
double next_replay_percent = 0.0;

// count flows we observe (not unique)
uint64_t num_flows = 0;

bool debug = true;


// just used to turn on taint, sadly 
void enable_taint(CPUState *cpu, target_ptr_t pc) {
    if (!taint2_enabled()) {
        cout << TSM_PRE << "enabling taint \n";
        taint2_enable_taint();
    }
}


// this will be called semantically just after a store,
// meaning not just after the store has been emulated,
// but *also* after whatever taint has propagated to memory 
void after_store(CPUState *cpu, uint64_t addr, uint64_t data, size_t size, bool isSigned) {
    
    if (!taint2_enabled()) return;
        
    if (!track_kernel)
        if (panda_in_kernel(cpu)) return;

    // coz this is in bits
    size /= 8;

    target_ulong pc = panda_current_pc(cpu);

    if (debug) 
        cout << TSM_PRE << " after_store: Write @ pc=" << hex << pc << " addr=" << addr << " size=" << "size \n";
    
    // obtain data just stored
    int size32max = (size < 32) ? size : 32;
    uint8_t read_buf[32];
    int rv = panda_virtual_memory_read(cpu, addr, read_buf, size32max);
    if (rv == -1) {
        // not there. is that even possible?
        // certainly it means we can't taint anything right?
        if (debug) 
            cout << TSM_PRE << " after_store: Attempt to read " << dec << size32max << " bytes at addr=" << hex << addr << " failed?\n";
        return;
    }
    
    if (debug) {
        cout << TSM_PRE << " after_store: data (first part): [";
        for (int i=0; i<size32max; i++)
            printf ("%02x ", read_buf[i]);
        cout << "]\n";
    }

    WriteInfo wi;
    wi.pc = pc;
    wi.asid = panda_current_asid(cpu);
    wi.in_kernel = panda_in_kernel(cpu);

    TaintLabel l;
    if (wi2l.count(wi) == 0) {
        // l is a new label -- this is first time we've seen this WriteInfo
        l = 1 + wi2l.size();
        wi2l[wi] = l;
        l2wi[l] = wi;
        if (debug) 
            cout << TSM_PRE " after_store: new tsm label l=" << dec << l << " " << wi << "\n";
    }
    else  {
        // old label
        l = wi2l[wi];
    }

    // NB: yes, we just discard / overwrite any existing taint labels on this memory extent
    int num_labeled = 0;
    for (int i=0; i<size; i++) {
        hwaddr pa = panda_virt_to_phys(cpu, addr + i);
        if (pa == (hwaddr)(-1) || pa >= ram_size)
            continue;
        taint2_label_ram(pa, l);
        num_labeled ++;
    }
    if (debug) {
        cout << TSM_PRE << " after_store: labeled " << dec << num_labeled << "\n";
    }

    if (first_taint_instr == 0) {
        first_taint_instr = rr_get_guest_instr_count();
        if (debug) cout << TSM_PRE "first taint instr is " << first_taint_instr << "\n";
    }

}


// used to collect labels in a set
set<TaintLabel> all_labels;

// taint2_labelset_ram_iter  helper
int collect_labels(TaintLabel l, void *stuff) {
    all_labels.insert(l);
    return 0;
}


// this will be called semantically just before a load,
// meaning before emulation of the store and any taint prop
void before_load(CPUState *cpu, uint64_t addr, uint64_t data, size_t size, bool isSigned) {

    if (first_taint_instr == 0)
        // nothing is labeled with taint yet
        return;

    assert (taint2_enabled());

    if (!track_kernel)
        if (panda_in_kernel(cpu)) return;

    // size is in bits
    size /= 8;

    target_ulong pc = panda_current_pc(cpu);

    if (debug) 
        cout << TSM_PRE << " before_load: Read @ pc=" << hex << pc << " addr=" << addr << " size=" << "size \n";

    // obtain data about to be loaded
    int size32max = (size < 32) ? size : 32;
    uint8_t read_buf[32];
    int rv = panda_virtual_memory_read(cpu, addr, read_buf, size32max);
    if (rv == -1) {
        // this means page fault or MMIO?
        // regardless, we bail
        if (debug) 
            cout << TSM_PRE << " before_load: Attempt to read " << dec << size32max << " bytes at addr=" << hex << addr << " failed\n";
        return;
    }

    if (debug) {
        cout << TSM_PRE " before_load: data (first part): [";
        for (int i=0; i<size32max; i++)
            printf ("%02x ", read_buf[i]);
        cout << "]\n";
    }

    // collect labels for this read (all byte)
    all_labels.clear();
    // how many of size bytes are tainted
    int num_tainted = 0;
    for (int i=0; i<size; i++) {
        hwaddr pa = panda_virt_to_phys(cpu, addr + i);
        if (pa == (hwaddr)(-1) || pa >= ram_size) 
            continue;
        if (taint2_query_ram(pa)) {
            taint2_labelset_ram_iter(pa, collect_labels, NULL);
            num_tainted ++;
        }
    }

    if (debug) 
        cout << TSM_PRE << " before_load: num_tainted=" << dec << num_tainted << "\n";

    if (num_tainted == 0) return;

    // every label observed on this read indicates a flow from a prior labeled write
    for (auto l : all_labels) {
        // there is a flow from write that is label l to this read
        target_ptr_t asid = panda_current_asid(cpu);
        WriteInfo wi = l2wi[l];
        Flow f = {wi.asid,wi.pc,asid,pc};
        if (debug) {
            cout << TSM_PRE << " before_load: flow observed from(asid=" << hex << wi.asid << ",pc=" << wi.pc << ")";
            cout << " -> to(asid=" << hex << asid << ",pc=" << pc << ")\n";
        }
        flows[f]++;
        // not unique flows 
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
//        cout << TSM_PRE << "next_replay_percent = " << next_replay_percent << "\n";
    }


}



bool init_plugin(void *self) {

    panda_require("taint2");
    assert (init_taint2_api());

    panda_arg_list *args = panda_get_args("tsm");

     track_kernel = panda_parse_bool_opt(args, "kernel", "turn on debug output");
     if (track_kernel)
         cout << TSM_PRE << "tracking kernel writes & reads too\n";
     else
         cout << TSM_PRE << "NOT tracking kernel writes & reads\n";

    panda_cb pcb;

    pcb.before_block_translate = enable_taint;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb);

    pcb.after_store = after_store;
    panda_register_callback(self, PANDA_CB_AFTER_STORE, pcb);

    // to query reads from memory
    pcb.before_load = before_load;
    panda_register_callback(self, PANDA_CB_BEFORE_LOAD, pcb);

    panda_enable_precise_pc();

    return true;
}



void uninit_plugin(void *) {

    Panda__CodePoint *cp_src  = (Panda__CodePoint *) malloc(sizeof(Panda__CodePoint));
    *cp_src = PANDA__CODE_POINT__INIT;
    Panda__CodePoint *cp_dest  = (Panda__CodePoint *) malloc(sizeof(Panda__CodePoint));
    *cp_dest = PANDA__CODE_POINT__INIT;
    Panda__TaintFlow *tf = (Panda__TaintFlow *) malloc (sizeof(Panda__TaintFlow));
    *tf = PANDA__TAINT_FLOW__INIT;
    for (auto kvp : flows) {
        auto flow = kvp.first;
        if (pandalog) {
            cp_src->asid = flow.src_asid;
            cp_src->pc = flow.src_pc;
            cp_dest->asid = flow.dest_asid;
            cp_dest->pc = flow.dest_pc;
            tf->src = cp_src;
            tf->dest = cp_dest;
            Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
            ple.taint_flow = tf;
            pandalog_write_entry(&ple);
        }
        else {
            cout << TSM_PRE 
                 << " flow src(asid=" << hex << cp_src->asid << ",pc=" << hex << cp_src->pc << ")"
                 << " -> dest(asid=" << hex << cp_dest->asid << ",pc=" << hex << cp_dest->pc << ")\n";
        }
    }
}
