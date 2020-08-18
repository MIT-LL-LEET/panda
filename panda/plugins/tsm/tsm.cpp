
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

#include "osi/osi_types.h"
#include "osi/osi_ext.h"

}

//#include "callstack_instr/callstack_instr.h"
//#include "callstack_instr/callstack_instr_ext.h"

#define TSM_PRE "tsm: "
using namespace std;

extern ram_addr_t ram_size;

typedef uint32_t Taintabel;


struct Thread {
    target_ptr_t pid;
    target_ptr_t tid;
    uint64_t create_time;

    bool operator ==(const Thread &other) const {
        if ((this->pid == other.pid) && (this->tid == other.tid) 
            && (this->create_time == other.create_time))
            return true;
        return false;
    }

    bool operator <(const Thread &other) const {
        if (this->pid < other.pid) return true;
        if (this->pid > other.pid) return false;
        if (this->tid < other.tid) return true;
        if (this->tid > other.tid) return false;
        if (this->create_time < other.create_time) return true;
        return false;
    }

    bool operator >(const Thread &other) const {
        if (this->pid < other.pid) return false;
        if (this->pid > other.pid) return true;
        if (this->tid < other.tid) return false;
        if (this->tid > other.tid) return true;
        if (this->create_time < other.create_time) return false;
        return true;
    }


    friend std::ostream &operator<<(std::ostream &os, const Thread &th) {
        os << "(Thread," << "pid=" << th.pid << ",tid=" << th.tid 
           << "create_time=" << th.create_time << ")";
        return os;
    }
};



struct WriteInfo {
    Thread thread;
    target_ptr_t pc;
    uint64_t instr;
    bool in_kernel;

    bool operator <(const WriteInfo &other) const {
        if (this->thread < other.thread) return true;
        if (this->thread > other.thread) return false;
        if (this->pc < other.pc) return true;
        if (this->pc > other.pc) return false;
        if (this->instr < other.instr) return true;
        if (this->instr > other.instr) return false;
        if (this->in_kernel < other.in_kernel) return true;
        return false;
    }

    friend std::ostream &operator<<(std::ostream &os, const WriteInfo &wi) {
        os << "(WriteInfo," << wi.thread << ",pc=" << hex << wi.pc;
        os << ",instr=" << dec << wi.instr << ",";
        if (wi.in_kernel) os << "kernel";
        else os << "user";
        os  << ")";
        return os;
    }

};


// rename as WriteReadFlow ? 
struct WriteReadFlow {
    Thread src_thread;
    Thread dest_thread;
    target_ptr_t src_pc;
    target_ptr_t dest_pc;
    uint64_t src_instr;
    uint64_t dest_instr;

    bool operator <(const WriteReadFlow &other) const {
        if (this->src_thread < other.src_thread) return true;
        if (this->src_thread > other.src_thread) return false;
        if (this->dest_thread < other.dest_thread) return true;
        if (this->dest_thread > other.dest_thread) return false;
        if (this->src_pc < other.src_pc) return true;
        if (this->src_pc > other.src_pc) return false;
        if (this->dest_pc < other.dest_pc) return true;
        if (this->dest_pc > other.dest_pc) return false;        
        if (this->src_instr > other.src_instr) return false;
        if (this->dest_instr < other.dest_instr) return true;
        return false;
    }

    friend std::ostream &operator<<(std::ostream &os, const WriteReadFlow &wrf) {
        os << "(WriteReadFlow,From(" << wrf.src_thread << ",pc=" << hex << wrf.src_pc 
           << ",instr=" << wrf.src_instr << "),";
        os << "To(" << wrf.dest_thread << ",pc=" << hex << wrf.dest_pc 
           << ",instr=" << wrf.dest_instr << ")";
        return os;
    }

};

struct WriteReadFlowStats {
    uint64_t count;       // number of observations of this flow
    uint64_t min_instr;   // min instr count for this flow
    uint64_t max_instr;   // max instr count for this flow
};


// taint labels map to WriteInfo structs
map<WriteInfo, TaintLabel> wi2l;
map<uint32_t, WriteInfo> l2wi;

// true if we are tracking flows into / out of kernel code points
bool track_kernel = false;

bool summary = false;

// really just indicating if anything has a taint label yet
uint64_t first_taint_instr = 0;

// collect & count flows between src and dest code points
map<WriteReadFlow, uint64_t> flows;

// used to spit out diag msg every 1% of replay
double next_replay_percent = 0.0;

// count flows we observe (not unique)
uint64_t num_flows = 0;

bool debug = false;


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

    target_ulong pc = cpu->panda_guest_pc;

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

    OsiProc *current = NULL;
    GArray *ms = NULL;
    OsiThread *othread = NULL;

    current =  get_current_process(cpu); 
    if (current == NULL || current->pid == 0) 
        goto CLEANUP;
    ms = get_mappings(cpu, current); 
    if (ms == NULL) 
        goto CLEANUP;
    othread = get_current_thread(cpu);
    if (othread == NULL) 
        goto CLEANUP;
    else {
        Thread thread;
        thread.pid = current->pid;
        thread.tid = othread->tid;
        thread.create_time = current->create_time;
        WriteInfo wi;
        wi.thread = thread;
        wi.pc = pc;
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

CLEANUP:
    if (current) free_osiproc(current);
    if (ms) g_array_free(ms, true);
    if (othread) free_osithread(othread);

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

    OsiProc *current = NULL;
    GArray *ms = NULL;
    OsiThread *othread = NULL;

    current =  get_current_process(cpu); 
    if (current == NULL || current->pid == 0) 
        goto CLEANUP;
    ms = get_mappings(cpu, current); 
    if (ms == NULL) 
        goto CLEANUP;
    othread = get_current_thread(cpu);
    if (othread == NULL) 
        goto CLEANUP;
    else {
        
        // collect labels for this read (all bytes)
        all_labels.clear();
        // how many of size bytes about to be read are tainted?
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
        
        if (num_tainted == 0) 
            goto CLEANUP;
        
        Thread read_thread;
        read_thread.pid = current->pid;
        read_thread.tid = othread->tid;
        read_thread.create_time = current->create_time;
        
        // every label observed on this read indicates a flow from a prior labeled write
        for (auto l : all_labels) {
            // there is a flow from write that is label l to this read
            WriteInfo wi = l2wi[l];
            uint64_t read_instr = rr_get_guest_instr_count();
            target_ptr_t read_pc = cpu->panda_guest_pc;
            if (debug) {
                cout << TSM_PRE << " before_load: flow observed from " << wi.thread << " to " << read_thread << "\n";
                cout << TSM_PRE << "    write @ (instr=" << dec << wi.instr << ",pc=" << hex << wi.pc << ")";
                cout << " read @ (instr=" << dec << read_instr << ",pc=" << hex << read_pc << ")\n";
            }
            if (summary) {
                WriteReadFlow wrf = {wi.thread, read_thread, wi.pc, read_pc, wi.instr, read_instr};
                if (flows.count(wrf) == 0) {
                    flows[wrf] = 0;
                }
                flows[wrf] = flows[wrf] + 1;
            }
            else {
                if (pandalog) {
                    Panda__Thread th_src, th_dest;
                    th_src = th_dest = PANDA__THREAD__INIT;
                    th_src.pid = wi.thread.pid;
                    th_src.tid = wi.thread.tid;
                    th_src.create_time = wi.thread.create_time;
                    th_dest.pid = read_thread.pid;
                    th_dest.tid = read_thread.tid;
                    th_dest.create_time = read_thread.create_time;
                    Panda__CodePoint cp_src, cp_dest;
                    cp_src = cp_dest = PANDA__CODE_POINT__INIT;
                    cp_src.thread = &th_src;
                    cp_src.pc = wi.pc;
                    cp_src.instr = wi.instr;
                    cp_dest.thread = &th_dest;
                    cp_dest.pc = read_pc;
                    cp_dest.instr = read_instr;                
                    Panda__WriteReadFlow tf;
                    tf = PANDA__WRITE_READ_FLOW__INIT;
                    tf.src = &cp_src;
                    tf.dest = &cp_dest;
                    Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
                    ple.write_read_flow = &tf;
                    pandalog_write_entry(&ple);                
                }
            }
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

CLEANUP:
    if (current) free_osiproc(current);
    if (ms) g_array_free(ms, true);
    if (othread) free_osithread(othread);

}



bool init_plugin(void *self) {

    panda_require("taint2");
    assert (init_taint2_api());

    panda_require("osi"); 
    assert(init_osi_api());

    panda_arg_list *args = panda_get_args("tsm");

     track_kernel = panda_parse_bool_opt(args, "kernel", "turn on debug output");
     if (track_kernel)
         cout << TSM_PRE << "tracking kernel writes & reads too\n";
     else
         cout << TSM_PRE << "NOT tracking kernel writes & reads\n";
     summary = panda_parse_bool_opt(args, "summary", "summary output");
     if (summary) 
         cout << TSM_PRE << "summary mode is ON\n";
     else
         cout << TSM_PRE << "summary mode is OFF\n";

    panda_cb pcb;

    pcb.before_block_translate = enable_taint;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb);

    pcb.after_store = after_store;
    panda_register_callback(self, PANDA_CB_AFTER_STORE, pcb);

    // to query reads from memory
    pcb.before_load = before_load;
    panda_register_callback(self, PANDA_CB_BEFORE_LOAD, pcb);

    // this will give us accurate pc within a bb
    panda_enable_precise_pc();

    return true;
}



void uninit_plugin(void *) {

    if (summary) {
        Panda__Thread th_src, th_dest;
        th_src = th_dest = PANDA__THREAD__INIT;
        Panda__CodePoint cp_src, cp_dest;
        cp_src = cp_dest = PANDA__CODE_POINT__INIT;
        Panda__WriteReadFlow wrf = PANDA__WRITE_READ_FLOW__INIT;
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        cout << (flows.size()) << " unique flows -- pandalogging\n";
        for (auto kvp : flows) {
            auto flow = kvp.first;
            auto [write_thread, read_thread, write_pc, read_pc, write_instr, read_instr] = flow;
            uint64_t count = kvp.second;
            if (pandalog) {
                th_src.pid = write_thread.pid;
                th_src.tid = write_thread.tid;
                th_src.create_time = write_thread.create_time;
                th_dest.pid = read_thread.pid;
                th_dest.tid = read_thread.tid;
                th_dest.create_time = read_thread.create_time;
                cp_src.thread = &th_src;
                cp_src.pc = write_pc;
                cp_src.instr = write_instr;
                cp_dest.thread = &th_dest;
                cp_dest.pc = read_pc;
                cp_dest.instr = read_instr;               
                wrf.src = &cp_src;
                wrf.dest = &cp_dest;
                wrf.count = count;
                wrf.has_count = true;
                ple.write_read_flow = &wrf;
                pandalog_write_entry(&ple);
            }
            else {
                cout << TSM_PRE << " Flow (count=" << count << " from " << write_thread << " to " << read_thread << "\n";
                cout << TSM_PRE << "    write @ (instr=" << dec << write_instr << ",pc=" << hex << write_pc << ")";
                cout <<            "    read  @ (instr=" << dec << read_instr << ",pc=" << hex << read_pc << ")\n";
            }
        }
    }
}
