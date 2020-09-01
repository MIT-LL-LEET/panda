
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
    target_ptr_t ppid;
    target_ptr_t tid;
    uint64_t create_time;

    bool operator <(const Thread &other) const {
        if (this->pid < other.pid) return true;        
        if (this->pid > other.pid) return false;
        if (this->ppid < other.ppid) return true;
        if (this->ppid > other.ppid) return false;
        if (this->tid < other.tid) return true;
        if (this->tid > other.tid) return false;
        if (this->create_time < other.create_time) return true;
        return false;
    }

    friend std::ostream &operator<<(std::ostream &os, const Thread &th) {
        os << "(Thread," << "pid=" << th.pid << ",ppid=" << th.ppid 
           << ",tid=" << th.tid << "create_time=" << th.create_time << ")";
        return os;
    }
};


// info about a source, either load or store
struct SourceInfo {
    bool isStore;     // true iff source is a store
    Thread thread;
    target_ptr_t pc;
    uint64_t instr;
    bool in_kernel;
    uint64_t value;    // the actual data that was written 
    size_t size;       // size of that data in bytes
    bool isSigned;     // was this a signed store?

    bool operator <(const SourceInfo &other) const {
        if (this->isStore < other.isStore) return true;
        if (this->isStore > other.isStore) return false;
        if (this->thread < other.thread) return true;
        if (other.thread < this->thread) return false;
        if (this->pc < other.pc) return true;
        if (this->pc > other.pc) return false;
        if (this->instr < other.instr) return true;
        if (this->instr > other.instr) return false;
        if (this->in_kernel < other.in_kernel) return true;
        if (this->in_kernel > other.in_kernel) return false;
        if (this->value < other.value) return true;
        if (this->value > other.value) return false;
        if (this->size < other.size) return true;
        if (this->size > other.size) return true;
        if (this->isSigned < other.isSigned) return true;
        return false;
    }

    friend std::ostream &operator<<(std::ostream &os, const SourceInfo &wi) {
        os << "(SourceInfo,isStore=" << wi.isStore << "," << wi.thread 
           << ",pc=" << hex << wi.pc  << ",instr=" << dec << wi.instr
           << ",value=" << hex << wi.value << ",size=" << dec << wi.size
           << ",isSigned=" << wi.isSigned;
        if (wi.in_kernel) os << ",kernel";
        else os << ",user";
        os  << ")";
        return os;
    }

};


struct SourceSink {
    Thread thread;
    uint64_t instr;
    target_ptr_t pc;

    bool operator <(const SourceSink &other) const {
        if (this->thread < other.thread) return true;
        if (other.thread < this->thread) return false;
        if (this->instr < other.instr) return true;
        if (this->instr > other.instr) return false;
        if (this->pc < other.pc) return true;
        return false;
    }

    friend std::ostream &operator<<(std::ostream &os, const SourceSink &ss) {
        os << "(SourceSink,thread=" << ss.thread 
           << ",instr=" << dec << ss.instr
           << ",pc=" << hex << ss.pc << dec << ")";
        return os;
    }
    
};


// A flow, either from store to load 
// or from load (through computation) to store
struct Flow {
    bool sinkIsStore;         // if true then load->store, else store->load
    SourceSink source;
    SourceSink sink;

    bool operator <(const Flow &other) const {
        if (this->sinkIsStore < other.sinkIsStore) return true;
        if (this->sinkIsStore > other.sinkIsStore) return false;
        if (this->source < other.source) return true;
        if (other.source < this->source) return false;
        if (this->sink < other.sink) return true;
        return false;
    }

    friend std::ostream &operator<<(std::ostream &os, const Flow &flow) {
        os << "(Flow,sinkIsStore=" << flow.sinkIsStore 
           <<  ",From=" << flow.source << ",To=" << flow.sink << ")";
        return os;
    }

};



// taint labels: mapping from load/store info to label number and back
map<SourceInfo, TaintLabel> source2label;
map<TaintLabel, SourceInfo> label2source;

// next label number to use for either load or store
TaintLabel next_label=1;


// true if we are tracking flows into / out of kernel code points
bool track_kernel = false;

bool summary = false;

// really just indicating if anything has a taint label yet
uint64_t first_taint_instr = 0;

// collect & count flows between source and sink code points
map<Flow, uint64_t> flows;

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



// used to collect labels in a set
set<TaintLabel> all_labels;
uint8_t cb[8];
uint32_t tcn[8];
uint32_t card[8]; 


enum LabelType {LoadLabel, StoreLabel};

LabelType collect_labels_type;

// taint2_labelset_ram_iter  helper
int collect_labels(TaintLabel l, void *stuff) {
    // only collect one kind of label 
    if (label2source[l].isStore
        && collect_labels_type == StoreLabel)
        all_labels.insert(l);
    return 0;
}


// is_store = true if we call from after_store
// in which case we should be collecting load labeles
// false means a load thus we collect store labels
// note: labels end up in global all_labels
uint32_t get_ldst_labels(bool is_store, CPUState *cpu, LabelType label_type, uint64_t addr, size_t size) {
    all_labels.clear();
    // collect load labels for a store and store labels for a load
    collect_labels_type = label_type;
    // how many of size bytes about to be load are tainted?
    uint32_t num_tainted = 0;
    for (int i=0; i<size; i++) {
        ram_addr_t ra;
        MemTxResult mtr = PandaVirtualAddressToRamOffset(&ra, cpu, addr+i, is_store);
        if (mtr != MEMTX_OK) 
            continue;                                           
        if (taint2_query_ram(ra)) {
            taint2_labelset_ram_iter(ra, collect_labels, NULL);
            num_tainted ++;
        }
    }
    return num_tainted;
}


void spit_thread(OsiProc *process, OsiThread *thread) {
    cout << "(pid=" << dec << process->pid << ",ppid=" << process->ppid
         << ",tid=" << thread->tid << ",create_time=" << process->create_time
         << ")";
}



Panda__FlowSource make_psource(SourceInfo &source, Panda__CodePoint &psource_cp, Panda__Thread &psource_thread) {
    Panda__FlowSource psource;

    psource_thread = PANDA__THREAD__INIT;
    psource_thread.pid = source.thread.pid;
    psource_thread.ppid = source.thread.ppid;
    psource_thread.tid = source.thread.tid;
    psource_thread.create_time = source.thread.create_time;
    
    psource_cp = PANDA__CODE_POINT__INIT;
    psource_cp.thread = &psource_thread;
    psource_cp.pc = source.pc;
    psource_cp.instr = source.instr;
    
    psource = PANDA__FLOW_SOURCE__INIT;
    psource.cp = &psource_cp;
    psource.size = source.size;
    psource.value = source.value;
    psource.is_store = source.isStore;

    return psource;
}


Panda__FlowSink make_psink(bool sinkIsStore, OsiProc *process, OsiThread *thread, target_ptr_t pc, uint64_t instr, 
                          uint64_t data, size_t size, Panda__CodePoint &psink_cp, Panda__Thread &psink_thread) {
    Panda__FlowSink psink;

    psink_thread = PANDA__THREAD__INIT;
    psink_thread.pid = process->pid;
    psink_thread.ppid = process->ppid;
    psink_thread.tid = thread->tid;
    psink_thread.create_time = process->create_time;
    
    psink_cp = PANDA__CODE_POINT__INIT;
    psink_cp.thread = &psink_thread;
    psink_cp.pc = pc;
    psink_cp.instr = instr;
    
    psink = PANDA__FLOW_SINK__INIT;
    psink.cp = &psink_cp;
    psink.size = size;
    psink.value = data;
    psink.is_store = sinkIsStore;

    return psink;
}


/*
  Log copy flow
  pc, addr, size, and data are all for sink
*/
void log_copy_flows(bool sinkIsStore, CPUState *cpu, OsiProc *process, OsiThread *thread, 
                    target_ptr_t pc, uint64_t addr, size_t size, uint64_t data) {
        
    // get taint labels on sink
    uint32_t num_tainted = get_ldst_labels(sinkIsStore, cpu, (sinkIsStore ? LoadLabel : StoreLabel), addr, size);

    if (debug) cout << TSM_PRE << " log_flows: num_tainted=" << dec << num_tainted << "\n";

    // no taint on sink so no flows
    if (num_tainted == 0) return;

    uint64_t instr = rr_get_guest_instr_count();
    
    // NB: all_labels populated by get_ldst_labels
    for (auto l : all_labels) {
        SourceInfo source = label2source[l];
        // flow is from load -> store or store -> load
        // if one is store the other should be load, and vice versa
        assert (source.isStore != sinkIsStore);
        if (debug) {
            cout << TSM_PRE << " log_copy_flows: flow observed from "
                 << source.thread;
            cout << TSM_PRE << " to ";
            spit_thread(process, thread);
            cout << " pc=" << hex << pc << dec << "\n";
            cout << "\n";
        }
        if (summary) {
/*
            Thread sink_thread = {process->pid, process->ppid, othread->tid, process->create_time};
            SourceSink source = {source.thread, source.instr, source.pc};
            SourceSink sink = {sink_thread, sink_instr, sink_pc};
            Flow flow = {isStore, source, sink};
            if (flows.count(flow) == 0) 
                flows[flow] = 0;            
            flows[flow] += 1;
*/
        }
        else {
            if (pandalog) {
                Panda__LogEntry ple;
                Panda__CodePoint psource_cp, psink_cp;
                Panda__Thread psource_thread, psink_thread;

                Panda__FlowSource psource = make_psource(source, psource_cp, psource_thread);
                Panda__FlowSink psink = make_psink(sinkIsStore, process, thread, pc, instr, data, size, psink_cp, psink_thread);
                    
                Panda__FlowCopy pflow_copy = PANDA__FLOW_COPY__INIT;
                pflow_copy.source = &psource;
                pflow_copy.sink = &psink;
                
                ple = PANDA__LOG_ENTRY__INIT;
                ple.has_asid = true;
                ple.asid = panda_current_asid(cpu);
                ple.flow_copy = &pflow_copy;
                pandalog_write_entry(&ple);
            }
        }
        // not unique flows 
        num_flows ++;
    }
}


    

void log_compute_flow(bool sinkIsStore, CPUState *cpu, SourceInfo &source, OsiProc *process, OsiThread *thread,
                      target_ptr_t pc, uint64_t addr, size_t size, uint64_t data, uint32_t offset,
                      uint32_t card, uint8_t cb, uint32_t tcn) {

    if (debug) {
        cout << TSM_PRE << " log_compute_flows: flow observed from "
             << source.thread;
        cout << TSM_PRE << " to ";
        spit_thread(process, thread);
        cout << " pc=" << hex << pc << dec << "\n";
        cout << "\n";
    }
    if (summary) {
        /* 
           do something
        */
    }
    else {
        if (pandalog) {            
    
            Panda__LogEntry ple;
            Panda__CodePoint psource_cp, psink_cp;
            Panda__Thread psource_thread, psink_thread;

            Panda__FlowSource psource = make_psource(source, psource_cp, psource_thread);
            Panda__FlowSink psink = make_psink(sinkIsStore, process, thread, pc, rr_get_guest_instr_count(), data, size, psink_cp, psink_thread);
                    
            Panda__FlowCompute pflow_compute = PANDA__FLOW_COMPUTE__INIT;
            pflow_compute.source = &psource;
            pflow_compute.sink = &psink;
            pflow_compute.offset = offset;
            pflow_compute.card = card;
            pflow_compute.tcn = tcn;
            pflow_compute.cb = cb;
    
            ple = PANDA__LOG_ENTRY__INIT;
            ple.has_asid = true;
            ple.asid = panda_current_asid(cpu);
            ple.flow_compute = &pflow_compute;
            pandalog_write_entry(&ple);
        }
    }
    
}


// Note process, thread, pc, addr, size all refer to sink
void log_flows(bool sinkIsStore, CPUState *cpu, OsiProc *process, OsiThread *thread, target_ptr_t pc, uint64_t addr, size_t size, uint64_t data) { 
    if (!sinkIsStore) {
        // store -> load flow
        // Has to be a copy
        log_copy_flows(sinkIsStore, cpu, process, thread, pc, addr, size, data);
    }
    else {
        // load -> store flow
        // might be a compute?

        // if all the bytes are tainted with same label (singular) 
        // and tcn = 0 on the data being stored at this sink, then
        // this is a copy flow.
        uint32_t num_tainted = get_ldst_labels(sinkIsStore, cpu, LoadLabel, addr, size);
        bool its_a_copy = false;
        if (num_tainted == size && all_labels.size() == 1) {
            // all the bytes on the load extent are tainted
            // and the union of labels on all bytes is a singleton (one label)
            uint32_t num_copies = 0;
            for (int i=0; i<size; i++) {
                ram_addr_t ra;
                MemTxResult mtr = PandaVirtualAddressToRamOffset(&ra, cpu, addr+i, sinkIsStore);
                assert (mtr == MEMTX_OK);
                uint32_t card = taint2_query_ram(ra);
                assert (card == 1);
                uint32_t tcn = taint2_query_tcn_ram(ra);
                if (tcn > 0) 
                    num_copies++;
            }
            if (num_copies == size) {
                // 1. every byte on the extent (addr,size) is tainted
                // 2. every byte has a label set with card=1 and tcn=0
                // 3. further, union of all labels for all tainted bytes is a set containing a single label
                // all of this together means this load -> store flow is really just a copy
                its_a_copy = true;
            }
        }
        if (its_a_copy) {
            // this compute is really a copy
            log_copy_flows(sinkIsStore, cpu, process, thread, pc, addr, size, data);
        }
        else {
            // its a compute flow 
            // which means one Compute flow per byte in sink
            // collect tcn/cb/card since we have to log that stuff
            for (int i=0; i<size; i++) {
                ram_addr_t ra;
                MemTxResult mtr = PandaVirtualAddressToRamOffset(&ra, cpu, addr+i, sinkIsStore);
                if (mtr != MEMTX_OK) 
                    continue;                                           
                uint32_t card = taint2_query_ram(ra);
                if (card != 0) {
                    // this byte is tainted. 
                    // collect labels just for this byte.
                    all_labels.clear();
                    collect_labels_type = LoadLabel;
                    taint2_labelset_ram_iter(ra, collect_labels, NULL);
                    // these are various compute kinds of things                                        
                    uint8_t cb = taint2_query_cb_mask_ram((uint64_t)ra); // # reversible bits
                    uint32_t tcn = taint2_query_tcn_ram(ra);    
                    for (auto l : all_labels) {
                        SourceInfo source = label2source[l];
                        log_compute_flow(sinkIsStore, cpu, source, process, thread, pc, addr+i, size, data, i, card, cb, tcn);
                    }
                }
            }    
        }
    }
}            
            




// apply taint labels to this load or store source
uint32_t label_store_or_load(bool sourceIsStore, CPUState *cpu, 
                             OsiProc *process, OsiThread *othread, 
                             target_ptr_t pc, bool in_kernel, uint64_t instr, 
                             uint64_t addr, uint64_t data, size_t size, bool isSigned) {

    Thread thread;
    thread.pid = process->pid;
    thread.ppid = process->ppid;
    thread.tid = othread->tid;
    thread.create_time = process->create_time;
    SourceInfo source;
    source.isStore = sourceIsStore;
    source.thread = thread;
    source.pc = pc;
    source.in_kernel = panda_in_kernel(cpu);
    source.instr = rr_get_guest_instr_count();
    source.value = data;
    source.size = size;
    source.isSigned = isSigned;

    TaintLabel l;
    if (source2label.count(source) == 0) {
        // l is a new label -- this is first time we've seen this StoreInfo
        l = next_label;
        next_label ++;
        source2label[source] = l;
        label2source[l] = source;
        if (debug) 
            cout << TSM_PRE " after_store: new tsm label l=" << dec << l << " " << source << "\n";
    }
    else  {
        // old label
        l = source2label[source];
    }
        
    // NB: yes, we just  overstore any existing taint labels on this memory extent
    uint32_t num_labeled = 0;
    for (int i=0; i<size; i++) {
        ram_addr_t ra;
        MemTxResult mtr = PandaVirtualAddressToRamOffset(&ra, cpu, addr+i, sourceIsStore);
        if (mtr != MEMTX_OK) 
            continue;                                           
        taint2_label_ram(ra, l);
        num_labeled ++;
    }

    if (debug) {
        cout << TSM_PRE;
        if (sourceIsStore)
            cout << " labeling source. num_labeled=" << dec << num_labeled << "\n";
    }

    if (num_labeled >0 && first_taint_instr == 0) {
        first_taint_instr = rr_get_guest_instr_count();
        if (debug) cout << TSM_PRE "first taint instr is " << first_taint_instr << "\n";
    }   

    return num_labeled;
}



// log flows from source labels seen at this sink.
// then, label this code point as a new source
void handle_source_sink(bool sinkIsStore, CPUState *cpu, uint64_t addr, uint64_t data, size_t size, bool isSigned) {
    
    if ((!taint2_enabled()) || (!track_kernel && (panda_in_kernel(cpu)))) return;

    // coz this is in bits
    size /= 8;
    
    target_ulong pc = cpu->panda_guest_pc;
    
    if (debug) 
        cout << TSM_PRE << " handle_sink: " << (sinkIsStore ? "store" : "load")
             << " @ pc=" << hex << pc << " addr=" << addr << " size=" << size << "\n";
    
    // obtain data at sink
    int size32max = (size < 32) ? size : 32;
    uint8_t buffer[32];
    int rv = panda_virtual_memory_read(cpu, addr, buffer, size32max);
    if (rv == -1) {
        // not there. is that even possible?
        // certainly it means we can't taint anything right?
        if (debug) 
            cout << TSM_PRE << " Attempted to get data at sink: " << dec << size32max 
                 << " bytes at addr=" << hex << addr << " : failed?\n";
        return;
    }
    
    if (debug) {
        cout << TSM_PRE << " Data at sink(first part): [";
        for (int i=0; i<size32max; i++)
            printf ("%02x ", buffer[i]);
        cout << "]\n";
    }

    // need current process and thread and mappings to be able to label
    // source or to log flows
    OsiProc *current;
    GArray *ms;
    OsiThread *othread;
    current = get_current_process(cpu); 
    if (current && current->pid !=0) {
        ms = get_mappings(cpu, current); 
        othread = get_current_thread(cpu);
        if (ms && othread) {
            // getting to here means we have process, thread, and mappings.
            // check taint on data just stored and log any load -> store flows
            log_flows(sinkIsStore, cpu, current, othread, pc, addr, size, data);            
            // apply taint labels to stopred data.
            label_store_or_load(sinkIsStore, cpu, current, othread, 
                                pc, panda_in_kernel(cpu), rr_get_guest_instr_count(), 
                                addr, data, size, isSigned);
        }
        if (ms) g_array_free(ms, true);
        if (othread) free_osithread(othread);        
    }        
    if (current) free_osiproc(current);
}


// this will be called semantically just before a load, meaning before emulation 
// of the load or any taint prop
void before_load(CPUState *cpu, uint64_t addr, uint64_t data, size_t size, bool isSigned) {
    handle_source_sink(/*sinkIsStore = */ false, cpu, addr, data, size, isSigned);
}    


// this will be called semantically just after a store, meaning after emulation 
// of the store and any taint prop
void after_store(CPUState *cpu, uint64_t addr, uint64_t data, size_t size, bool isSigned) {
    handle_source_sink(/*sinkIsStore = */ true, cpu, addr, data, size, isSigned);
}    

 




bool init_plugin(void *self) {

    panda_require("taint2");
    assert (init_taint2_api());

    panda_require("osi"); 
    assert(init_osi_api());

    panda_arg_list *args = panda_get_args("tsm");

    track_kernel = panda_parse_bool_opt(args, "kernel", "turn on debug output");
    if (track_kernel)
        cout << TSM_PRE << "tracking kernel stores & loads too\n";
    else
        cout << TSM_PRE << "NOT tracking kernel stores & loads\n";
    summary = panda_parse_bool_opt(args, "summary", "summary output");
    cout << TSM_PRE << "summary mode is " << (summary ? "ON" : "OFF") << "\n";
    
    panda_cb pcb;

    pcb.before_block_translate = enable_taint;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb);


    // This is in order to label stores
    // but first we query the data just stored
    // to see if it has a load label
    pcb.after_store = after_store;
    panda_register_callback(self, PANDA_CB_AFTER_STORE, pcb);

    // ... and this is to query loads
    // and to be able to label loads
    pcb.before_load = before_load;
    panda_register_callback(self, PANDA_CB_BEFORE_LOAD, pcb);





    // this will give us accurate pc within a bb
    panda_enable_precise_pc();

    return true;
}



void uninit_plugin(void *) {

    if (summary) {
/*
        Panda__Thread th_source, th_sink;
        th_source = th_sink = PANDA__THREAD__INIT;
        Panda__CodePoint cp_source, cp_sink;
        cp_source = cp_sink = PANDA__CODE_POINT__INIT;
        Panda__Flow wrf = PANDA__STORE_LOAD_FLOW__INIT;
        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
        cout << (flows.size()) << " unique flows -- pandalogging\n";
        for (auto kvp : flows) {
            auto flow = kvp.first;
            auto [store_thread, load_thread, store_pc, load_pc, store_instr, load_instr] = flow;
            uint64_t count = kvp.second;
            if (pandalog) {
                th_source.pid = store_thread.pid;
                th_source.tid = store_thread.tid;
                th_source.create_time = store_thread.create_time;
                th_sink.pid = load_thread.pid;
                th_sink.tid = load_thread.tid;
                th_sink.create_time = load_thread.create_time;
                cp_source.thread = &th_source;
                cp_source.pc = store_pc;
                cp_source.instr = store_instr;
                cp_sink.thread = &th_sink;
                cp_sink.pc = load_pc;
                cp_sink.instr = load_instr;               
                wrf.source = &cp_source;
                wrf.sink = &cp_sink;
                wrf.count = count;
                wrf.has_count = true;
                ple.store_load_flow = &wrf;
                pandalog_store_entry(&ple);
            }
            else {
                cout << TSM_PRE << " Flow (count=" << count << " from " << store_thread << " to " << load_thread << "\n";
                cout << TSM_PRE << "    store @ (instr=" << dec << store_instr << ",pc=" << hex << store_pc << ")";
                cout <<            "    load  @ (instr=" << dec << load_instr << ",pc=" << hex << load_pc << ")\n";
            }
        }
    }
*/
}
}
