
#define __STDC_FORMAT_MACROS

extern "C" {
#include <stdint.h>
#include <sys/time.h>
#include <sys/resource.h>
}

#include "panda/plugin.h"
#include "taint2/taint2.h"
#include "taint2/addr_fns.h"

extern "C" {
#include "taint2/taint2_ext.h"
#include "taint2/taint2_int_fns.h"
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

#define EBX ((CPUArchState*)cpu->env_ptr)->regs[R_EBX]

uint32_t max_tcn;

string addr_typ_name[11] = { 
    "haddr", "maddr", "iaddr", "paddr", "laddr", "greg", 
    "gspec", "unk", "const", "ret", "addr_last"};

string addr_str(Addr a) {
    string val;
    switch (a.typ) {
    case MADDR:
        val = to_string(a.val.ma);
        break;
    case LADDR:
        val = to_string(a.val.la);
        break;
    case GREG:
        val = to_string(a.val.gr);
        break;
    default:
        assert (1==0);
    }
    return (string(addr_typ_name[a.typ])) + "(val=" + val + ",off=" + to_string(a.off) + ")";
}


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
struct TaintFlow {
    bool sinkIsStore;         // if true then load->store, else store->load
    SourceSink source;
    SourceSink sink;

    bool operator <(const TaintFlow &other) const {
        if (this->sinkIsStore < other.sinkIsStore) return true;
        if (this->sinkIsStore > other.sinkIsStore) return false;
        if (this->source < other.source) return true;
        if (other.source < this->source) return false;
        if (this->sink < other.sink) return true;
        return false;
    }

    friend std::ostream &operator<<(std::ostream &os, const TaintFlow &flow) {
        os << "(TaintFlow,sinkIsStore=" << flow.sinkIsStore 
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

// true if we are logging TSM updates on store/load
bool log_map_updates = false;

// log load -> compute -> store flows?
bool log_compute_flows = false;

// bit masks for different kinds of flows 
#define FLOWS_STORE_LOAD 1
#define FLOWS_LOAD_STORE 2

uint32_t log_flows_mode = 0;

// really just indicating if anything has a taint label yet
uint64_t first_taint_instr = 0;

// collect & count flows between source and sink code points
map<TaintFlow, uint64_t> flows;

// used to spit out diag msg every 1% of replay
double next_replay_percent = 0.0;


bool debug = false;


// just used to turn on taint, sadly 
void enable_taint(CPUState *cpu, target_ptr_t pc) {
    if (!taint2_enabled()) {
        cout << TSM_PRE << "enabling taint \n";
        taint2_enable_taint();
    }
}


// vaddr is a virtual addr
// determine if it is mapped.
// return a pair (bool, Addr)
// first is true iff all bytes are mapped
// second is taint system Addr for vaddr (or for 0 if not mapped)
pair<bool, Addr> get_maddr(CPUState *cpu, bool isStore, uint64_t vaddr) {
    ram_addr_t ra;
    MemTxResult mtr = PandaVirtualAddressToRamOffset(&ra, cpu, vaddr, isStore);
    if (mtr != MEMTX_OK) 
        return make_pair(false, create_maddr((uint64_t) 0));
    return make_pair(true, create_maddr((uint64_t) (ra)));
}            


Addr get_addr_with_offset(Addr a, uint32_t i) {
    Addr b = a;
    switch (a.typ) {
    case MADDR:
        // this should be true, right?
        assert (a.off == 0);
        b.val.ma += i;
        break;
    case LADDR:
    case GREG:
        // bc this can be nonzero ugh.
        b.off = i + a.off;
        break;
    default:
        cout << "Encountered addr type [" << (addr_typ_name[a.typ]) << "] ?\n";
        assert (1==0);
        break;
    }
    return b;
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
    if ((label2source[l].isStore && collect_labels_type == StoreLabel) 
        || (!label2source[l].isStore && collect_labels_type == LoadLabel))
        all_labels.insert(l);
    return 0;
}


// consider each of the bytes in (addr,size)
// count how many have taint
// also collect all labels seen on any byte in a big set: all_labels
uint32_t get_ldst_labels(CPUState *cpu, LabelType label_type, 
                         Addr addr, size_t size) {
    all_labels.clear();
    // collect load labels for a store and store labels for a load
    collect_labels_type = label_type;
    // how many bytes on the range are tainted?
    uint32_t num_tainted = 0;
    for (int i=0; i<size; i++) {
        Addr b = get_addr_with_offset(addr, i);
        if (taint2_query(b)) {
            taint2_labelset_iter(b, collect_labels, NULL);
            num_tainted++;
        }        
    }
    return num_tainted;
}


void spit_thread(OsiProc *process, OsiThread *thread) {
    cout << "(pid=" << dec << process->pid << ",ppid=" << process->ppid
         << ",tid=" << thread->tid << ",create_time=" << process->create_time
         << ")";
}




void make_psource(SourceInfo &source, Panda__CodePoint &psource_cp,
                  Panda__TaintSource &psource, Panda__Thread &psource_thread) {

    psource_thread = PANDA__THREAD__INIT;
    psource_thread.pid = source.thread.pid;

    psource_thread.ppid = source.thread.ppid;
    psource_thread.tid = source.thread.tid;
    psource_thread.create_time = source.thread.create_time;
    
    psource_cp = PANDA__CODE_POINT__INIT;
    psource_cp.thread = &psource_thread;
    psource_cp.pc = source.pc;
    
    psource = PANDA__TAINT_SOURCE__INIT;
    psource.cp = &psource_cp;
    psource.size = source.size;
    psource.value = source.value;
    psource.instr = source.instr;
    psource.is_store = source.isStore;

}


void fill_pthread(OsiProc *process, OsiThread *thread, Panda__Thread &pthread) {
    pthread = PANDA__THREAD__INIT;
    pthread.pid = process->pid;
    pthread.ppid = process->ppid;
    pthread.tid = thread->tid;
    pthread.create_time = process->create_time;
}



void make_psink(bool isStore, OsiProc *process, OsiThread *thread, 
                target_ptr_t pc, uint64_t instr, uint64_t data, 
                size_t size, Panda__CodePoint &psink_cp,
                Panda__TaintSink &psink, Panda__Thread &psink_thread) {

    fill_pthread(process, thread, psink_thread);
    
    psink_cp = PANDA__CODE_POINT__INIT;
    psink_cp.thread = &psink_thread;
    psink_cp.pc = pc;
    
    psink = PANDA__TAINT_SINK__INIT;
    psink.cp = &psink_cp;
    psink.size = size;
    psink.value = data;
    psink.instr = instr;
    psink.is_store = isStore;

}


/*
  Log copy flow

  if atStore then src is load and sink is store
  else src is store and sink is load

  pc, addr, size, and data are all for sink

  NOTE: uses all_labels which is assume previously to have been
  populated by a call to get_ldst_labels

*/
void log_copy_flows(bool atStore, CPUState *cpu, OsiProc *process, OsiThread *thread, 
                    target_ptr_t pc, Addr addr, size_t size, uint64_t data, TaintLabel label) {
        
    SourceInfo source = label2source[label];

    // flow is from load -> store or store -> load
    // if one is store the other should be load, and vice versa
    assert (source.isStore != atStore);

    if (debug) {
        cout << TSM_PRE << " log_copy_flows: flow observed from "
             << source.thread;
        cout << TSM_PRE << " to ";
        spit_thread(process, thread);
        cout << " pc=" << hex << pc << dec << "\n";
        cout << "\n";
    }

    if (pandalog) {
        Panda__LogEntry ple;
        Panda__CodePoint psource_cp, psink_cp;
        Panda__Thread psource_thread, psink_thread;
        Panda__TaintSource psource; 
        make_psource(source, psource_cp, psource, psource_thread);
        Panda__TaintSink psink;
        make_psink(atStore, process, thread, pc, rr_get_guest_instr_count(), data, size, psink_cp, 
                   psink, psink_thread);                    
        Panda__TaintFlow taint_flow = PANDA__TAINT_FLOW__INIT;
        taint_flow.source = &psource;
        taint_flow.sink = &psink;
        taint_flow.copy = true;              
        ple = PANDA__LOG_ENTRY__INIT;
        ple.has_asid = true;
        ple.asid = panda_current_asid(cpu);
        ple.taint_flow = &taint_flow;
        pandalog_write_entry(&ple);            
    }    
 
}


    

void log_compute_flow(bool atStore, CPUState *cpu, SourceInfo &source, OsiProc *process, OsiThread *thread,
                      target_ptr_t pc, size_t size, uint64_t data, uint32_t offset,
                      uint32_t card, uint8_t cb, uint32_t tcn) {

    if (debug) {
        cout << TSM_PRE << " log_compute_flows: flow observed from "
             << source.thread;
        cout << TSM_PRE << " to ";
        spit_thread(process, thread);
        cout << " pc=" << hex << pc << dec << "\n";
        cout << "\n";
    }

    if (pandalog) {                
        Panda__LogEntry ple;
        Panda__CodePoint psource_cp, psink_cp;
        Panda__Thread psource_thread, psink_thread;
        Panda__TaintSource psource;
        Panda__TaintSink psink;
        make_psource(source, psource_cp, psource, psource_thread);
        make_psink(atStore, process, thread, pc, rr_get_guest_instr_count(), 
                   data, size, psink_cp, psink, psink_thread);
        
        Panda__TaintFlow taint_flow = PANDA__TAINT_FLOW__INIT;
        taint_flow.source = &psource;
        taint_flow.sink = &psink;
        taint_flow.copy = false;
        taint_flow.has_offset = taint_flow.has_card = taint_flow.has_tcn = taint_flow.has_cb = true;
        taint_flow.offset = offset;
        taint_flow.card = card;
        taint_flow.tcn = tcn;
        taint_flow.cb = cb;    
        ple = PANDA__LOG_ENTRY__INIT;
        ple.has_asid = true;
        ple.asid = panda_current_asid(cpu);
        ple.taint_flow = &taint_flow;
        pandalog_write_entry(&ple);        
    }
    
}

// returns true iff all bytes on this extent are a copy wrt original taint labels
bool its_a_copy(Addr addr, size_t size, uint32_t num_tainted) {
    bool copy = false;
    if (num_tainted == size && all_labels.size() == 1) {
        // all the bytes on the load extent are tainted
        // and the union of labels on all bytes is a singleton (one label)
        uint32_t num_copies = 0;
        for (int i=0; i<size; i++) {
            Addr b = get_addr_with_offset(addr, i);
            uint32_t card = taint2_query(b);
            if (card != 1) return false;
            uint32_t tcn = taint2_query_tcn(b);
            if (tcn == 0) num_copies++;
            else return false;
        }
        if (num_copies == size) {
            // 1. every byte on the extent (addr,size) is tainted
            // 2. every byte has a label set with card=1 and tcn=0
            // 3. further, union of all labels for all tainted bytes is a set containing a single label
            // all of this together means this load -> store flow is really just a copy
            copy = true;
        }
    }
    return copy;
}


// Note process, thread, pc, addr, size all refer to sink
// addr,size is the target (dest) of either a load or a store.  
void log_flows(bool atStore, CPUState *cpu, OsiProc *process, OsiThread *thread, 
               target_ptr_t pc, Addr addr, size_t size, uint64_t data) { 

    // not logging either kind of flow
    if (! ((atStore && (log_flows_mode & FLOWS_LOAD_STORE))
           || (!atStore && (log_flows_mode & FLOWS_STORE_LOAD))))
        return;

    // NB: this populates 'all_labels'
    uint32_t num_tainted = get_ldst_labels(cpu, (atStore ? LoadLabel : StoreLabel), addr, size);

    // dest not tainted -- bail
    if (num_tainted == 0) return;

    bool copied_data = its_a_copy(addr, size, num_tainted);

    // grab a label from the set -- if its card=1 this is the only element
    auto label_iter = all_labels.begin();
    TaintLabel label = *label_iter;

    if (!atStore) {
        // store -> load flow
        assert (addr.typ == LADDR || addr.typ == GREG);
        // Has to be a copy
        assert (copied_data);
        log_copy_flows(atStore, cpu, process, thread, pc, addr, size, data, label);            
    }
    else {
        // load -> store flow
        assert (addr.typ == MADDR);
        // might be a compute?
        if (copied_data) 
            log_copy_flows(atStore, cpu, process, thread, pc, addr, size, data, label);
        else {
            // looks like its a compute flow
            if (log_compute_flows) {
                // its a compute flow 
                // which means one Compute flow per byte in sink
                // collect tcn/cb/card since we have to log that stuff
                for (int i=0; i<size; i++) {
                    Addr b = get_addr_with_offset(addr, i);
                    uint32_t card = taint2_query(b);
                    if (card > 0) {
                        // this byte is tainted. 
                        // collect load labels just for this byte.
                        all_labels.clear();
                        collect_labels_type = LoadLabel;
                        taint2_labelset_iter(b, collect_labels, NULL);
                        // these are various compute kinds of things                                        
                        uint8_t cb = taint2_query_cb_mask(b); // num reversible bits
                        uint32_t tcn = taint2_query_tcn(b);    
                        for (auto l : all_labels) {
                            SourceInfo source = label2source[l];
                            log_compute_flow(atStore, cpu, source, process, thread, pc, size, data, i, card, cb, tcn);
                        }
                    }
                }
            }    
        }
    }
}            
            


float pdice() {
    return ( ((float)random()) / RAND_MAX);
}

// apply taint labels to this load or store source
TaintLabel label_store_or_load(bool sourceIsStore, CPUState *cpu, 
                             OsiProc *process, OsiThread *othread, 
                             target_ptr_t pc, bool in_kernel, uint64_t instr, 
                             Addr addr, uint64_t data, size_t size, bool isSigned) {

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

    TaintLabel label;
    if (source2label.count(source) == 0) {
        // l is a new label -- this is first time we've seen this StoreInfo
        label = next_label;
        next_label ++;
        source2label[source] = label;
        label2source[label] = source;
        if (debug) 
            cout << TSM_PRE " after_store: new tsm label l=" << dec << label << " " << source << "\n";
    }
    else  {
        // old label
        label = source2label[source];
    }
        
    // NB: yes, we just  overstore any existing taint labels on this memory extent
    uint32_t num_labeled = 0;
    for (int i=0; i<size; i++) {
        Addr addr_off = get_addr_with_offset(addr, i);
        taint2_label(addr_off, label);
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

    return label;
}


// at store.  we want to log this update to the TSM
void log_map_update(OsiProc *process, OsiThread *thread, target_ptr_t pc, uint64_t vaddr, size_t size, TaintLabel label) {
//    cout << "log_map_update instr=" << (rr_get_guest_instr_count()) << " rbx=" << RBX << "  vaddr=" << vaddr << "\n";
    Panda__Thread pthread;
    assert (process != NULL);
    assert (thread != NULL);
    fill_pthread(process, thread, pthread);
    Panda__CodePoint cp = PANDA__CODE_POINT__INIT;
    cp.thread = &pthread;
    cp.pc = pc;
    Panda__TsmChange tsmc = PANDA__TSM_CHANGE__INIT;
    tsmc.cp = &cp;
    tsmc.vaddr = vaddr;
    tsmc.size = size;
    tsmc.label = label;
    Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
    ple.tsm_change = &tsmc;
    pandalog_write_entry(&ple);
}
    


map <bool, uint64_t> flow_type;
uint64_t n = 0;
bool found_it=false;

//uint64_t num_handle_ss=0;
//uint64_t num_deletes=0;

// semantically just after a load or a store.
// if its a load, then addr,size is the register into which the data was loaded
// if its a store, it is a taint system memory address address (which will be a physical address).
//
// This addr,size is first treated as a possible *sink* for taint: we query it 
// to see if there are labels and if we find any then we record a flow from the 
// source implicit in the labels and this sink.
//
// Second, we treat the addr,size as a *source* by labeling it according to
// the thread, pc etc of the code that did the load or store
//
bool handle_source_sink(bool atStore, CPUState *cpu, Addr addr, uint64_t vaddr,
                        uint64_t data, size_t size, bool isSigned) {

    target_ulong pc = cpu->panda_guest_pc;

    if (debug) 
        cout << TSM_PRE << " handle_sink: " << (atStore ? "store" : "load")
             << " @ pc=" << hex << pc << " addr=" << (addr_str(addr)) << " size=" << size << "\n";

    // need current process and thread and mappings to be able to
    // log flows or label a new source
    OsiProc *current;
//    GArray *ms;
    OsiThread *othread;
    current = get_current_process(cpu); 
    bool able_to_handle = false;
    if (current && current->pid !=0) {
        othread = get_current_thread(cpu);
        if (othread) {
            if (true) {
                able_to_handle = true;
                // getting to here means we have process, thread, and mappings.
                // check taint on data just stored and log any flows
                log_flows(atStore, cpu, current, othread, pc, addr, size, data);            
                // apply taint labels to data just loaded or stored
                TaintLabel label = label_store_or_load(atStore, cpu, current, othread, 
                                                       pc, panda_in_kernel(cpu), 
                                                       rr_get_guest_instr_count(), 
                                                       addr, data, size, isSigned);            
                if (log_map_updates && atStore) {
                    log_map_update(current, othread, pc, vaddr, size, label);
                }
            }
        }
        if (othread) free_osithread(othread);        
    }
    if (current) free_osiproc(current);

    if (!able_to_handle) {
        // we weren't able to log flows or apply taint labels
        if (atStore) {
            // so we should make sure to clear taint labels here 
            // since otherwise we could be storing compute stuff. 
            for (int i=0; i<size; i++) {
                Addr a = get_addr_with_offset(addr,i);
                taint2_delete(a);
            }
        }
        return false;
    }

    return true;
}

        



bool bail_early(CPUState *cpu) {
    if (!taint2_enabled() 
        || (!track_kernel && (panda_in_kernel(cpu))))
        return true; // bail
    return false; // dont bail
}


uint64_t num_dt_card = 0;
uint64_t num_dt_tcn = 0;
uint64_t iii = 0;

// taint has been propagated and a is the addr
void taint_change (Addr addr, uint64_t size) {

    if (bail_early(current_cpu)) return;

    // stay with me.
    // (addr,size) is the destination of this taint change. 
    // If that dest is 
    // * not memory
    // * tainted
    // * tcn=0, card=0 (NO computation has happened)
    // * labels indicate current data there is from a STORE source
    // 
    // then this kinda has to be just after the load of that data? 
    // NB: That's only true under the assumption we proceed to label it as
    // a load source, since otherwise it would just copy around.
    // 
    // Upshot is we can use this as a callback for after load 
    // where we have the reg/size in hand
    if (addr.typ != MADDR) { 
        // is there taint on this non-memory extent?
        // and how many of the bytes are stores?
        uint32_t num_tainted = 0;
        uint32_t num_bytes_store = 0;
        for (int i=0; i<size; i++) {
            // this is a register so we offset to get at its bytes
            Addr b = get_addr_with_offset(addr, i);
            uint32_t n = taint2_query(b);
            if (n>0) num_tainted++;
            // only consider n=1 (singleton set)
            // and tcn==0
            if (n!=1 || taint2_query_tcn(b) > 0) 
                continue;
            // has to be tcn=0 otherwise it cant be from a store
            all_labels.clear();
            // get that label and determine if its a store
            collect_labels_type = StoreLabel;
            taint2_labelset_iter(b, collect_labels, NULL);
            // non-store label             
            if (all_labels.size() == 0) continue;
            // a is tainted, and its labelset is a singleton set
            // and tcn=0 and its one label is a store label
            num_bytes_store ++;
        }
        if (num_tainted == size && num_bytes_store == size) {
//            cout << "taint_change -- we are after load @ pc=" << hex << panda_current_pc(current_cpu);
//            cout << " addr=" + (addr_str(addr)) << " size=" << dec << size << "\n";
            handle_source_sink(/* atStore = */ false, current_cpu, addr,
                               /*vaddr=*/ 0, /*data=*/ 0, size, false);    
        }
    }
}

    

// this will be called semantically just after a store, meaning after emulation 
// of the store and any taint prop
void after_store(CPUState *cpu, uint64_t vaddr, uint64_t data, size_t size, bool isSigned, enum panda_gp_reg_enum target_reg) {

    if (bail_early(cpu)) return;

    size_t size_in_bytes = size/8;
    // make sure all the bytes on this extent ar mapped
    for (int i=0; i<size_in_bytes; i++) {
        pair p = get_maddr(cpu, true, vaddr + i);
        if (p.first == false) return;
    }

    pair p = get_maddr(cpu, true, vaddr);

    Addr addr = p.second;

    handle_source_sink(/* atStore = */ true, cpu, addr, vaddr,
                       data, size_in_bytes, isSigned);
}    

 


// NB: Ultimately we want to use a callback registered after load that has access to reg into which load went.
/*
void after_load(CPUState *cpu, uint64_t addr, uint64_t data, size_t size, bool isSigned, uint32_t reg_num, enum panda_gp_reg_enum target_reg) {
    if (size == 8 && ptrs.count(data)) {
        cout << "data=" << hex << data << " was previously labeled and just loaded\n";
    }
}    
*/

bool init_plugin(void *self) {

    panda_require("taint2");
    assert (init_taint2_api());

    panda_require("osi"); 
    assert(init_osi_api());

    panda_arg_list *args = panda_get_args("tsm");

    track_kernel = panda_parse_bool_opt(args, "kernel", "turn on debug output");
    if (track_kernel) cout << TSM_PRE << "tracking kernel stores & loads\n";
    else cout << TSM_PRE << "NOT tracking kernel stores & loads\n";

    log_map_updates = panda_parse_bool_opt(args, "map_updates", "log updates to tsm");
    if (log_map_updates) cout << TSM_PRE << "logging updates to tsm\n";
    else cout << TSM_PRE << "NOT logging updates to tsm\n";

    log_flows_mode = panda_parse_uint32_opt(args, "flows", 0, "0 no flows (default), 1 only store->load flows, 2 only load->store flows, 3 both flows");
    if (log_flows_mode) {
        if (log_flows_mode & FLOWS_LOAD_STORE) 
            cout << TSM_PRE << "logging load->store flows\n";
        if (log_flows_mode & FLOWS_STORE_LOAD) 
            cout << TSM_PRE << "logging store->load flows\n";
    }
    else 
        cout << TSM_PRE << "NOT logging any flows\n";
        
    log_compute_flows = panda_parse_bool_opt(args, "compute", "log compute flows");
    if (log_compute_flows) cout << TSM_PRE << "logging compute flows\n";
    else cout << TSM_PRE << "NOT logging compute flows\n";

    max_tcn =  panda_parse_uint32_opt(args, "max_tcn", 5, "max tcn before taint is deleted (need some tcn to support tainted_branch)");
    printf ("max_tcn=%d\n", max_tcn);

    panda_cb pcb;

    // just to turn on taint (unfortunate)
    pcb.before_block_translate = enable_taint;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb);

    // This is to query and then label stores
    pcb.after_store = after_store;
    panda_register_callback(self, PANDA_CB_AFTER_STORE, pcb);

    // // this is to query loads
    // pcb.after_load = after_load;
    // panda_register_callback(self, PANDA_CB_AFTER_LOAD, pcb);

    // this is to query and then label loads 
    PPP_REG_CB("taint2", on_taint_change, taint_change);

    // this will give us accurate pc within a bb
    panda_enable_precise_pc();

    return true;
}



void uninit_plugin(void *) {
}
