
#define __STDC_FORMAT_MACROS

extern "C" {
#include <stdint.h>
#include <sys/time.h>
#include <sys/resource.h>
}

#include "stdlib.h"
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


int get_reg_addr(enum panda_gp_reg_enum target_reg, Addr &a) {

    uint64_t xmm_start = (uint64_t)(&(((CPUArchState *)0)->xmm_regs));

    switch (target_reg) {

    // R_EAX = 0
    case PANDA_GP_REG_RAX:
    case PANDA_GP_REG_EAX:
    case PANDA_GP_REG_AX:
    case PANDA_GP_REG_AL:
        a = create_greg(0,0);
        break;

    case PANDA_GP_REG_AH:
        a = create_greg(0,0);
        break;

    // R_ECX = 1
    case PANDA_GP_REG_RCX:
    case PANDA_GP_REG_ECX:
    case PANDA_GP_REG_CX:
    case PANDA_GP_REG_CL:
        a = create_greg(1,0);
        break;

    case PANDA_GP_REG_CH:
        a = create_greg(1,1);
        break;

    // R_EDX = 2
    case PANDA_GP_REG_RDX:
    case PANDA_GP_REG_EDX:
    case PANDA_GP_REG_DX:
    case PANDA_GP_REG_DL:
        a = create_greg(2,0);
        break;

    case PANDA_GP_REG_DH:
        a = create_greg(2,1);
        break;

    // R_EBX = 3
    case PANDA_GP_REG_RBX:
    case PANDA_GP_REG_EBX:
    case PANDA_GP_REG_BX: 
    case PANDA_GP_REG_BL:
        a = create_greg(3,0);
        break;

    case PANDA_GP_REG_BH:
        a = create_greg(3,1);
        break;

    // R_ESP = 4
    case PANDA_GP_REG_RSP:
    case PANDA_GP_REG_ESP:
    case PANDA_GP_REG_SP:
        a = create_greg(4,0);
        break;

    // R_EBP = 5
    case PANDA_GP_REG_RBP:
    case PANDA_GP_REG_EBP:
    case PANDA_GP_REG_BP:
        a = create_greg(5,0);
        break;

    // R_ESI = 6
    case PANDA_GP_REG_RSI:
    case PANDA_GP_REG_ESI:
    case PANDA_GP_REG_SI:
        a = create_greg(6,0);
        break;

    // R_EDI = 7
    case PANDA_GP_REG_RDI:
    case PANDA_GP_REG_EDI:
    case PANDA_GP_REG_DI:
        a = create_greg(7,0);
        break;

    case PANDA_GP_REG_R8:
    case PANDA_GP_REG_R9:
    case PANDA_GP_REG_R10:
    case PANDA_GP_REG_R11:
    case PANDA_GP_REG_R12:
    case PANDA_GP_REG_R13:
    case PANDA_GP_REG_R14:
    case PANDA_GP_REG_R15:
        a = create_greg(target_reg - PANDA_GP_REG_R8, 0);
        break;

    case PANDA_GP_REG_XMM0:
    case PANDA_GP_REG_XMM1:
    case PANDA_GP_REG_XMM2:
    case PANDA_GP_REG_XMM3:
    case PANDA_GP_REG_XMM4:
    case PANDA_GP_REG_XMM5:
    case PANDA_GP_REG_XMM6:
    case PANDA_GP_REG_XMM7:
    case PANDA_GP_REG_XMM8:
    case PANDA_GP_REG_XMM9:
    case PANDA_GP_REG_XMM10:
    case PANDA_GP_REG_XMM11:
    case PANDA_GP_REG_XMM12:
    case PANDA_GP_REG_XMM13:
    case PANDA_GP_REG_XMM14:
    case PANDA_GP_REG_XMM15:
    case PANDA_GP_REG_XMM16:
    case PANDA_GP_REG_XMM17:
    case PANDA_GP_REG_XMM18:
    case PANDA_GP_REG_XMM19:
    case PANDA_GP_REG_XMM20:
    case PANDA_GP_REG_XMM21:
    case PANDA_GP_REG_XMM22:
    case PANDA_GP_REG_XMM23:
    case PANDA_GP_REG_XMM24:
    case PANDA_GP_REG_XMM25:
    case PANDA_GP_REG_XMM26:
    case PANDA_GP_REG_XMM27:
    case PANDA_GP_REG_XMM28:
    case PANDA_GP_REG_XMM29:
    case PANDA_GP_REG_XMM30:
    case PANDA_GP_REG_XMM31:
    {
        int ind = (target_reg - PANDA_GP_REG_XMM0);
        a = create_gspec(xmm_start + ind * 64, 0);
        break;
    }
    case PANDA_GP_REG_YMM0:
    case PANDA_GP_REG_YMM1:
    case PANDA_GP_REG_YMM2:
    case PANDA_GP_REG_YMM3:
    case PANDA_GP_REG_YMM4:
    case PANDA_GP_REG_YMM5:
    case PANDA_GP_REG_YMM6:
    case PANDA_GP_REG_YMM7:
    case PANDA_GP_REG_YMM8:
    case PANDA_GP_REG_YMM9:
    case PANDA_GP_REG_YMM10:
    case PANDA_GP_REG_YMM11:
    case PANDA_GP_REG_YMM12:
    case PANDA_GP_REG_YMM13:
    case PANDA_GP_REG_YMM14:
    case PANDA_GP_REG_YMM15:
    case PANDA_GP_REG_YMM16:
    case PANDA_GP_REG_YMM17:
    case PANDA_GP_REG_YMM18:
    case PANDA_GP_REG_YMM19:
    case PANDA_GP_REG_YMM20:
    case PANDA_GP_REG_YMM21:
    case PANDA_GP_REG_YMM22:
    case PANDA_GP_REG_YMM23:
    case PANDA_GP_REG_YMM24:
    case PANDA_GP_REG_YMM25:
    case PANDA_GP_REG_YMM26:
    case PANDA_GP_REG_YMM27:
    case PANDA_GP_REG_YMM28:
    case PANDA_GP_REG_YMM29:
    case PANDA_GP_REG_YMM30:
    case PANDA_GP_REG_YMM31:
    {
        int ind = (target_reg - PANDA_GP_REG_YMM0);
        a = create_gspec(xmm_start + ind * 64, 0);
        break;
    }
    case PANDA_GP_REG_ZMM0:
    case PANDA_GP_REG_ZMM1:
    case PANDA_GP_REG_ZMM2:
    case PANDA_GP_REG_ZMM3:
    case PANDA_GP_REG_ZMM4:
    case PANDA_GP_REG_ZMM5:
    case PANDA_GP_REG_ZMM6:
    case PANDA_GP_REG_ZMM7:
    case PANDA_GP_REG_ZMM8:
    case PANDA_GP_REG_ZMM9:
    case PANDA_GP_REG_ZMM10:
    case PANDA_GP_REG_ZMM11:
    case PANDA_GP_REG_ZMM12:
    case PANDA_GP_REG_ZMM13:
    case PANDA_GP_REG_ZMM14:
    case PANDA_GP_REG_ZMM15:
    case PANDA_GP_REG_ZMM16:
    case PANDA_GP_REG_ZMM17:
    case PANDA_GP_REG_ZMM18:
    case PANDA_GP_REG_ZMM19:
    case PANDA_GP_REG_ZMM20:
    case PANDA_GP_REG_ZMM21:
    case PANDA_GP_REG_ZMM22:
    case PANDA_GP_REG_ZMM23:
    case PANDA_GP_REG_ZMM24:
    case PANDA_GP_REG_ZMM25:
    case PANDA_GP_REG_ZMM26:
    case PANDA_GP_REG_ZMM27:
    case PANDA_GP_REG_ZMM28:
    case PANDA_GP_REG_ZMM29:
    case PANDA_GP_REG_ZMM30:
    case PANDA_GP_REG_ZMM31:
    {
        int ind = (target_reg - PANDA_GP_REG_ZMM0);
        a = create_gspec(xmm_start + ind * 64, 0);
        break;
    }
    default:
        return -1;
    }

    return 0;
}




const char* target_reg_name(enum panda_gp_reg_enum target_reg)
{
    if (target_reg == PANDA_GP_REG_INVALID)
        return "<Unknown>";
    if (target_reg < 0 || target_reg >= PANDA_GP_REG_NAMES_COUNT)
        return "<Illegal>";
    return PANDA_GP_REG_NAMES[target_reg];
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
        cout << "enabling taint \n";
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
    case GSPEC:
        assert (a.off == 0);
        b.val.gs += i;
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
int num_collected = 0;
int collect_labels(TaintLabel l, void *stuff) {
    // only collect one kind of label 
    if ((label2source[l].isStore && collect_labels_type == StoreLabel) 
        || (!label2source[l].isStore && collect_labels_type == LoadLabel)) {
        all_labels.insert(l);
        num_collected ++;
    }
    return 0;
}


// consider each of the bytes in (addr,size)
// count how many have taint
// also collect all labels seen on any byte in a big set: all_labels
uint32_t get_ldst_labels(CPUState *cpu, LabelType label_type, 
                         Addr addr, size_t size) {
    all_labels.clear();
    // note, if this is called on a store sink, then we'll only collect load labels
    // else if it is called on a load sink, we'll only collect store labels
    collect_labels_type = label_type;
    // how many bytes on the range are tainted?
    uint32_t num_tainted = 0;
    for (int i=0; i<size; i++) {
        Addr b = get_addr_with_offset(addr, i);
        if (taint2_query(b)) {
            num_collected = 0;
            taint2_labelset_iter(b, collect_labels, NULL);
            if (num_collected > 0)
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

*/
void log_copy_flows(bool atStore, CPUState *cpu, OsiProc *process, OsiThread *thread, 
                    target_ptr_t pc, size_t size, uint64_t data, TaintLabel label) {
        
    SourceInfo source = label2source[label];

    if (debug) {
        cout << " log_copy_flows: flow observed from "
             << source.thread;
        cout << " to ";
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
        cout << " log_compute_flows: flow observed from "
             << source.thread;
        cout << " to ";
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
// actually, some bytes can be untainted.  And they can be differently tainted
bool its_a_copy(Addr addr, size_t size) {
    bool copy = false;
    uint32_t num_copies=0;
    uint32_t num_untainted=0;
    for (int i=0; i<size; i++) {
        Addr b = get_addr_with_offset(addr, i);
        uint32_t card = taint2_query(b);
        // card can be 0 (not tainted) or 1
        if (card > 1) return false;
        uint32_t tcn = taint2_query_tcn(b);
        if (tcn == 0) 
            num_copies++;
    }
    if (num_copies + num_untainted == size) 
        copy = true;
    if (debug) {
        cout << " its_a_copy: num_copies=" << num_copies << " num_untainted=" << num_untainted;
        cout << " vs size=" << size << "\n";
    }    
    return copy;
}


// Note process, thread, pc, sink, size all refer to sink
// sink,size will be a register if atStore=true and memory else
void log_flows(bool atStore, CPUState *cpu, OsiProc *process, OsiThread *thread, 
               target_ptr_t pc, Addr sink, size_t size, uint64_t data) { 

    // NB: this populates 'all_labels' with set of labels on sink that could be a src
    uint32_t num_tainted = get_ldst_labels(cpu, (atStore ? LoadLabel : StoreLabel), sink, size);

    if (debug) 
        cout << "log_flows: " << num_tainted << " bytes tainted on sink\n";

    // sink is not tainted -- bail
    if (num_tainted == 0) 
        return;    
    
    if (its_a_copy(sink, size)) {
        // note: this relies on prior call to get_labels
        auto label_iter = all_labels.begin();
        TaintLabel one_label = *label_iter;
        log_copy_flows(atStore, cpu, process, thread, pc, size, data, one_label);            
    }
    else {
        if (log_compute_flows) {
            // One compute flow per byte in sink
            // collect tcn/cb/card since we have to log that stuff
            for (int i=0; i<size; i++) {
                Addr b = get_addr_with_offset(sink, i);
                uint32_t card = taint2_query(b);
                if (card > 0) {
                    // this byte has some taint. collect load labels just for this byte.
                    all_labels.clear();
                    collect_labels_type = LoadLabel;
                    taint2_labelset_iter(b, collect_labels, NULL);
                    // other features of the load->store flow for offset i 
                    // number of 'reversible' bits
                    uint8_t cb = taint2_query_cb_mask(b); 
                    // taint compute number (depth of tree of computation from input (taint) to this byte)
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
            


// apply taint labels to this load or store source
// label is applied to addr which can be register or memory 
// size is the number of bytes to label, starting at addr
// the label is unique to this source which is a combination of
// thread/process, instr count, pc, etc 
TaintLabel label_store_or_load(bool sourceIsStore, CPUState *cpu, 
                               OsiProc *process, OsiThread *othread, 
                               target_ptr_t pc, bool in_kernel, uint64_t instr, 
                               Addr addr, uint64_t vaddr, uint64_t data, 
                               size_t size, bool isSigned) {
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
    source.instr = instr;
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
            cout << " label_store_or_load: new tsm label l=" << dec << label << " " << source << "\n";
    }
    else  {
        // old label
        label = source2label[source];
    }
        
    // NB: yes, we just  overwrite any existing taint labels on this memory extent
    uint32_t num_labeled = 0;
    for (int i=0; i<size; i++) {
        Addr addr_off = get_addr_with_offset(addr, i);
        taint2_label(addr_off, label);
        if (debug) {
            if (addr.typ == MADDR) 
                cout << "Labeling taint on vaddr=" << hex << vaddr + i << dec << "\n";            
            if (addr.typ == LADDR) 
                cout << "Labeling taint on laddr i=" << i << "\n";
            if (addr.typ == GREG) 
                cout << "Labeling taint on greg i=" << i << "\n";

        }
        num_labeled ++;
    }

    if (debug) {
        if (sourceIsStore)
            cout << " labeling source. num_labeled=" << dec << num_labeled << "\n";
    }

    if (num_labeled >0 && first_taint_instr == 0) {
        first_taint_instr = rr_get_guest_instr_count();
        if (debug) cout << "first taint instr is " << first_taint_instr << "\n";
    }   

    if (debug) cout << "Done with label_load_or_store\n";

    if (! (its_a_copy(addr, size))) 
        cout << "Wait, its not a copy!\n";


    return label;
}


// at store.  we want to log this update to the TSM
void log_map_update(OsiProc *process, OsiThread *thread, target_ptr_t pc, uint64_t vaddr, size_t size, TaintLabel label) {
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
    


// returns true iff current proc and thread are available.
// also populates *currentp and othreadp
tuple<bool,OsiProc*,OsiThread*> get_proc_thread(CPUState *cpu) {
    // need current process and thread and to be able to
    // log flows at a sink or label a new source
    OsiProc *current = NULL;
    OsiThread *othread = NULL;
    current = get_current_process(cpu); 
    if (current && current->pid !=0) {
        othread = get_current_thread(cpu);
        if (othread) {
            return make_tuple(true, current, othread);
        }
    }
    return make_tuple(false, current, othread);
}



// src_or_sink might be a reg or might be mem, depending on if this
// is called from load (atStore=False) or store and if before or after
void handle_ldst(bool atStore, bool isSink, CPUState *cpu, Addr src_or_sink, 
                 uint64_t vaddr, uint64_t data, size_t size_in_bits, 
                 bool isSigned, enum panda_gp_reg_enum target_reg) {

    uint64_t instr = rr_get_guest_instr_count();
 
    // check if taint enabled 
    if (!taint2_enabled())
        return;

    if (isSink) {
        // at sink so we'd be logging flows
        // check that we are logging this flow
        if (! ((atStore && (log_flows_mode & FLOWS_LOAD_STORE))
               || (!atStore && (log_flows_mode & FLOWS_STORE_LOAD))))
            return;
    }

    size_t size_in_bytes = size_in_bits/8;

    if (debug) {
        cout << "handle_ldst --";
        cout << " instr=" << instr;
        cout << " pc=" << hex << cpu->panda_guest_pc << dec;
        cout << " atStore=" << atStore << " isSink=" << isSink; 
        cout << " vaddr=" << hex << vaddr << dec << " size=" << size_in_bytes;
        cout << " target_reg=" << target_reg << " " << (target_reg_name(target_reg));
        cout << "\n";
    }

    bool ok_to_handle = true;

    // if this is kernel code and we arent tracking it... 
    if (!track_kernel && (panda_in_kernel(cpu))) {
        if (debug) cout << "handle_ldst: not tracking kernel code\n";
        ok_to_handle = false;
    }

    // we can only handle if proc/thread are mapped
    auto [pt_ok, current, othread] = get_proc_thread(cpu);
    if (!pt_ok) {
        if (debug) cout << "handle_ldst: process / thread not available\n";
        ok_to_handle = false;
    }

    if (atStore != isSink) {
        // src_or_sink will be mem. So, we need to check that all of those
        // the bytes are mapped
        for (size_t i=0; i<size_in_bytes; i++) {
            pair p = get_maddr(cpu, true, vaddr + i);
            if (i==0 && p.first && vaddr == 0xffff8880366b6a20) 
                cout << "p.second = " << (addr_str(p.second)) << "\n";              
            if (p.first == false) {
                if (debug) 
                    cout << "handle_ldst: one or more of sink bytes aren't available\n";
                ok_to_handle = false;
            }
        }
    }
    
    if (atStore == isSink) {
        // src_or_sink will be a reg for these cases
        // But we may not actually know the reg so check
        if (target_reg == PANDA_GP_REG_IMMEDIATE 
            || target_reg == PANDA_GP_REG_INVALID) {
            if (debug) cout << "handle_ldst: handling involves a register but"
                           "we dont have a reasonable one\n";
            ok_to_handle = false;
        }
    }

    if (ok_to_handle) {
        // fine to handle this src_or_sink.  either log flows or label
        if (debug)
            cout << "handle_ldst: checks passed and ok to handle.\n";
        if (isSink) {
            log_flows(atStore, cpu, current, othread, cpu->panda_guest_pc,
                      src_or_sink, size_in_bytes, data);
        }
        else {
            TaintLabel label
                = label_store_or_load(atStore, cpu, current, othread, 
                                      cpu->panda_guest_pc, panda_in_kernel(cpu), 
                                      instr, src_or_sink, vaddr, data, 
                                      size_in_bytes, isSigned);            
            if (log_map_updates && atStore) {
                log_map_update(current, othread, cpu->panda_guest_pc, vaddr, 
                               size_in_bytes, label);
            }
        }
    }
    else {
        // something is wrong and we can't handle this src / sink
        if (isSink) {
            // can't handle sink -- that's ok.  we just miss the taint_flow
            if (debug) 
                cout << "handle_ldst: Can't handle sink.  Missing flow.\n";
        }
        else {
#if 0
// i think all of this is a bad idea.  just let the taint flow 
           
            // can't handle this source -- must clear taint on source!
            if (debug) 
                cout << "handle_ldst: Can't handle source. Deleting taint on source.\n";
            if ((atStore == isSink) && (r_num<0)) {
                // we'd be deleting taint on a reg we can't reason about
            }
            else {
                for (int i=0; i<size_in_bytes; i++) {
                    Addr a = get_addr_with_offset(src_or_sink,i);
                    taint2_delete(a);                           
                } 
            }
#endif
        }    
    }
    
    if (othread) free_osithread(othread);            
    if (current) free_osiproc(current);
}



// before a store, we'll check taint on the reg being stored and maybe log a ld->st flow
// the reg is a flow sink
void before_store(CPUState *cpu, uint64_t vaddr, uint64_t data, size_t size_in_bits, bool isSigned, enum panda_gp_reg_enum target_reg) {
    Addr reg_addr;
    if (get_reg_addr(target_reg, reg_addr) == 0) {
        handle_ldst(/*atStore=*/true, /*isSink=*/true, cpu, /*src_or_sink=*/reg_addr, 
                    vaddr, data, size_in_bits, isSigned, target_reg);
    }
}



// before a load, we'll check taint on the memory being loaded and maybe logging a st->ld flow
// the memory is a flow sink
void before_load(CPUState* cpu, uint64_t vaddr, uint64_t data, size_t size_in_bits, bool isSigned, enum panda_gp_reg_enum target_reg) {
    pair p = get_maddr(cpu, true, vaddr);
    if (!p.first) return;
    Addr mem_addr = p.second;
    if (p.first) 
        handle_ldst(/*atStore=*/false, /*isSink=*/true, cpu, /*src_or_sink=*/mem_addr, 
                    vaddr, data, size_in_bits, isSigned, target_reg);
}



// after a store, we'll label taint on the memory written
// the memory is a flow source 
void after_store(CPUState *cpu, uint64_t vaddr, uint64_t data, size_t size_in_bits, bool isSigned, enum panda_gp_reg_enum target_reg) {
    pair p = get_maddr(cpu, true, vaddr);
    if (!p.first) return;
    Addr mem_addr = p.second;
    if (p.first) 
        handle_ldst(/*atStore=*/true, /*isSink=*/false, cpu, /*src_or_sink=*/mem_addr, 
                    vaddr, data, size_in_bits, isSigned, target_reg);
}
 


// after a load, we'll label taint on the register
void after_load(CPUState* cpu, uint64_t vaddr, uint64_t data, size_t size_in_bits, bool isSigned, enum panda_gp_reg_enum target_reg) {
    Addr reg_addr;
    if (get_reg_addr(target_reg, reg_addr) == 0) {
        handle_ldst(/*atStore=*/false, /*isSink=*/false, cpu, /*src_or_sink=*/reg_addr, 
                    vaddr, data, size_in_bits, isSigned, target_reg);
    }
}



bool init_plugin(void *self) {

    panda_require("taint2");
    assert (init_taint2_api());

    panda_require("osi"); 
    assert(init_osi_api());

    panda_arg_list *args = panda_get_args("tsm");

    track_kernel = panda_parse_bool_opt(args, "kernel", "turn on debug output");
    if (track_kernel) cout << "tracking kernel stores & loads\n";
    else cout << "NOT tracking kernel stores & loads\n";

    log_map_updates = panda_parse_bool_opt(args, "map_updates", "log updates to tsm");
    if (log_map_updates) cout << "logging updates to tsm\n";
    else cout << "NOT logging updates to tsm\n";

    log_flows_mode = panda_parse_uint32_opt(args, "flows", 0, "0 no flows (default), 1 only store->load flows, 2 only load->store flows, 3 both flows");
    if (log_flows_mode) {
        if (log_flows_mode & FLOWS_LOAD_STORE) 
            cout << "logging load->store flows\n";
        if (log_flows_mode & FLOWS_STORE_LOAD) 
            cout << "logging store->load flows\n";
    }
    else 
        cout << "NOT logging any flows\n";
        
    log_compute_flows = panda_parse_bool_opt(args, "compute", "log compute flows");
    if (log_compute_flows) cout << "logging compute flows\n";
    else cout << "NOT logging compute flows\n";

    max_tcn =  panda_parse_uint32_opt(args, "max_tcn", 5, "max tcn before taint is deleted (need some tcn to support tainted_branch)");
    printf ("max_tcn=%d\n", max_tcn);

    panda_cb pcb;

    // just to turn on taint (unfortunate)
    pcb.before_block_translate = enable_taint;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb);

    // query taint on reg being stored and maybe log LD -> ST flow
    pcb.before_store = before_store;
    panda_register_callback(self, PANDA_CB_BEFORE_STORE, pcb);

    // label memory stored to
    pcb.after_store = after_store;
    panda_register_callback(self, PANDA_CB_AFTER_STORE, pcb);

    // query memory being loaded from and maybe log ST -> LD flow
    pcb.before_load = before_load;
    panda_register_callback(self, PANDA_CB_BEFORE_LOAD, pcb);

    // label register loaded into
    pcb.after_load = after_load;
    panda_register_callback(self, PANDA_CB_AFTER_LOAD, pcb);

    // this will give us accurate pc within a bb
    panda_enable_precise_pc();

    return true;
}



void uninit_plugin(void *) {
}
