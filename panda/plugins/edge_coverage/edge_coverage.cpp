#define __STDC_FORMAT_MACROS

#include <cstdio>

#include "panda/plugin.h"

extern "C" {

    bool init_plugin(void *);
    void uninit_plugin(void *);

#include <stdint.h>

#include "panda/plog.h"
#include "osi/osi_types.h"
#include "osi/osi_ext.h"
#include "track_intexc/track_intexc_ext.h"

}

#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <iomanip>
#include <vector>

#ifdef CONFIG_SOFTMMU

#endif

using namespace std;

typedef target_ulong Pc;

target_ulong start_main = 0;



struct Thread {
    target_ptr_t tid;
    uint64_t create_time;

    bool operator <(const Thread &other) const {
        if (this->tid < other.tid) return true;
        if (this->tid > other.tid) return false;
        if (this->create_time < other.create_time) return true;
        return false;
    }

    friend std::ostream &operator<<(std::ostream &os, const Thread &th) {
        os << "(Thread," << "tid=" << th.tid << "create_time=" << th.create_time << ")";
        return os;
    }


};

map <Thread, vector<Pc>> thread_trace; 

bool debug=false;

// Up to n-edge coverage 
int n;




map<Thread,target_ulong> last_bb_start;
map<Thread,bool> last_bb_was_split;
map<Thread,bool> last_bb_intexc;
map<Thread,target_ulong> last_bb_before_intexc;

bool saw_main = false;

bool got_current_thread = false;
Thread current_thread;

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


void after_block(CPUState *env, TranslationBlock *tb, uint8_t exitCode) {

    // only paying attention to one program and haven't seen main yet..
    if (start_main && !saw_main) 
        return;

    if (!got_current_thread) return;

    // dont record pc if we are in exception or interrupt code
    if (check_in_exception() || check_in_interrupt()) 
        return;
    
    // dont record pc if last block was split
    if (last_bb_was_split.count(current_thread) != 0 && !last_bb_was_split[current_thread])
        last_bb_start[current_thread] = tb->pc;
    
    // keep track of if last bb was split
    last_bb_was_split[current_thread] = tb->was_split; 
    
}

// tb size
map<target_ulong, vector<uint64_t>> tb_size;

void before_block(CPUState *env, TranslationBlock *tb) {

    tb_size[tb->pc].push_back(tb->size);
    
    if (start_main) {
        // we are only paying attention to edges within some program
        // and are waiting to see main
        if (tb->pc == start_main) {
            //   printf("saw main");
            saw_main = true;
        }
        if (!saw_main)
            return;
    }

    auto [pt_ok, current, othread] = get_proc_thread(env);

    // dont know process/thread
    if (!pt_ok) {
        got_current_thread = false;
        return;
    }

    got_current_thread = true;

    current_thread.tid = othread->tid;
    current_thread.create_time = current->create_time;
    
    bool intexc = (check_in_exception() || check_in_interrupt());
    
    // we can only know transition if we know where we were for this thread last
    if (last_bb_intexc.count(current_thread) != 0) {
        
        // four possibilities
        
        // 1. transition from reg to intexc code
        if (!last_bb_intexc[current_thread] && intexc) {
            // remember start pc of last bb before intexc
            if (debug) 
                cout << "trans from reg to intexc -- saving last_bb_before_intexc[" 
                     << hex << current_thread << "]=" << last_bb_start[current_thread] << "\n";
            last_bb_before_intexc[current_thread] = last_bb_start[current_thread];
            goto done;
        }
        
        // 2. transition from int/exc code to reg
        if (last_bb_intexc[current_thread] && !intexc) {
            // if this bb is just same as the last one before
            // the int/exc, we ignore
            if (debug) 
                cout << "trans from intexc to reg\n";
            if (tb->pc == last_bb_before_intexc[current_thread]) {
                cout << "same last bb\n";
                last_bb_start[current_thread] = tb->pc;
                goto done;
            }
            // bbs have different start pc. 
            // add bb so we'll get an edge that elides away all
            // the intexc code
            if (debug) {
                cout << "not same last bb\n";
                cout << "adding to trace last_bb_before_intexc["
                     << hex << current_thread << "]=" << last_bb_before_intexc[current_thread] << "\n";
                cout << "and setting last_bb_start[" << hex << current_thread << "]=" << tb->pc << "\n";
            }

            thread_trace[current_thread].push_back(last_bb_before_intexc[current_thread]);                     
            // update pc in case we get longjmped
            last_bb_start[current_thread] = tb->pc;
        }
        
        // 3. no transition && we are in regular code
        if (!last_bb_intexc[current_thread] && !intexc) {
            // ugh last bb was split so we dont update trace yet
            if (debug) 
                cout << "no trans and in reg code\n";
            if (last_bb_was_split[current_thread]) {
                if (debug) 
                    cout << "but last bb was split\n";
                goto done;
            }
            if (debug) {
                cout << "last bb not split\n";
                cout << "adding to trace last_bb_start["
                     << hex << current_thread << "]=" << last_bb_start[current_thread] << "\n";        
                cout << "and setting last_bb_start[" << current_thread << "]=" << tb->pc << "\n";
            }
            
            // update trace in normal way
            thread_trace[current_thread].push_back(last_bb_start[current_thread]);                 
            // update pc in case we get longjmped
            last_bb_start[current_thread] = tb->pc; 
        }
    }
    

    // 4. last bb was intexc and so is this one
    // -- nothing to do

    // keep track of last intexc value to be able
    // to observe transition
done:
    last_bb_intexc[current_thread] = intexc;
}


bool pandalog_trace = false;

bool init_plugin(void *self) {

    panda_require("track_intexc");
    assert(init_track_intexc_api());

    panda_arg_list *args; 
    args = panda_get_args("edge_coverage");

    // Set the default value to 1-edge or basic block coverage  
    n = panda_parse_uint64_opt(args, "n", 1, "collect up-to-and-including n-edges");
    //    no_kernel = panda_parse_bool_opt(args, "no_kernel", "disable kernel pcs"); 
    pandalog_trace = panda_parse_bool_opt(args, "trace", "output trace to pandalog");
    const char *start_main_str = panda_parse_string_opt(args, "main", nullptr,
                                            "hex addr of main");
    if (start_main_str != nullptr) {
        start_main = strtoul(start_main_str, NULL, 16);
        printf ("edge coverage for just one program: start_main = 0x" TARGET_FMT_lx "\n", start_main);
    }
    else 
        printf ("edge coverage for all threads and all code\n");
    
    panda_require("osi");
    assert(init_osi_api()); // Setup OSI inspection
    panda_cb pcb;
    pcb.before_block_exec = before_block;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    pcb.after_block_exec = after_block;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
    printf("Initialized coverage plugin\n");
    return true;
}



void uninit_plugin(void *) {

    if (!pandalog) return; 

    printf("Writing out pandalog info for edge_coverage\n");

    map<Thread, map<vector<Pc>, int>> final_map; 

    // From the traces in each thread, collect up to n-edges 
    for (auto kvp : thread_trace) { 
        map<vector<Pc>, int> edges;
        auto thread = kvp.first;
        auto pc_trace = kvp.second; 
        ofstream tracef;
        for (int k = 1; k <= n; k++) { 
            for (int i = 0; i < pc_trace.size(); i++) {
                // Build the edge (vector) 
                vector<Pc> edge;
                for (int j = 0; j < k; j++) { 
                    if (i+j < pc_trace.size()) 
                        edge.push_back(pc_trace[i + j]);                     
                }
                // Add the edge to the map for this thread and update its count  
                if (edges.find(edge) != edges.end())  edges[edge] += 1;
                else  edges[edge] = 1; 
            }
        }
        if (pandalog_trace) {
            Panda__ThreadTrace *at = (Panda__ThreadTrace *) malloc (sizeof(Panda__ThreadTrace));
            *at = PANDA__THREAD_TRACE__INIT;
            at->tid = thread.tid;
            at->create_time = thread.create_time;
            at->pcs = (uint64_t *) malloc(sizeof(uint64_t) * pc_trace.size());            
            int i=0;
            for (auto pc : pc_trace) 
                at->pcs[i++] = pc;
            at->n_pcs = pc_trace.size();	  
            Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
            ple.trace = at;
            pandalog_write_entry(&ple);
            free(at->pcs);
            free(at);
        }
        final_map[thread] = edges; 
        
        cout << "final_map[" << thread << "] is " << (final_map[thread].size()) << " long\n";
    }
    

    // Write out each to a pandalog 
    for (auto kvp: final_map) { 
        auto thread = kvp.first;
        auto edge_map = kvp.second; 

        Panda__ThreadEdges * ae = (Panda__ThreadEdges *) malloc (sizeof (Panda__ThreadEdges)); 
        *ae = PANDA__THREAD_EDGES__INIT; 
        ae->tid = thread.tid;
        ae->create_time = thread.create_time;

        ae->n_edges = edge_map.size(); 
        Panda__Edge ** e = (Panda__Edge **) malloc (sizeof (Panda__Edge *) * edge_map.size()); 

        int i = 0;
        for (auto kvp : edge_map) { 
            auto n_edge = kvp.first;
            auto hit_count = kvp.second;

            // some edges we will skip
            bool skip = false;
            if (n_edge.size() <= 1) skip = true;
            if (!skip) {
                for (auto pc:n_edge) {
                    if (pc == 0 || tb_size.count(pc) == 0) {
                        skip = true;
                        break;
                    }
                }
            }
            if (skip) 
                continue;
            
            e[i] = (Panda__Edge *) malloc (sizeof (Panda__Edge)); 
            *(e[i]) = PANDA__EDGE__INIT;

            Panda__Block **block_list = (Panda__Block **) malloc(sizeof(Panda__Block *) * n_edge.size());
            
            int j=0;
            for (auto pc : n_edge) {                
                block_list[j] = (Panda__Block *) malloc(sizeof(Panda__Block));
                *block_list[j] = PANDA__BLOCK__INIT;
                block_list[j]->pc = pc;
                if (tb_size[pc][0] == 0) 
                    block_list[j]->size = 0;
                else
                    block_list[j]->size = (uint32_t) tb_size[pc][0];
                j++;
            }

            e[i]->block = block_list;
            e[i]->n_block = n_edge.size();
            e[i]->hit_count = hit_count; 
            i++; 
        } 
        int num_edges = i;
        ae->edges = e; 
        ae->n_edges = num_edges;


        Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT; 
        ple.edge_coverage = ae; 
        pandalog_write_entry(&ple); 

        // Free everything I used
        for (int i=0; i<num_edges; i++) {
            for (int j=0; j<e[i]->n_block; j++) {
                free(e[i]->block[j]);
            }
            free(e[i]->block);
        }
        free(e);
        free(ae); 
    } 

}


