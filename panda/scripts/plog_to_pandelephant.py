
import pandelephant.pandelephant as pe
from plog_reader import PLogReader

from datetime import datetime
import argparse
import time
import sys


"""
plog_to_pandelephant.py db_url plog



"""


class Process:

    def __init__(self, pid, create_time, names, asids, tids):
        self.pid = al.pid
        self.create_time = create_time
        self.names = names
        self.asids = asids
        self.tids = tids
        
    def __repr__(self):
        return ("Process(names=[%s],pid=%d,asid=0x%x,create_time=%s)" % (self.names, self.pid, self.asid, str(self.create_time)))

    def __hash__(self):
        return (hash(self.__repr__()))
    
    def __cmp__(self, other):
        return(cmp(self.__repr__(), other.__repr__()))




    

class AsidInfo:

    def __init__ (self, m):
        self.process = Process(m.names, m.pid, m.asid, m.create_time)
        self.range = (m.start_instr, m.end_instr)

    def __repr__(self):
        return ("AsidInfo(Process(%s),range=(%d,%d))" % (self.process,self.range[0],self.range[1]))



class Module:

    def __init__(self, m):
        self.name = m.name
        self.file = m.file
        self.base = m.base_addr
        self.size = m.size
        self.end = self.base + self.size

    def __repr__(self):
        return ("Module(name=%s,file=%s,base=0x%x,end=0x%xsize=%d)" \
                % (self.name,self.file,self.base,self.end,self.size))


class AsidLibs:

    def __init__(self, m):
        self.modules = {}
        self.asid = m.asid
        module_names = set([])
        for module in m.asid_libraries.modules:
            m_new = Module(module)
            if not (module.name in self.modules.keys()):
                self.modules[module.name] = m_new
            else:
                m = self.modules[module.name]
                base = min(m.base, m_new.base)
                end = max(m.end, m_new.end)
                m.base = base
                m.end = end
                self.modules[module.name] = m

    def __repr__(self):
        retstr = "AsidLibs(asid=0x%x\n" % self.asid
        for module in self.modules:
            retstr += " " + repr(module) + ",\n"
        retstr += ")"
        return retstr



if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="ingest pandalog and tranfer results to pandelephant")
    parser.add_argument("-db_url", help="db url", action="store")
    parser.add_argument("-pandalog", help="pandalog", action="store")    
    parser.add_argument("-exec_start", "--exec-start", help="Start time for execution", action="store", default=None)
    parser.add_argument("-exec_end", "--exec-end", help="End time for execution", action="store", default=None)

    # must have this
    parser.add_argument("-exec_name", "--exec-name", help="A name for the execution", action="store", required=True)

    args = parser.parse_args()
#    db = pe.init_and_create_session(db_url, debug=True)

#    db_exexcution = pe.Execution(name=args.exec_name, start_time=args.exec_start, end_time=args.exec_end)
#    db.add(db_execution)


    procs = {}

    pts = set([])

    # determine set of threads
    threads = set([])
    pid2createtime = {}
    with PLogReader(args.pandalog) as plr:
        for i, msg in enumerate(plr):
            if msg.HasField("asid_libraries"):
                al = msg.asid_libraries
                thread = (al.pid, al.tid, al.create_time)
                threads.add(thread)
                # keep track of earliest create time for
                # a thread with this pid, which we will
                # use to indicated a process.
                if not (al.pid in pid2createtime):
                    pid2createtime[al.pid] = al.create_time
                else:
                    if al.create_time < pid2createtime[al.pid]:
                        pid2createtime[al.pid] = al.create_time
                        print "This should not happen?"

    # determine set of processes now that we know
    # earliest create time for a thread in group for each pid
    processes = set([])
    for pid in pid2createtime.keys():
        # process is a pid,create_time pair
        process = (pid,pid2createtime[pid])
        processes.add(process)

    mappings = {}
    tid_names = {}
    tids = {}
    num_discard = 0
    num_keep = 0
    process2ppid = {}
    proc2threads = {}
    thread2proc = {}
    num_mappings = 0
    num_no_mappings = 0
    with PLogReader(args.pandalog) as plr:
        for i, msg in enumerate(plr):
            if msg.HasField("asid_libraries"):
                al = msg.asid_libraries                
                # mappings in this plog entry
                if al.succeeded:
                    these_mappings = []
                    for mapping in al.modules:
                        mp = (mapping.name, mapping.file, mapping.base_addr, mapping.size)
                        these_mappings.append(mp)
                    num_mappings += 1
                else:
                    these_mappings = None                        
                    num_no_mappings += 1
                # the process these mappings belong to
                process = (al.pid, pid2createtime[al.pid])
                if process in process2ppid:
                    assert (process2ppid[process] == al.ppid)
                # we are going to need ppid for this process later
                process2ppid[process] = al.ppid
                # collect mappings for this process, which 
                # are indexed by instr count and we also keep asid
                if not (process in mappings):
                    mappings[process] = [(msg.instr, msg.asid, these_mappings)]
                else:
                    (x,last_asid,last_mappings) = mappings[process][-1]
                    if these_mappings == last_mappings and msg.asid == last_asid:
#                        print "asid and mappings did not change -- discard"
                        num_discard += 1
                    else:
#                        print "mappings changed -- keeping"
                        mappings[process].append((msg.instr,msg.asid,these_mappings))
                        num_keep += 1
                # there might be several names for a tid
                thread = (al.pid, al.tid, al.create_time)
                if not (process in proc2threads):
                    proc2threads[process] = set([])
                proc2threads[process].add(thread)
                thread2proc[thread] = process
                if not (thread in tid_names):
                    tid_names[thread] = set([])
                if not (process in tids):
                    tids[process] = set([])
                tid_names[thread].add(al.proc_name)
                tids[process].add(al.tid)


    print "Num mappings = %d" % num_mappings
    print "Num no_mappings = %d" % num_no_mappings

    print "Kept %d of %d mappings (%f percent)" % \
        (num_keep, num_discard, 100 * (float(num_keep) / (num_keep+num_discard)))

    print "%d processes" % (len(processes))
    for (pid,create_time) in processes:
        print "proc %d %d" % (pid, create_time)
    for thread in threads:
        (pid,tid,create_time) = thread
        print "thread %d %d %d %s" % (pid, tid, create_time, str(tid_names[thread]))

    for process, mapping_list in mappings.iter():
        (pid,create_time) = process
        ppid = process2ppid[process]
        if debug:
            print ("Creating process pid-%d ppid=%d" % (pid, ppid))
        db_proc = pe.Process(pid=pid, ppid=ppid, execution=ex)
        # collect threads for this process
        db_threads = []
        for thread in proc2threads[process]:
            (thread_pid, tid, thread_create_time) = thread
            assert (thread_pid == pid)
            db_thread = pe.Thread(names=tid_names[(pid,tid,thread_create_time)], \
                                  tid=tid, create_time=thread_create_time)
            db_threads.append(db_thread)
            if debug:
                print ("** Creating thread for that process names=[%s] tid=%d create_time=%d" % \
                       (tid_names[(pid,tid,thread_create_time)], tid, thread_create_time))
        db_proc.threads = db_threads
        db_mappings = []
        for (instr,asid,mapping) in mapping_list:
            (m_name, m_file, m_base, m_size) = mapping
            db_va = pe.VirtualAddress(asid=asid, execution_offset=instr, address=m_base, execution=db_execution)
            if debug: 
                print ("** Creating virtual addr for base for module in that process asid=%x base=%x instr=%d" % \
                       (asid, m_base, instr))
            db_mapping = pe.Mapping(name=m_name, path=m_file, base=db_va, size=m_size)
            if debug:
                print ("** Creating mapping for that process name=%s path=%s base=that virtual addr size=%d" % \
                       (m_name, m_file, m_size))
            db_mappings.append(db_mapping)
        db_proc.mappings = db_mappings
        db.add(db_proc)

    # find mapping that corresponds best to this code point
    # at this instr count
    def getModuleOffset(cp):
        thread = (cp.thread.pid, cp,thread.tid, cp.thread.create_time)
        process = thread2proc[thread]
        last_mappings = None
        for mapping_process, mtup in mappings.iter():
            if mapping_process == process:
                # 1. the process for this mapping is same as for code point            
                (mapping_instr, mapping_asid, mapping_list) = mtup
                if mapping_instr < instr:
                    # 2. and instr count for this mapping is *prior 
                    # to the instr count of the Code point
                    last_mappings = mtup
                if mapping_instr >= cp.instr:
                    # this mapping is for *after our code point
                    # instr count, so we'll use last_mappings
                    # if we have it
                    if last_mapping is None:
                        # we dont.  fail
                        return None
                    # see if any mapping corresponds to our pc
                    (mapping_instr, mapping_asid, mapping_list) = mtup
                    for mapping in mapping_list:
                        (name, filename, base, size) = mapping
                        if cp.pc >= base and cp.pc <= (base+size-1):
                            # found a mapping that contains our pc
                            return (mapping_instr, mapping, cp.pc - base)
        return None
        
    
    # required = True means caller thinks this va MUST exist
    def get_db_va(execution, asid, instr, addr, required):
        db_base = db.query(VirtualAddress).filter_by(asid=asid, execution_offset=instr, address=base, execution=execution)        
        if db_base is None:
            if required:
                print "db_get_va failed to find row in db when caller thought it was def there."
                assert required
            return None
        assert (db_base.count() == 1)
        return db_base


    def get_db_thread(process,tid,create_time):

    def get_db_process(execution, pid, ppid): 
 

    # find db rows for process and thread indicated, if its there.
    def get_db_process_thread(db_execution, thr):
        # possible processes
        db_processes = db.query(Process).filter_by(execution=db_execution, pid=thr.pid, ppid=thr.ppid)
        # there should be at least one
        assert (not (processes is None))
        for db_process in db_processes:
            db_threads = db.query(Thread).filter_by(tid=thr.tid, create_time=thr.create_time, process=db_process)
            if db_threads.count() == 1:
                return (db_process,db_threads.first())
            if db_threads.count() > 1:
                print "Found multiple matching threads?"
                assert threads.count() <= 1
        return None


    def get_db_mapping(execution, asid, instr, mapping):
        (name, filename, base, size) = mapping
        # get db virt addr for base (which we've already added)
        db_base_va = get_db_va(execution, asid, instr, base, True)
        db_mapping = db.query(Mapping).filter_by(name=name,path=filename,base=db_base_va,size=size)
        assert (not (db_mapping is None))
        asssert(db_mapping.count() == 1)
        return db_mapping.first()
        
    # another pass over the plog to
    # read Flows from tsm and transform them
    # into module/offset
    with PLogReader(sys.argv[1]) as plr:
        for i, msg in enumerate(plr):
            if msg.HasField("write_read_flow"):
                wrf = msg.write_read_flow
                src_mo = getModuleOffset(wrf.src)
                dest_mo = getModuleOffset(msg.instr, wrf.dest)
                if (src_mo is None) or (dest_mo is None):
                    continue
                (src_mapping_instr, src_mapping, src_offset) = src_mo
                (dest_mapping_instr, dest_mapping, dest_offset) = dest_mo
                db_src_mapping = get_db_mapping(db_execution, msg.asid, src_mapping_instr, src_mapping)
                db_dest_mapping = get_db_mapping(db_execution, msg.asid, dest_mapping_instr, dest_mapping)
                db_src_code_point = pe.CodePoint(mapping=db_src_mapping, offset=src_offs)
                db_dest_code_point = pe.CodePoint(mapping=db_dest_mapping, offset=dest_offs)
                (db_src_process, db_src_thread) = get db_process_thread(db_execution, wrf.src.thread)
                (db_dest_process, db_dest_thread) = get db_process_thread(db_execution, wrf.dest.thread)
                db_write_read_flow = pe.WriteReadFlow(write=db_src_code_point, \
                                                      write_thread = db_src_thread,\
                                                      write_execution_offset = wrf.src.instr, \
                                                      read=db_dest_code_point, \
                                                      read_thread = db_dest_thread, \
                                                      read_execution_offset = wrf.dest.instr)
                # execution_offset: 
                # this is instruction count of the read, really
                # should we have write instr count as well?
                db.add(db_write_read_flow)
