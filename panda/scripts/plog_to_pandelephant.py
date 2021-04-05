
#from sqlalchemy_utils.functions import create_database, drop_database, database_exists

import pandelephant.pandelephant as pe
from plog_reader import PLogReader

from datetime import datetime,timedelta
import argparse
import time
import sys


"""
plog_to_pandelephant.py db_url plog



"""

debug = True


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




    



if __name__ == "__main__":

    start_time = time.time()

    parser = argparse.ArgumentParser(description="ingest pandalog and tranfer results to pandelephant")
    parser.add_argument("-db_url", help="db url", action="store")
    parser.add_argument("-pandalog", help="pandalog", action="store")    
    parser.add_argument("-exec_start", "--exec-start", help="Start time for execution", action="store", default=None)
    parser.add_argument("-exec_end", "--exec-end", help="End time for execution", action="store", default=None)

    # must have this
    parser.add_argument("-exec_name", "--exec-name", help="A name for the execution", action="store", required=True)

    args = parser.parse_args()

#    db_url = "postgres://tleek:tleek123@localhost/pandelephant1"
 #   if database_exists(db_url):
#        drop_database(db_url)
#    create_database(db_url)

    pe.init("postgres://tleek:tleek123@localhost/pandelephant1")
    db = pe.create_session("postgres://tleek:tleek123@localhost/pandelephant1")

    execution_start_datetime = datetime.now()
    try:
        db_execution = pe.Execution(name=args.exec_name, start_time=execution_start_datetime) # int(args.exec_start), end_time=int(args.exec_end))
        db.add(db_execution)
    except Exception as e:
        print e
        
    procs = {}

    pts = set([])

    # determine set of threads
    threads = set([])
    # and processes
    processes = set([])
    def collect_thread(tmsg):
        if (tmsg.pid == 0):
            print "FOOF"
        if (tmsg.pid == 0) or (tmsg.ppid == 0) or (tmsg.tid == 0):
            return
        thread = (tmsg.pid, tmsg.ppid, tmsg.tid, tmsg.create_time)
        threads.add(thread)
        process = (tmsg.pid, tmsg.ppid)
        processes.add(process)

    with PLogReader(args.pandalog) as plr:
        for i, msg in enumerate(plr):
            if msg.HasField("asid_libraries"):
                al = msg.asid_libraries
                if al.succeeded == False:
                    continue
                collect_thread(al)
            if msg.HasField("write_read_flow"):
                collect_thread(msg.write_read_flow.src.thread)
                collect_thread(msg.write_read_flow.dest.thread)


    # re-collect threads by proc
    thread2proc = {}
    proc2threads = {}
    newthreads = set([])
    for thread in threads:
        (pid, ppid, tid, create_time) = thread
        proc = (pid, ppid)
        if not (proc in proc2threads):
            proc2threads[proc] = set([])
        th = (tid,create_time)
        newthreads.add(th)
        proc2threads[proc].add(th)
        if th in thread2proc:
            assert proc == thread2proc[th]
        thread2proc[th] = proc
    threads = newthreads


    # again through the pandalog, this time to get
    # mappings for processes as well as tids for a process
    # and names for each tid
    mappings = {}
    tid_names = {}
    tids = {}
    num_discard = 0
    num_keep = 0
    num_mappings = 0
    num_no_mappings = 0
    xmllint = set([])
    libxml = set([])
    with PLogReader(args.pandalog) as plr:
        for i, msg in enumerate(plr):
            # this msg is the output of loaded_libs plugin
            if msg.HasField("asid_libraries"):
                al = msg.asid_libraries                
                if (al.succeeded == False) or \
                   (al.pid == 0) or (al.ppid == 0) or (al.tid == 0):
                    these_mappings = None                        
                    num_no_mappings += 1
                    continue
                thread = (al.tid, al.create_time)
                process = (al.pid, al.ppid)
                # mappings in this plog entry
                these_mappings = []
                for mapping in al.modules:
                    mp = (mapping.name, mapping.file, mapping.base_addr, mapping.size)
                    if "xmllint" in mapping.name:
                        xmllint.add(mp)
                    if "libxml" in mapping.name:
                        libxml.add(mp)
                    these_mappings.append(mp)
                num_mappings += 1                
                # collect mappings for this process, which 
                # are bundled with instr count and asid
                # which we need to interpret base_addr
                if not (process in mappings):
                    mappings[process] = [(msg.instr, msg.asid, these_mappings)]
                else:
                    (x,last_asid,last_mappings) = mappings[process][-1]
                    if these_mappings == last_mappings and msg.asid == last_asid:
                        num_discard += 1
                    else:
                        mappings[process].append((msg.instr,msg.asid,these_mappings))
                        num_keep += 1
                thread2proc[thread] = process
                # there might be several names for a tid
                if not (thread in tid_names):
                    tid_names[thread] = set([])
                if not (process in tids):
                    tids[process] = set([])
                tid_names[thread].add(al.proc_name)
                tids[process].add(al.tid)


    print "Num mappings = %d" % num_mappings
    print "Num no_mappings = %d" % num_no_mappings

    print "Kept %d of %d mappings (%f percent)" % \
        (num_keep, (num_keep+num_discard), 100 * (float(num_keep) / (num_keep+num_discard)))

    print "%d processes" % (len(processes))
    for process in processes:
        print "proc %d %d" % process
        for thread in proc2threads[process]:
            (tid,create_time) = thread
            print "** thread %d %d %s" % (tid, create_time, str(tid_names[thread]))

    # construct db process, and for each, 
    # create associated threads and mappings and connect them up

    db_sav_procs = {}
    db_sav_threads = {}
    db_sav_mappings = {}
    for process, mapping_list in mappings.items():
        (pid,ppid) = process
        if debug:
            print ("Creating db process pid-%d ppid=%d for execution" % process)
        # why doesn't proc have a create_time?
        # bc all its threads do and the thread with earliest
        # create_time is create time of process, I think.
        db_proc = pe.Process(pid=pid, ppid=ppid, execution=db_execution)
        db_threads = []
        for thread in proc2threads[process]:
            (tid, thread_create_time) = thread
            db_thread = pe.Thread(names=list(tid_names[thread]), tid=tid, \
                                  create_time = thread_create_time)
            db_threads.append(db_thread)
            db_sav_threads[thread] = db_thread
            if debug:
                print ("** Creating thread for that process names=[%s] tid=%d create_time=%d" % \
                       (str(tid_names[thread]), tid, thread_create_time))
        db_proc.threads = db_threads
        db_mappings = []
        for (instr,asid,one_mappings) in mapping_list:
            for mapping in one_mappings:
                (m_name, m_file, m_base, m_size) = mapping
                db_va = pe.VirtualAddress(asid=asid, execution_offset=instr, address=m_base, execution=db_execution)
#                db_sav_vas_base[(asid,instr,m_base)] = db_va
                if debug: 
                    print ("** Creating virtual addr for base for module in that process asid=%x base=%x instr=%d" % \
                           (asid, m_base, instr))
                db_mapping = pe.Mapping(name=m_name, path=m_file, base=db_va, size=m_size)
                if debug:
                    print ("** Creating mapping for that process name=%s path=%s base=that virtual addr size=%d" % \
                           (m_name, m_file, m_size))
                db_mappings.append(db_mapping)
        
        db_proc.mappings = db_mappings
        db_sav_procs[process] = db_proc
        db.add(db_proc)

    print ("FOO")
    db.commit()

    # find mapping that corresponds best to this code point
    # at this instr count
    def get_module_offset(cp):
        thread = (cp.thread.tid, cp.thread.create_time)
        if not (thread in thread2proc):
            return None
        process = thread2proc[thread]
        last_mappings = None
        for mapping_process, mtup_list in mappings.items():
            if mapping_process == process:
                # the process for this mapping is same as for code point  
                # now find best mapping for instr count of code point
                for mtup in mtup_list:
                    (mapping_instr, mapping_asid, mapping_list) = mtup
 #                   print "mapping_instr = " + (str(mapping_instr))
                    if mapping_instr <= cp.instr:
                        # instr count for this mapping is *prior 
                        # to the instr count of the Code point
                        last_mappings = mtup
#                        print "too early"
                    if mapping_instr > cp.instr:
                        # this mapping is for *after our code point
                        # instr count, so we'll use last_mappings
                        # if we have it
#                        print "too late"
                        if last_mappings is None:
                            # we dont.  fail
                            return None
                        # ok we have a mapping.  see if it contains
                        # our code point pc
                        (mapping_instr, mapping_asid, mapping_list) = last_mappings
                        for mapping in mapping_list:
                            (name, filename, base, size) = mapping
                            if cp.pc >= base and cp.pc <= (base+size-1):
                                # found a mapping that contains our pc
#                                print "found a mapping instr=%d pc=%x " % (cp.instr, cp.pc)
                                return (mapping_instr, mapping, cp.pc - base)
        return None
        
    
    # required = True means caller thinks this va MUST exist
#    def get_db_va(execution, asid, instr, addr, required):
#        return db_sav_vas_base[(asid,instr,add)]
#        db_addr = db.query(pe.VirtualAddress).filter_by(asid=asid, execution_offset=instr, address=addr, execution=execution)        
#        if db_addr is None:
#            if required:
#                print "get_dn_va failed to find row in db when caller thought it was def there."
#                assert (not (db_addr is None))
#            return None
#        assert (db_addr.count() == 1)
#        return db_addr.first()

 

    # find db rows for process and thread indicated, if its there.
    def get_db_process_thread(db_execution, thr):
        thread = (thr.tid, thr.create_time)
        if not (thread in db_sav_threads):
            return None
        db_thread = db_sav_threads[thread]
        if not (thread in thread2proc):
            return None
        process = thread2proc[thread]        
        if not (process in db_sav_procs):
            return None
        return (db_sav_procs[process], db_thread)


    def get_db_mapping(execution, db_process, asid, instr, mapping, True):
        (name, filename, base, size) = mapping
        # since instr is of a read/write, we need to *create* this va
        # as there's no reason to expect it will already be in the db
        db_va = pe.VirtualAddress(asid=asid, execution_offset=instr, address=base, execution=execution)
        # ditto since this mapping uses a virt address indexed to an instr,
        # we dont imagine it will already be there. so create.
        db_mapping = pe.Mapping(name=name, path=filename, base=db_va, size=size)
        # and we need to make sure mapping is assocated with our process, right?
        db_proc.mappings.append(db_mapping)
        return db_mapping

    # debugging stuff... 
    def in_xmllint(pc):
        intervals = [
            (0x555555563000, 2150400),
            (0x555555554000, 2211840),
            (0x555555554000, 61440),
            (0x555555762000, 8192),
            (0x555555763000, 4096),
            (0x555555762000, 4096)]
        for (base,size) in intervals:
            if (pc >= base and pc <= (base+size)):
                return True            
        return False
        
    def in_libxml(pc):
        intervals = [
            (0x7ffff7dd2000,8192),
            (0x7ffff7a77000,1392640),
            (0x7ffff7dca000,40960),
            (0x7ffff7a77000,3530752),
            (0x7ffff7dca000,32768),
            (0x7ffff7bcb000,2138112),
            (0x7ffff7dd4000,4096),
            (0x7ffff7dca000,45056),
            (0x7ffff7bcb000,2093056)]
        for (base,size) in intervals:
            if (pc >= base and pc <= (base+size)):
                return True            
        return False



    # another pass over the plog to
    # read Flows from tsm and transform them
    # into module/offset
    next_instr = 10000
    num_write_read_flows = 0
    code_points = set([])
    with PLogReader(args.pandalog) as plr:
        for i, msg in enumerate(plr):
            if msg.instr > next_instr:
                print "Hit instr=%d num_write_read_flow=%d time=%.2f sec" % \
                    (next_instr, num_write_read_flows, time.time() - start_time)
                next_instr += 10000
            
            if msg.HasField("write_read_flow"):
                wrf = msg.write_read_flow
#                if msg.instr > 2100000:
#                    print "wrf src=0x%x dest=0x%x" % (wrf.src.pc, wrf.dest.pc)
#                else:
#                    continue
#                both = True
#                print "src=%x dest=%x" % (wrf.src.pc, wrf.dest.pc)
#                if in_xmllint(wrf.src.pc) or in_libxml(wrf.src.pc):
#                    print "src is in xmllint/libxml"
#                else: 
#                    both = False
#                if in_xmllint(wrf.dest.pc) or in_libxml(wrf.dest.pc):
#                    print "dest is in xmllint/libxml"
#                else:
#                    both = False
#                if both:
#                    print "Both"

                pt = get_db_process_thread(db_execution, wrf.src.thread)
                if pt is None:
#                    print "src proc/thread doesnt exit"
                    continue
                (db_src_process, db_src_thread) = pt
                pt = get_db_process_thread(db_execution, wrf.dest.thread)
                if pt is None:
#                    print "dest proc/thread doesnt exit"
                    continue
                (db_dest_process, db_dest_thread) = pt

                src_mo = get_module_offset(wrf.src)
                dest_mo = get_module_offset(wrf.dest)
                if (src_mo is None) or (dest_mo is None):
                    continue

#                print "Adding a WriteReadFlow! %s -> %s" % (str(src_mo), str(dest_mo))

                (src_mapping_instr, src_mapping, src_offset) = src_mo
                (dest_mapping_instr, dest_mapping, dest_offset) = dest_mo

                db_src_mapping = get_db_mapping(db_execution, db_src_process, msg.asid, src_mapping_instr, src_mapping, True)
                db_dest_mapping = get_db_mapping(db_execution, db_dest_process, msg.asid, dest_mapping_instr, dest_mapping, True)
                    
                p_src = (db_src_mapping, src_offset)
                p_dest = (db_dest_mapping, dest_offset)
                
                if (p_src in code_points) or (p_dest in code_points):
                    print "WATTTT"

                db_src_code_point = pe.CodePoint(mapping=db_src_mapping, offset=src_offset)
                db_dest_code_point = pe.CodePoint(mapping=db_dest_mapping, offset=dest_offset)

                code_points.add(p_src)
                code_points.add(p_dest)

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
                num_write_read_flows += 1
                
    print "db commit..."
    db.commit()
    print "final time: %.2f sec" % (time.time() - start_time)