
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

    def __init__(self, name, pid, asid, create_time):
        self.name = name
        self.pid = pid
        self.asid = asid
        self.create_time = create_time
        
    def __repr__(self):
        return ("Process(name=%s,pid=%d,asid=0x%x,create_time=%s)" % (self.name, self.pid, self.asid, str(self.create_time)))

    def __hash__(self):
        return (hash(self.__repr__()))
    
    def __cmp__(self, other):
        return(cmp(self.__repr__(), other.__repr__()))


class AsidInfo:

    def __init__ (self, m):
        self.process = Process(m.name, m.pid, m.asid)
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
    parser.add_argument("exec_start", "--exec-start", help="Start time for execution", action="store", default=None)
    parser.add_argument("exec_end", "--exec-end", help="End time for execution", action="store", default=None)

    # must have this
    parser.add_argument("exec_name", "--exec-name", help="A name for the execution", action="store", required=True)

    args = parser.parse_args()
    db = pe.init_and_create_session(sys.argv[1], debug=True)

    ex = pe.Execution(name=args.exec_name, start_time=args.exec_start, end_time=args.exec_end)
    db.add(ex)

    asidinfos = []
    asidlibss = {}
    processes = set([])
    process_modules = {}

    # first obtain asidinfo and libraries entries
    with PLogReader(sys.argv[1]) as plr:
        for i, m in enumerate(plr):
            if m.HasField("asid_info"):
                ai = AsidInfo(m.asid_info)
                asidinfos.append(ai)
                processes.add(ai.process)
            if m.HasField("asid_libraries"):
                al = AsidLibs(m)
                if not (al.asid in asidlibss):
                    asidlibss[al.asid] = []
                asidlibss[al.asid].append(al)


    if len(asidinfos) == 0:
        print ("No asid_info entries in pandalog -- exiting\n")
        assert (len(asidinfos) > 0)

    if len(asidlibss) == 0:
        print ("No asid_libraries entries in pandalog -- exiting\n")
        assert (len(asidlibss) > 0)

    if len(processes) == 0:
        print ("No processes found -- exiting\n")
        assert (len(processes) > 0)

    print ("Found %d processes" % (len(processes)))
    for process in processes:
        print ("  %s" % process)
        assert (process.asid in asidlibss)
        idx = int(0.75 * (len(asidlibss[process.asid])))
        asidlibs=asidlibss[process.asid][idx]
        for name in asidlibs.modules.keys():
            print(asidlibs.modules[name])
        process_modules[process] = asidlibs.modules

    def getModuleOffset(cp):
        for process in process_modules.keys():
            if process.asid == cp.asid:
                for (name, module) in process_modules[process].items():
                    if module.base <= cp.pc and cp.pc < (module.base + module.size):
                        return(module.name, cp.pc - module.base)
        return None
        
    # another pass over the plog to
    # read Flows from tsm and transform them
    # into module/offset
    with PLogReader(sys.argv[1]) as plr:
        for i, m in enumerate(plr):
            if m.HasField("taint_flow"):
                tf = m.taint_flow
                src_mo = getModuleOffset(tf.src)
                dest_mo = getModuleOffset(tf.dest)
                if (src_mo is None) or (dest_mo is None):
                    continue
                (src_name, src_offs) = src_mo
                (dest_name, dest_offs) = dest_mo
                print ("instr="),
                if tf.min_instr == tf.max_instr:
                    print (tf.min_instr),
                else:
                    print ("(%d..%d)" % (tf.min_instr, tf.max_instr)),
                print (" count=%d Flow(%s -> %s)" % \
                       (tf.count, str(src_mo), str(dest_mo)))
                
