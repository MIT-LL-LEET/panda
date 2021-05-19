import sys
import random
import subprocess as sp
import pickle
from plog_reader import PLogReader



libc = "/home/tleek/tsm/libc-2.27.so"
libdl = "/home/tleek/tsm/libdl-2.27.so"
xmllint = "/home/tleek/git/panda-replays/targets/xmllint-3e7e75bed2cf2853b0d42d635d36676b3330d475-64bit-bug/install/libxml2/.libs/xmllint"
libxml = "/home/tleek/git/panda-replays/targets/xmllint-3e7e75bed2cf2853b0d42d635d36676b3330d475-64bit-bug/install/libxml2/.libs/libxml2.so"

def get_syms(libf, flag):
    outp = sp.check_output(["nm", flag, libf]).decode()
    syms = []
    for line in outp.split("\n"):
        try:
            (offsS, typ, name) = line.split(" ")
            offs = int(offsS, 16)
            if typ == 'T' or typ == 't':
                sym = (offs, name)
                syms.append(sym)
        except:
            pass
    return sorted(syms, key=lambda sym: sym[0])

syms = {}
syms["libc"] = get_syms(libc, "-D")
syms["libdl"] = get_syms(libdl, "-D")
syms["libxml"] = get_syms(libxml, "-D")
syms["xmllint"] = get_syms(xmllint, "-a")



libs_for_thread = {}
threads = set([])
thread_names = {}
num_instr = None
instr_for_overflow_map = None
l2ts = {}
uls = {}
labels_that_are_ptrs = {}
labels_that_are_branches = {}
picklefile = "tsm.pickle6"

plogfile = sys.argv[1]

pickled = False

if pickled:
    with open(picklefile, "rb") as p:
        (libs_for_thread, threads, thread_names, num_instr, \
         instr_for_overflow_map, l2ts, uls, labels_that_are_ptrs, \
         labels_that_are_branches) \
         = pickle.load(p)

        
else:

    def update_uls(tqr):
        for tq in tqr:
            if tq.HasField("unique_label_set"):
                x = tq.unique_label_set
                ls = set([])
                for l in x.label:
                    ls.add(l)
                uls[x.ptr] = ls
                

#    dfp = open("/data/tleek/delta_p", "w")
#    dfb = open("/data/tleek/delta_b", "w")
    with PLogReader(plogfile) as plr:
        for i,m in enumerate(plr):
#            if m.instr == 73:
#                print ("klsjdhf")
            if (m.instr % 100000) == 0:
                print ("instr=%d" % m.instr)
            num_instr = m.instr
            if m.HasField("asid_info"):
                ai = m.asid_info
                for tid in ai.tids:
                    thread = (tid, ai.create_time)
                    if not (thread in threads):
                        threads.add(thread)
                        thread_names[thread] = set(ai.names)
                    else:
                        thread_names[thread] = set(ai.names).union(thread_names[thread])
                for name in ai.names:
                    if "xmllint" in name:
                        print ("Saw xmllint at instr %d" % m.instr)
                        break
            if m.HasField("asid_libraries"):
                al = m.asid_libraries
                thread = (al.tid, al.create_time)
                libs = {}
                for lib in al.modules:
                    if lib.name == "[???]":
                        continue
                    libn = lib.name + ":" + lib.file
                    if (libn in libs):
                        (start,end) = libs[libn]
                        start = min(start, lib.base_addr)
                        end = max(end, lib.base_addr + lib.size)
                    else:
                        (start,end) = (lib.base_addr, lib.base_addr + lib.size)
                    libs[libn] = (start,end)                
                if len(libs) > 0:
                    if not (thread in libs_for_thread):
                        libs_for_thread[thread] = []
                    libs_for_thread[thread].append(libs)
            
            if m.HasField("taint_flow"):
                tf = m.taint_flow
                if tf.sink.is_store:
                    print ("kjdshf")


#            if m.HasField("taint_source"):
#                l2ts[int(m.taint_source.label)] = m
#                n = len(l2ts)
#                if ((n % 1000) == 0):
#                    print ("Found %d labels.  %f are pointers" % (n, (float(len(labels_that_are_ptrs))) / n))

            if m.HasField("tainted_ldst"):
                tls = m.tainted_ldst
                update_uls(tls.taint_query)
                for tq in tls.taint_query:
                    for l in uls[tq.ptr]:
                        if not l in labels_that_are_ptrs:
                            labels_that_are_ptrs[l] = set([])
                        p = (int(m.instr), int(m.pc))
                        labels_that_are_ptrs[l].add(p)
#                        dfp.write("%d\n" % (int(m.instr) - int(l2ts[l].instr)))
            if m.HasField("tainted_branch"):
                tb = m.tainted_branch
                update_uls(tb.taint_query)
                for tq in tb.taint_query:
                    for l in uls[tq.ptr]:
                        if not l in labels_that_are_branches:
                            labels_that_are_branches[l] = set([])
                        p = (int(m.instr), int(m.pc))
                        labels_that_are_branches[l].add(p)
#                        dfb.write("%d\n" % (int(m.instr) - int(l2ts[l].instr)))
                
            if m.HasField("tsm_change"):
                if (instr_for_overflow_map is None) and m.instr >= 13232800:
                    print ("instr with tsm_change post overflow block: " + str(last_instr) + " " + str(m.instr))
                    instr_for_overflow_map = last_instr
                last_instr = m.instr

    print ("Done with 1st pass. Found %d labels.  %d are pointers %d are branches" % (len(l2ts), len(labels_that_are_ptrs), len(labels_that_are_branches)))

    with open(picklefile, "wb") as p:
        everything = (libs_for_thread, threads, thread_names, num_instr, \
                      instr_for_overflow_map, l2ts, uls, labels_that_are_ptrs, \
                      labels_that_are_branches)
        pickle.dump(everything, p)
    
#    sys.exit(0)




xmllintthread = None
for thread in threads:
    if "xmllint" in thread_names[thread]:
        xmllintthread = thread
assert (not (xmllintthread is None))
xmllintlibs = None
n = len(libs_for_thread[xmllintthread])
xmllintlibs = libs_for_thread[xmllintthread][int(n*0.8)]
print(str(xmllintthread) + " " + str(thread_names[xmllintthread]))
for item in xmllintlibs.items():
    print(str(item))


c = int ((num_instr - 11063407) / 20)
tsm_spit_next = int(11063407 + c/2)


def get_mod_fn_offs(mod_name, mod_offs):
    mn = (mod_name.split('/'))[-1]
    for n in syms.keys():
        if n in mn:
            last_fn_offs = None
            last_fn_name = None
            for (fn_offs, fn_name) in syms[n]:
                if fn_offs > mod_offs:
                    return (last_fn_name, last_fn_offs)
                (last_fn_offs, last_fn_name) = (fn_offs, fn_name)
    return None

def spit(minstr):
    fn = plogfile + "tsm-%d" % minstr
    with open(fn, "w") as tsmo:
        print("Writing xmllint tsm %s -- %d" % (fn,len(xmltsm)))
        addrs = list(xmltsm.keys())
        addrs.sort()
        start = None            
        first = True
        for addr in addrs:
            if first:
                start_addr = addr
                start = xmltsm[addr]
                first = False
            elif xmltsm[addr] != start:
                # spit out last range
                (instr, mod_name, mod_offs, is_ptr, is_br) = start
                foo = get_mod_fn_offs(mod_name, mod_offs)
                success = False
                n = last_addr - start_addr + 1
                if foo:
                    (fn_name, fn_offs) = foo
                    if not(fn_name is None):
                        tsmo.write("%x[%d] (%s:%s:%x) d=%d " % (start_addr,n,mod_name,fn_name,mod_offs,minstr-instr))
                        success = True
                if not success:
                    tsmo.write("%x[%d] (%s:%x) d=%d " % (start_addr,n,mod_name,mod_offs,minstr-instr))
                if not (is_ptr == ""):
                    tsmo.write(" PTR(" + is_ptr + ")")
                if not (is_br == ""):
                    tsmo.write(" BR(" + is_br + ")")
                tsmo.write("\n")
                     
                start_addr = addr
                start = xmltsm[addr]

            last_addr = addr



last_instr = None
xmltsm = {}
ok_to_spit = False
first_instr_for_xmllint = None
with PLogReader(plogfile) as plr:
    first_instr=True
    for i,m in enumerate(plr):
        if first_instr: 
            first_instr = False
            continue
        last_instr = m.instr
        if m.HasField("tsm_change"):
            if m.instr == instr_for_overflow_map:
                spit(m.instr)
            tsm = m.tsm_change
            if tsm.vaddr <= 94355329531968 and 94355329531968 < (tsm.vaddr + tsm.size):
                print ("tsm_change for addr in questino @ instr=%d" % m.instr)
            cp = tsm.cp
            th = cp.thread
            thread = (th.tid, th.create_time)
            label = tsm.label
            if (thread == xmllintthread):  
                if first_instr_for_xmllint is None:
                    first_instr_for_xmllint = m.instr 
                    print ("saw tsm_change for xmlint at instr=%d" % m.instr)
                    ok_to_spit = True
                is_ptr = ""
                is_br = ""
                if label in labels_that_are_ptrs:
                    for (instr,pc) in labels_that_are_ptrs[label]:
                        if instr > m.instr:
                            is_ptr += " (%d,%x)" % (instr,pc)
                if label in labels_that_are_branches:
                    for (instr,pc) in labels_that_are_branches[label]:
                        if instr > m.instr:
                            is_br += " (%d,%x)" % (instr,pc)
                x = (m.instr, "unknown", tsm.cp.pc, is_ptr, is_br)
                for (module_name, (start,end)) in xmllintlibs.items():
                    if tsm.cp.pc>=start and tsm.cp.pc<end:
                        x = (m.instr, module_name, tsm.cp.pc - start, is_ptr, is_br)
                for i in range(int(tsm.size)):
                    a = int(tsm.vaddr) + i
                    xmltsm[a] = x

                    
#        if m.HasField("taint_source"):
#            ts = m.taint_source
#            label = ts.label
#            last_was_ts = True
#        else:
#            last_was_ts = False
#            label = None

#spit(last_instr)


