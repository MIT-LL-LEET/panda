
#
# autoscissors.py replay_pfx program_name scissors_pfx instr_buffer [main_offset main_module_name]
#
# This plugin analyzes a replay to find the instruction count range
# corresponding to the execution of a program and then generates a new
# replay that is scissorsed to just include that.
#
# replay_pfx is the replay prefix (full path up to '-rr-' bit)
#
# program_name is the program that was know to run during that replay;
# you want autoscissors to just pull out that part of the replay.
#
# scissors_pfx is the prefix of the new replay to create
#
# instr_buffer is the number of additional instructions to left and
# right of the inferred range to add "just in case"
# 
# main_offset is hex offset of main in its module
# 
# main_module_name is the name of the module main is in
#



import sys
from pandare import Panda
from pandare.plog_reader import PLogReader
import portion


def usage():
    print ("Usage: autoscissors.py replay_pfx program_name scissors_pfx instr_buffer [main_offset main_module_name]")
    sys.exit(1)

if (len(sys.argv) < 5):
    usage()

panda = Panda(generic="x86_64")


START_OF_MAIN = "start_of_main_mode"
mode = None


replay_pfx = sys.argv[1]
program_name = sys.argv[2]
scissors_pfx = sys.argv[3]
instr_buffer = int(sys.argv[4])
if (len(sys.argv) > 5):
    if (len(sys.argv) < 7):
        usage()
    # offset of start of main within its module
    start_of_main = int(sys.argv[5], 16)
    # name of module containing main
    module_name_main = sys.argv[6]
    mode = START_OF_MAIN

print ("poi name is [%s]" % program_name)


plogfile = "asidstory.plog"
panda.set_pandalog(plogfile)
panda.load_plugin("asidstory")
panda.load_plugin("loaded_libs")
panda.load_plugin("collect_code")
panda.run_replay(replay_pfx)
#panda.end_analysis()

# first pass through plog to 
# get set of procs (pid, create_time)
# and list of names per proc
# and loaded libs at various times

procs = set([])
proc_names = {}
with PLogReader(plogfile) as plr:
    for i, m in enumerate(plr):
        if m.HasField("asid_info"):
            ai = m.asid_info
            proc = (ai.pid, ai.create_time)
            procs.add(proc)
            if not (proc in proc_names):
                proc_names[proc] = set([])
            for name in ai.names:
                proc_names[proc].add(name)
            

print ("\nfound %d procs" % (len(procs)))
found_poi = False
for proc in procs:
    print (str(proc) + " " + (str(proc_names[proc])), end="")
    if program_name in proc_names[proc]:
        if found_poi == True:
            print ("Hmm, you seem to have more than one proc corresponding to the name %s" % program_name)
            assert (not found_poi)
        print(" <----- program of interest")
        found_poi = True
        poi = proc
    else:
        print ("")
        
if not found_poi:
    print ("Program of interest specified on cmdline not in plog?")
    assert found_poi
           

start_of_main_instr = None


print (" ")

# two modes of operation
if mode == START_OF_MAIN:
    
    # in this mode, we scissors a little before start of main
    the_module = None    
    with PLogReader(plogfile) as plr:
        for i, m in enumerate(plr):
            if m.HasField("asid_libraries"):
                al = m.asid_libraries
                the_module = None
                for module in al.modules:
                    if module_name_main in module.name:
                        mint = portion.closedopen(module.base_addr, module.base_addr + module.size)
                        if the_module is None:
                            the_module = mint
                        else:
                            the_module |= mint
#                if the_module:
#                    print (str(the_module))
            if m.HasField("basic_block"):
                if (not (the_module is None)) and (m.pc in the_module):
#                    print ("pc=%x is in toy_debug" % m.pc)
                    if m.pc - the_module.lower == start_of_main:
                        print ("saw bb that is start of main @ instr %d" % m.instr)
                        start_of_main_instr = m.instr

                        
    if start_of_main_instr is None:
        print ("Couldn't find start of main")
        assert start_of_main_instr

else:
    # in this mode, we scissors just based on asid_info ranges for poi
    pass

# second pass will find start,end instr counts for poi
# just based on asid_info ranges
# so it will include program and libs being loaded 

poi_instr_range = None 
with PLogReader(plogfile) as plr:
    for i, m in enumerate(plr):
        if m.HasField("asid_info"):
            ai = m.asid_info
            proc = (ai.pid, ai.create_time)
            if proc == poi:
                pint = portion.closed(ai.start_instr, ai.end_instr)
#                print("poi: %s" % (str(pint)))
                if poi_instr_range is None:
                    poi_instr_range = pint
                else:
                    i1 = min(poi_instr_range.lower, pint.lower)
                    i2 = max(poi_instr_range.upper,pint.upper)
                    poi_instr_range = portion.closed(i1, i2)

print ("poi instr range: %s" % (str(poi_instr_range)))

if start_of_main_instr:
    print ("adjusting instr range to start with hitting main")
    poi_instr_range = portion.closed(start_of_main_instr, poi_instr_range.upper)

print ("final poi instr range: %s" % (str(poi_instr_range)))



                    
                
#panda.set_pandalog("")
panda.unload_plugin("asidstory")
panda.unload_plugin("loaded_libs")
panda.unload_plugin("collect_code")


print ("\nScissorsing")

panda.load_plugin("scissors", 
                  args={"name": scissors_pfx,
                        "start": poi_instr_range.lower - instr_buffer,
                        "end": poi_instr_range.upper + instr_buffer})
panda.run_replay(replay_pfx)


