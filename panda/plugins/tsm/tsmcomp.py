import sys
import re

sys.path.append("../../scripts")
from plog_reader import PLogReader

# Input is plog1 and plog2.  Also a qemu log to get disassembly

# Compare plogs from two implementations of tsm
# Ignore details in a flow except 
#   (src.cp.pc, src.is_store, src.instr, sink.cp.pc, sink.is_store, sink.instr, (sink.instr - src.instr))
# f1 is set of such flows in plog1 and f2 is set for plog2,
#
# Report first N 
# Report 1st N discrepancies f1-f2 

# Report 1st 10 discrepancies f2-f1
# Further diagnose using qemu log to spit out all instructions in a discrepancy flow

plog1 = sys.argv[1]
plog2 = sys.argv[2]
qemulog = sys.argv[3]

def read_qemulog(qemulog):
    mode = 0 
    bbs = {}
    trace = []
    with open(qemulog, "r") as ql:
        for line in ql:
            if "IN:" in line:
                mode = 1
                bb = []
                continue
            if mode == 1:
                # collecting asm for bb
                if line.startswith("0x"):
                    bb.append(line)
                else:
                    # done with bb collection
                    start = int(bb[0].split()[0][:-1], 16)
                    bbs[start] = bb
                    mode = 0
            if "Prog point" in line:
                foo = re.search("Prog point: (0x[0-9a-f]+),([0-9]+) {guest_instr_count=([0-9]+)}", line)
                assert (not (foo is None))
                (bb_start_s, bb_len_s, instr_s) = foo.groups()
                bb_start = int(bb_start_s, 16)
                bb_len = int(bb_len_s)
                instr = int(instr_s)
                tp = (instr, bb_start, bb_len)
                trace.append(tp)
    return(bbs, trace)


# read qemu log to get instr trace but also assembly for each bb 
(bbs, trace) = read_qemulog(qemulog)

def hasfield(msg, field_name):
    try:
        if msg.HasField(field_name):
            return True
        else:
            return False
    except:
        return False

def read_taint_flows(plog):
    tfs = []
    with PLogReader(plog) as plr:
        for i,m in enumerate(plr):
            if hasfield(m, "taint_flow"):
                tfs.append(m)
    return tfs

# read taint flows for each of the plogs
flows1 = read_taint_flows(plog1)
flows2 = read_taint_flows(plog2)

def flows_set(flows):
    fls = set([])
    for msg in flows:
        src = msg.taint_flow.source
        sink = msg.taint_flow.sink
        # NB: have to -1 from instr bc its already been updated by the time we hit any callbacks
        # yes we are ignoring things like size of a flow. trying to just see if the two
        # implementations are seeing same flows between same pcs for same instr
        fs = (src.cp.pc, src.is_store, src.instr - 1, sink.cp.pc, sink.is_store, sink.instr - 1) # (sink.instr - src.instr))
        fls.add(fs)
    return fls

f1 = flows_set(flows1)
f2 = flows_set(flows2)

print ("%d flows in %s" % (len(f1), plog1))
print ("%d flows in %s" % (len(f2), plog2))


def diagnose(flow):
    (src_pc, src_is_store, src_instr, sink_pc, sink_is_store, sink_instr) = flow
    print ("%x(%d)(%d)->%x(%d)(%d)" % flow, end="")
    delta = sink_instr - src_instr
    print ("(%d)" % delta)
    if delta > 50:
        print ("  delta too big to diagnose!")
        return False
    else:
        for instr in range(src_instr, sink_instr+1):
            def find_tp(ind1, ind2):
                if ind2-ind1 <= 1:
                    return ind1
                (instr1, pc1, l1) = trace[ind1]
                (instr2, pc2, l2) = trace[ind2]
                indm = int((ind1+ind2)/2)
                (instrm, pcm, lm) = trace[indm]
                if instr < instrm:
                    return find_tp(ind1, indm)
                return find_tp(indm, ind2)
            ind_bb_start = find_tp(0, len(trace)-1)
            (bb_start_instr, bb_start_pc, len_bb) = trace[ind_bb_start]
            assert (bb_start_instr <= instr)
            asm = bbs[bb_start_pc][instr - bb_start_instr].strip()
            print ("%d %s" % (instr, asm))
        return True


#import pdb; pdb.set_trace()

for f in f2:
    (src_pc, a, src_instr, sink_pc, b, sink_instr) = f
    if src_pc == 0xffffffff810c31b5 and src_instr == 254261:
        print("at missing src")
    if sink_pc == 0xffffffff810c31dc and sink_instr == 254291:
        print ("at missing sink")


N = 25


def diag_subset(msg, flows_subset):

    counts = {}
    print("%s: subset is %d items" % (msg, len(flows_subset)))
    i = 1
    for f in flows_subset:
        (src_pc, src_is_store, src_instr, sink_pc, sink_is_store, sink_instr) = f
        fs = (src_is_store, sink_is_store)
        if not (fs in counts):
            counts[fs] = 0
        counts[fs] += 1
        if diagnose(f):
            i += 1
        print(" ")
        if i>N: 
            break
    for fs in counts.keys():
        print("%d %s" % (counts[fs], fs))


diag_subset("In both %s and %s" % (plog1, plog2), f1&f2)
diag_subset("In %s but not %s" % (plog1, plog2), f1-f2)
diag_subset("In %s but not %s" % (plog2, plog1), f2-f1)


