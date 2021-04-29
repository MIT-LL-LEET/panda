import sys
from plog_reader import PLogReader

def hasfield(msg, field_name):
    try:
        if msg.HasField(field_name):
            return True
        else:
            return False
    except:
        return False


num_copies = 0
num_compute = 0
num_flow = 0
num_kinds = {}

with open("tsmstat.out", "w") as outp:

    with PLogReader(sys.argv[1]) as plr:
        for i,m in enumerate(plr):
            if hasfield(m, "taint_flow"):
                num_flow += 1
                tf = m.taint_flow
                if tf.copy:
                    num_copies += 1
                    outp.write("COPY %d\n" % (tf.sink.instr - tf.source.instr))
                else:
                    num_compute += 1
                    outp.write("COMPUTE %d\n" % (tf.sink.instr - tf.source.instr))
                kind = ("st" if tf.source.is_store else "ld") + "-" + ("st" if tf.sink.is_store else "ld")
                if not (kind in num_kinds):
                    num_kinds[kind] = 1
                else:
                    num_kinds[kind] += 1
                
                
print("%d flows" % num_flow)
print("%d are copies" % num_copies)
print("%d compute" % num_compute)

for kind in num_kinds.keys():
    print ("%d %s" % (num_kinds[kind], kind))

