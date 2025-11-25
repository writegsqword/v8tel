import gdb
import sys
from typing import Callable




def u32(val : bytes, endianness = None, **kwargs):
    assert(len(val) == 4)
    return int.from_bytes(val, 'little')



class GDBCommand(gdb.Command):
    def __init__(
        self,
        #debugger: GDB,
        name: str,
        handler: Callable[[str, bool], None],
        doc: str | None,
    ):
        #self.debugger = debugger
        self.handler = handler
        self.__doc__ = doc
        super().__init__(name, gdb.COMMAND_USER, gdb.COMPLETE_EXPRESSION)

    def invoke(self, args: str, from_tty: bool) -> None:
        self.handler(
            #self.debugger, 
            args, from_tty)
        

def get_thread_id():
    th = gdb.selected_thread()
    assert(th)
    pid, lwp, tid = th.ptid
    return lwp or tid


        
G_cagebase = -1
def resolve_cagebase():
    #return int(gdb.parse_and_eval('v8::internal::MainCage::base_'))
    return int(str(gdb.parse_and_eval("(long long)_ZN2v88internal8MainCage5base_E")), base=0)
    #TODO: resolve by heuristic
    

def get_cagebase(args, from_tty):
    print("cage base")
    print(hex(resolve_cagebase()))
    

def is_tagged_ptr(val):
    return val & 1 == 1



def v8tel_main(args : str, from_tty : bool):

    _argv = args.split(" ")
    arg_var_count = 10
    arg_start_addr = 0
    
    cagebase = resolve_cagebase()
    
    #first element will always exist
    if len(_argv[0]) > 0:
        arg_start_addr = int(_argv[0], base=0)
    if len(_argv) >= 2:
        arg_start_addr = int(_argv[1], base=0)
        
        
    #fix start address based on heuristics
    if cagebase <= arg_start_addr <= cagebase + int(2**32):
        arg_start_addr -= cagebase
    if is_tagged_ptr(arg_start_addr):
        arg_start_addr -= 1
    read_len = arg_var_count * 4
    inferior = gdb.selected_inferior()
    
    dump = bytes(inferior.read_memory(cagebase + arg_start_addr, read_len))
    for off in range(0, len(dump), 4):
        addr = arg_start_addr + off
        val = u32(dump[off:off+4])
        refchain = []
        addr_explore = val
        max_depth = 3
        depth = 1
        while is_tagged_ptr(addr_explore + cagebase) and depth < max_depth:
            depth += 1
            addr_explore = u32(bytes(inferior.read_memory(addr_explore + cagebase - 1, 4)))
            refchain.append(addr_explore)
        res_str = f"{hex(addr)}| {hex(val)}"
        for v in refchain:
            res_str += f"-> {hex(v)} "
            
        
        print(res_str)
        
        
    
    #print(args)
    
    


cmd = GDBCommand("v8tel", v8tel_main, "hi")
cmd2 = GDBCommand("cagebase", get_cagebase, "hi")