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
    

def is_tagged_ptr(val : int):
    return val & 1 == 1

def untag_ptr(val : int):
    return val & ~3

def read_mem(addr : int, read_len : int, cage = False):
    if cage:
        addr += resolve_cagebase()        
    return bytes(gdb.selected_inferior().read_memory(addr, read_len))

def read_u32(addr : int, cage = False):
    return u32(read_mem(addr, 4, cage))



def _get_value_info_explore(val : int, explore_chain : list[int], depth : int):
    explore_chain.append(val)
    
    if depth <= 0:
        return explore_chain
    if is_tagged_ptr(val):
        #stop exploring if ref loops
        if val in explore_chain[:-1]:
            return explore_chain
        return _get_value_info_explore(read_u32(untag_ptr(val), True), explore_chain, depth - 1)
    return explore_chain

    

def get_value_info(val : int) -> str:
    chain = _get_value_info_explore(val, [], 3)
    res = ""
    #print(chain)
    for i in range(len(chain)):
        v = chain[i]
        #tagged ptr
        if is_tagged_ptr(v):
            res += f"{hex(v)} -> "
            if i >= len(chain) - 1:
                res += '...'
        else:
            res += f"{hex(v)} ({hex(v >> 1)})"
    return res


g_last_argstr = ""
g_next_addr = 0
def v8tel_main(args : str, from_tty : bool):
    global g_last_argstr
    global g_next_addr
    _argv = args.split(" ")
    arg_var_count = 10
    arg_start_addr = 0
    
    cagebase = resolve_cagebase()
    
    #first element will always exist
    if len(_argv[0]) > 0:
        arg_start_addr = int(_argv[0], base=0)
    if len(_argv) >= 2:
        arg_var_count = int(_argv[1], base=0)
        
    #not too fond of this solution but the other way(that i know of) is wayyy too messy
    if args == g_last_argstr:
        arg_start_addr = g_next_addr
    g_last_argstr = args
    #fix start address based on heuristics
    if cagebase <= arg_start_addr <= cagebase + int(2**32):
        arg_start_addr -= cagebase
    if is_tagged_ptr(arg_start_addr):
        arg_start_addr = untag_ptr(arg_start_addr)
    read_len = arg_var_count * 4

    dump = read_mem(cagebase + arg_start_addr, read_len)
    g_next_addr = arg_start_addr + read_len
    for off in range(0, len(dump), 4):
        addr = arg_start_addr + off
        val = u32(dump[off:off+4])
        res_str = f"{hex(addr)}| " + get_value_info(val)

            
        
        print(res_str)



cmd = GDBCommand("v8tel", v8tel_main, "hi")
cmd2 = GDBCommand("cagebase", get_cagebase, "hi")