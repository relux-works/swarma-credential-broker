# Restrict only this owned process tree: ptrace returns EPERM; other calls remain available.
import ctypes,errno,os,platform,sys
assert platform.machine()=='x86_64'
class Filter(ctypes.Structure):
 _fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
class Program(ctypes.Structure):
 _fields_=[('len',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]
rules=(Filter*4)(Filter(0x20,0,0,0),Filter(0x15,0,1,101),Filter(0x06,0,0,0x50000|errno.EPERM),Filter(0x06,0,0,0x7fff0000))
program=Program(4,rules);libc=ctypes.CDLL(None,use_errno=True)
assert libc.prctl(38,1,0,0,0)==0,ctypes.get_errno()
assert libc.prctl(22,2,ctypes.byref(program),0,0)==0,ctypes.get_errno()
os.execvp(sys.argv[1],sys.argv[1:])
