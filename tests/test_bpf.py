import ctypes
import os

libc = ctypes.CDLL("libc.so.6", use_errno=True)
__NR_bpf = 321
BPF_OBJ_GET = 7

class BpfAttrObjGet(ctypes.Structure):
    _fields_ = [
        ("pathname", ctypes.c_uint64),
        ("bpf_fd", ctypes.c_uint32),
        ("file_flags", ctypes.c_uint32),
    ]

def bpf_obj_get(pathname):
    path_bytes = pathname.encode('utf-8')
    attr = BpfAttrObjGet()
    attr.pathname = ctypes.cast(ctypes.c_char_p(path_bytes), ctypes.c_void_p).value
    attr.bpf_fd = 0
    attr.file_flags = 0
    
    # 144 bytes is the total size of union bpf_attr
    buffer = ctypes.create_string_buffer(144)
    ctypes.memmove(buffer, ctypes.byref(attr), ctypes.sizeof(attr))
    
    fd = libc.syscall(__NR_bpf, BPF_OBJ_GET, ctypes.byref(buffer), 144)
    if fd < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    return fd

if __name__ == '__main__':
    try:
        print("Testing syscall bpf_obj_get on dummy path...")
        bpf_obj_get("/sys/fs/bpf/test")
    except OSError as e:
        print("Failed as expected (likely ENOENT):", e)

