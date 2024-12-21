import ctypes
import sys
import os

def inject_dll(pid, dll_path):
    kernel32 = ctypes.windll.kernel32
    OpenProcess = kernel32.OpenProcess
    CreateRemoteThread = kernel32.CreateRemoteThread
    LoadLibraryA = kernel32.LoadLibraryA
    VirtualAllocEx = kernel32.VirtualAllocEx
    WriteProcessMemory = kernel32.WriteProcessMemory
    CloseHandle = kernel32.CloseHandle
    PROCESS_ALL_ACCESS = 0x001F0FFF
    handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if handle == 0:
        raise Exception(f"Failed to open process with PID {pid}")
    dll_path_bytes = dll_path.encode('ascii')
    dll_path_len = len(dll_path_bytes) + 1
    remote_dll_path = VirtualAllocEx(handle, None, dll_path_len, 0x00001000 | 0x00002000, 0x0040)
    if not remote_dll_path:
        raise Exception("Failed to allocate memory in target process")
    written = ctypes.c_size_t(0)
    if not WriteProcessMemory(handle, remote_dll_path, dll_path_bytes, dll_path_len, ctypes.byref(written)):
        raise Exception("Failed to write DLL path to target process")
    load_library_address = ctypes.windll.kernel32.LoadLibraryA
    thread_id = ctypes.c_ulong(0)
    if not CreateRemoteThread(handle, None, 0, load_library_address, remote_dll_path, 0, ctypes.byref(thread_id)):
        raise Exception("Failed to create remote thread")
    CloseHandle(handle)

if __name__ == "__main__":
    pid = 3752
    dll_path = os.path.join(os.path.dirname(__file__), "luh.dll") 
    try:
        inject_dll(pid, dll_path)
        print(f"Successfully injected DLL '{dll_path}' into process with PID {pid}")
    except Exception as e:
        print(f"Error injecting DLL: {e}")
