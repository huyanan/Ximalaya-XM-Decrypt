import base64
import io
import sys
import magic
import pathlib
import os
import glob
import mutagen
import argparse

# 尝试导入 tkinter，如果失败则设为 None
try:
    import tkinter as tk
    from tkinter import filedialog
    HAS_TKINTER = True
except ImportError:
    HAS_TKINTER = False

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from mutagen.easyid3 import ID3

# 尝试使用 wasmtime（推荐，支持 macOS arm64），如果失败则尝试 wasmer
try:
    import wasmtime
    USE_WASMTIME = True
except ImportError:
    USE_WASMTIME = False
    try:
        from wasmer import Store, Module, Instance, Uint8Array, Int32Array, engine
        from wasmer_compiler_cranelift import Compiler
        USE_WASMTIME = False
    except ImportError:
        raise ImportError("需要安装 wasmtime 或 wasmer。推荐使用: pip install wasmtime")


class XMInfo:
    def __init__(self):
        self.title = ""
        self.artist = ""
        self.album = ""
        self.tracknumber = 0
        self.size = 0
        self.header_size = 0
        self.ISRC = ""
        self.encodedby = ""
        self.encoding_technology = ""

    def iv(self):
        if self.ISRC != "":
            return bytes.fromhex(self.ISRC)
        return bytes.fromhex(self.encodedby)


def get_str(x):
    if x is None:
        return ""
    return x


def read_file(x):
    with open(x, "rb") as f:
        return f.read()


# return number of id3 bytes
def get_xm_info(data: bytes):
    # print(EasyID3(io.BytesIO(data)))
    id3 = ID3(io.BytesIO(data), v2_version=3)
    id3value = XMInfo()
    id3value.title = str(id3["TIT2"])
    id3value.album = str(id3["TALB"])
    id3value.artist = str(id3["TPE1"])
    id3value.tracknumber = int(str(id3["TRCK"]))
    id3value.ISRC = "" if id3.get("TSRC") is None else str(id3["TSRC"])
    id3value.encodedby = "" if id3.get("TENC") is None else str(id3["TENC"])
    id3value.size = int(str(id3["TSIZ"]))
    id3value.header_size = id3.size
    id3value.encoding_technology = str(id3["TSSE"])
    return id3value


def get_printable_count(x: bytes):
    i = 0
    for i, c in enumerate(x):
        # all pritable
        if c < 0x20 or c > 0x7e:
            return i
    return i


def get_printable_bytes(x: bytes):
    return x[:get_printable_count(x)]


def xm_decrypt(raw_data):
    # load xm encryptor
    # print("loading xm encryptor")
    wasm_bytes = pathlib.Path("./xm_encryptor.wasm").read_bytes()
    
    if USE_WASMTIME:
        # 使用 wasmtime
        engine = wasmtime.Engine()
        module = wasmtime.Module(engine, wasm_bytes)
        store = wasmtime.Store(engine)
        instance = wasmtime.Instance(store, module, [])
        exports = instance.exports(store)
        memory = exports['i']  # WASM 文件导出的内存名称是 'i'
        func_a = exports['a']
        func_c = exports['c']
        func_g = exports['g']
    else:
        # 使用 wasmer
        xm_encryptor = Instance(Module(
            Store(engine.Universal(Compiler)),
            wasm_bytes
        ))
    
    # decode id3
    xm_info = get_xm_info(raw_data)
    # print("id3 header size: ", hex(xm_info.header_size))
    encrypted_data = raw_data[xm_info.header_size:xm_info.header_size + xm_info.size:]

    # Stage 1 aes-256-cbc
    xm_key = b"ximalayaximalayaximalayaximalaya"
    # print(f"decrypt stage 1 (aes-256-cbc):\n"
    #       f"    data length = {len(encrypted_data)},\n"
    #       f"    key = {xm_key},\n"
    #       f"    iv = {xm_info.iv().hex()}")
    cipher = AES.new(xm_key, AES.MODE_CBC, xm_info.iv())
    de_data = cipher.decrypt(pad(encrypted_data, 16))
    # print("success")
    # Stage 2 xmDecrypt
    de_data = get_printable_bytes(de_data)
    track_id = str(xm_info.tracknumber).encode()
    
    if USE_WASMTIME:
        # wasmtime API
        stack_pointer = func_a(store, -16)
        assert isinstance(stack_pointer, int)
        de_data_offset = func_c(store, len(de_data))
        assert isinstance(de_data_offset, int)
        track_id_offset = func_c(store, len(track_id))
        assert isinstance(track_id_offset, int)
        
        # 写入内存
        memory.write(store, de_data, de_data_offset)
        memory.write(store, track_id, track_id_offset)
        
        # 调用解密函数
        func_g(store, stack_pointer, de_data_offset, len(de_data), track_id_offset, len(track_id))
        
        # 读取结果
        import struct
        stack_data = memory.read(store, stack_pointer, stack_pointer + 16)
        result_pointer = struct.unpack('<i', stack_data[0:4])[0]
        result_length = struct.unpack('<i', stack_data[4:8])[0]
        assert struct.unpack('<i', stack_data[8:12])[0] == 0
        assert struct.unpack('<i', stack_data[12:16])[0] == 0
        result_data = memory.read(store, result_pointer, result_pointer + result_length).decode()
    else:
        # wasmer API
        stack_pointer = xm_encryptor.exports.a(-16)
        assert isinstance(stack_pointer, int)
        de_data_offset = xm_encryptor.exports.c(len(de_data))
        assert isinstance(de_data_offset, int)
        track_id_offset = xm_encryptor.exports.c(len(track_id))
        assert isinstance(track_id_offset, int)
        memory_i = xm_encryptor.exports.i
        memview_unit8: Uint8Array = memory_i.uint8_view(offset=de_data_offset)
        for i, b in enumerate(de_data):
            memview_unit8[i] = b
        memview_unit8: Uint8Array = memory_i.uint8_view(offset=track_id_offset)
        for i, b in enumerate(track_id):
            memview_unit8[i] = b
        # print(bytearray(memory_i.buffer)[track_id_offset:track_id_offset + len(track_id)].decode())
        # print(f"decrypt stage 2 (xmDecrypt):\n"
        #       f"    stack_pointer = {stack_pointer},\n"
        #       f"    data_pointer = {de_data_offset}, data_length = {len(de_data)},\n"
        #       f"    track_id_pointer = {track_id_offset}, track_id_length = {len(track_id)}")
        # print("success")
        xm_encryptor.exports.g(stack_pointer, de_data_offset, len(de_data), track_id_offset, len(track_id))
        memview_int32: Int32Array = memory_i.int32_view(offset=stack_pointer // 4)
        result_pointer = memview_int32[0]
        result_length = memview_int32[1]
        assert memview_int32[2] == 0, memview_int32[3] == 0
        result_data = bytearray(memory_i.buffer)[result_pointer:result_pointer + result_length].decode()
    
    # Stage 3 combine
    # print(f"Stage 3 (base64)")
    decrypted_data = base64.b64decode(xm_info.encoding_technology + result_data)
    final_data = decrypted_data + raw_data[xm_info.header_size + xm_info.size::]
    # print("success")
    return xm_info, final_data


def find_ext(data):
    exts = ["m4a", "mp3", "flac", "wav"]
    value = magic.from_buffer(data).lower()
    for ext in exts:
        if ext in value:
            return ext
    raise Exception(f"unexpected format {value}")


def decrypt_xm_file(from_file, output_path='./output'):
    print(f"正在解密{from_file}")
    data = read_file(from_file)
    info, audio_data = xm_decrypt(data)
    output = f"{output_path}/{replace_invalid_chars(info.album)}/{replace_invalid_chars(info.title)}.{find_ext(audio_data[:0xff])}"
    if not os.path.exists(f"{output_path}/{replace_invalid_chars(info.album)}"):
        os.makedirs(f"{output_path}/{replace_invalid_chars(info.album)}")
    buffer = io.BytesIO(audio_data)
    tags = mutagen.File(buffer, easy=True)
    tags["title"] = info.title
    tags["album"] = info.album
    tags["artist"] = info.artist
    print(tags.pprint())
    tags.save(buffer)
    with open(output, "wb") as f:
        buffer.seek(0)
        f.write(buffer.read())
    print(f"解密成功，文件保存至{output}！")


def replace_invalid_chars(name):
    invalid_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
    for char in invalid_chars:
        if char in name:
            name = name.replace(char, " ")
    return name


def select_file():
    if HAS_TKINTER:
        root = tk.Tk()
        root.withdraw()
        file_path = filedialog.askopenfilename()
        root.destroy()
        return file_path
    else:
        # 如果没有 tkinter，使用命令行输入
        file_path = input("请输入要解密的 .xm 文件路径: ").strip()
        if not file_path:
            return ""
        if not os.path.exists(file_path):
            print(f"错误：文件不存在: {file_path}")
            return ""
        return file_path


def select_directory():
    if HAS_TKINTER:
        root = tk.Tk()
        root.withdraw()
        directory_path = filedialog.askdirectory()
        root.destroy()
        return directory_path
    else:
        # 如果没有 tkinter，使用命令行输入
        directory_path = input("请输入目录路径: ").strip()
        if not directory_path:
            return ""
        if not os.path.exists(directory_path):
            print(f"错误：目录不存在: {directory_path}")
            return ""
        if not os.path.isdir(directory_path):
            print(f"错误：路径不是目录: {directory_path}")
            return ""
        return directory_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="喜马拉雅音频解密工具 - 解密 .xm 文件为普通音频格式",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 解密单个文件
  python main.py -f /path/to/file.xm
  
  # 批量解密目录中的所有 .xm 文件
  python main.py -d /path/to/xm/files
  
  # 指定输出目录
  python main.py -f /path/to/file.xm -o /path/to/output
        """
    )
    parser.add_argument("-f", "--file", help="要解密的单个 .xm 文件路径")
    parser.add_argument("-d", "--directory", help="包含 .xm 文件的目录路径（批量解密）")
    parser.add_argument("-o", "--output", default="./output", help="输出目录路径（默认: ./output）")
    
    args = parser.parse_args()
    
    # 如果提供了命令行参数，使用命令行模式
    if args.file or args.directory:
        files_to_decrypt = []
        
        if args.file:
            if not os.path.exists(args.file):
                print(f"错误：文件不存在: {args.file}")
                sys.exit(1)
            if not args.file.endswith(".xm"):
                print(f"警告：文件扩展名不是 .xm: {args.file}")
            files_to_decrypt = [args.file]
        elif args.directory:
            if not os.path.exists(args.directory):
                print(f"错误：目录不存在: {args.directory}")
                sys.exit(1)
            files_to_decrypt = glob.glob(os.path.join(args.directory, "*.xm"))
            if not files_to_decrypt:
                print(f"错误：在目录中未找到 .xm 文件: {args.directory}")
                sys.exit(1)
        
        output_path = args.output
        print(f"输出目录: {output_path}")
        print(f"找到 {len(files_to_decrypt)} 个文件待解密\n")
        
        for file in files_to_decrypt:
            try:
                decrypt_xm_file(file, output_path)
            except Exception as e:
                print(f"解密文件 {file} 时出错: {e}")
                continue
        
        print("\n所有文件处理完成！")
    else:
        # 交互式模式
        if not HAS_TKINTER:
            print("注意：未检测到 tkinter 支持，将使用命令行输入模式")
            print()
        
        while True:
            print("欢迎使用喜马拉雅音频解密工具")
            print("本工具仅供学习交流使用，严禁用于商业用途")
            print("请选择您想要使用的功能：")
            print("1. 解密单个文件")
            print("2. 批量解密文件")
            print("3. 退出")
            choice = input()
            if choice == "1" or choice == "2":
                if choice == "1":
                    files_to_decrypt = [select_file()]
                    if files_to_decrypt == [""]:
                        print("检测到文件选择被取消")
                        continue
                elif choice == "2":
                    dir_to_decrypt = select_directory()
                    if dir_to_decrypt == "":
                        print("检测到目录选择被取消")
                        continue
                    files_to_decrypt = glob.glob(os.path.join(dir_to_decrypt, "*.xm"))
                    if not files_to_decrypt:
                        print(f"在目录中未找到 .xm 文件: {dir_to_decrypt}")
                        continue
                
                print("请选择是否需要设置输出路径：（不设置默认为本程序目录下的output文件夹）")
                print("1. 设置输出路径")
                print("2. 不设置输出路径")
                choice = input()
                if choice == "1":
                    output_path = select_directory()
                    if output_path == "":
                        print("检测到目录选择被取消")
                        continue
                elif choice == "2":
                    output_path = "./output"
                else:
                    print("输入错误，使用默认输出路径")
                    output_path = "./output"
                
                for file in files_to_decrypt:
                    try:
                        decrypt_xm_file(file, output_path)
                    except Exception as e:
                        print(f"解密文件 {file} 时出错: {e}")
                        continue
            elif choice == "3":
                sys.exit()
            else:
                print("输入错误，请重新输入！")
