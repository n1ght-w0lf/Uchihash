import argparse
import sys
import os
import json
import importlib
import pathlib
import hashlib
import crcmod
import fnvhash
import mmh3

# Disable __pycache__
sys.dont_write_bytecode = True

current_path = ""
data_dir = ""
out_dir = ""

patterns = []
comments = []

crc8  = crcmod.predefined.mkCrcFun("crc-8")
crc16 = crcmod.predefined.mkCrcFun("crc-16")
crc32 = crcmod.predefined.mkCrcFun("crc-32")
crc64 = crcmod.predefined.mkCrcFun("crc-64")

def djb2(s):
    hash = 5381
    for c in s:
        hash = ((hash << 5) + hash) + c
    return hash & 0xffffffff

def sdbm(s):
    hash = 0
    for c in s:
        hash = c + (hash << 6) + (hash << 16) - hash
    return hash & 0xffffffff

def loselose(s):
    hash = 0
    for c in s:
        hash += c
    return hash & 0xffffffff

def hashme(s, hashType):
    if hashType == "md4":
        return "0x" + hashlib.new("md4", s).hexdigest()
    elif hashType == "md5":
        return "0x" + hashlib.new("md5", s).hexdigest()
    elif hashType == "sha1":
        return "0x" + hashlib.new("sha1", s).hexdigest()
    elif hashType == "sha224":
        return "0x" + hashlib.new("sha224", s).hexdigest()
    elif hashType == "sha256":
        return "0x" + hashlib.new("sha256", s).hexdigest()
    elif hashType == "sha384":
        return "0x" + hashlib.new("sha384", s).hexdigest()
    elif hashType == "sha512":
        return "0x" + hashlib.new("sha512", s).hexdigest()
    elif hashType == "ripemd160":
        return "0x" + hashlib.new("ripemd160", s).hexdigest()
    elif hashType == "whirlpool":
        return "0x" + hashlib.new("whirlpool", s).hexdigest()
    elif hashType == "crc8":
        return hex(crc8(s))
    elif hashType == "crc16":
        return hex(crc16(s))
    elif hashType == "crc32":
        return hex(crc32(s))
    elif hashType == "crc64":
        return hex(crc64(s))
    elif hashType == "djb2":
        return hex(djb2(s))
    elif hashType == "sdbm":
        return hex(sdbm(s))
    elif hashType == "loselose":
        return hex(loselose(s))
    elif hashType == "fnv1_32":
        return hex(fnvhash.fnv1_32(s))
    elif hashType == "fnv1a_32":
        return hex(fnvhash.fnv1a_32(s))
    elif hashType == "fnv1_64":
        return hex(fnvhash.fnv1_64(s))
    elif hashType == "fnv1a_64":
        return hex(fnvhash.fnv1a_64(s))
    elif hashType == "murmur3": # this might also take a different seed
        return hex(mmh3.hash(s, signed=False))

def build_patterns_and_comments(hashes):
    global patterns, comments

    for h, v in hashes.items():
        h = h[2:]
        h = (len(h)%2 * '0') + h  # padding with '0' if odd length
        h = [h[i:i+2] for i in range(0, len(h), 2)]
        patterns.append(" ".join(h[::-1]))  # search uses little endian
        comments.append(v)

def calc_hashes(filename, algo):
    global patterns, comments

    hashes = {}
    if filename == "apis_list.txt" or filename == "keywords_list.txt":
        file_path = os.path.join(data_dir, filename)
    else:
        file_path = filename
    with open(file_path) as apis:
        for line in apis:
            line = line.strip()
            hashval = hashme(line.encode(), algo)
            hashes[hashval] = line

    with open(os.path.join(out_dir, "hashmap.txt"), "w") as f:
        json.dump(hashes, f, indent=2)
        print("[+] Hashmap written to output folder")
        build_patterns_and_comments(hashes)

def calc_custom_hash(filename, scriptpath):
    global patterns, comments

    sys.path.append(str(pathlib.PurePath(scriptpath).parent))
    script = importlib.import_module(pathlib.PurePath(scriptpath).stem)
    
    hashes = {}
    if filename == "apis_list.txt" or filename == "keywords_list.txt":
        file_path = os.path.join(data_dir, filename)
    else:
        file_path = filename
    with open(file_path) as apis:
        for line in apis:
            line = line.strip()
            hashval = script.hashme(line.encode())
            hashes[hashval] = line

    with open(os.path.join(out_dir, "hashmap.txt"), "w") as f:
        json.dump(hashes, f, indent=2)
        print("[+] Hashmap written to output folder")
        build_patterns_and_comments(hashes)

def search_hashes(search_file, hlist, gida):
    global patterns, comments

    with open(search_file) as f:
        hash_list = json.load(f)

    hashes = {}
    with open(hlist) as f:
        for line in f:
            line = hex(int(line.strip(), 16))
            val = hash_list.get(line)
            hashes[line] =  val if val != None else "UNKNOWN"

    with open(os.path.join(out_dir, "search_hashmap.txt"), "w") as f:
        json.dump(hashes, f, indent=2)
        print("[+] Search hashmap written to output folder")
        build_patterns_and_comments(hashes)

def generate_idaidc():
    global patterns, comments

    # Builld patterns array str
    patterns_str = ""
    for i in range(len(patterns)):
        patterns_str += f'    patterns[{i}] = "{patterns[i]}";\n'

    # Builld comments array str
    comments_str = ""
    for i in range(len(comments)):
        comments_str += f'    comments[{i}] = "{comments[i]}";\n'

    script = f"""// IDC script to comment hash values

#include <idc.idc>

static main()
{{
    auto patterns = object();
{patterns_str}
    auto comments = object();
{comments_str}

    auto i;
    for (i = 0; i < {len(patterns)}; i++)
    {{
        auto addr = get_inf_attr(INF_MIN_EA);
        while (1)
        {{
            addr = find_binary(addr, BADADDR, patterns[i]);
            if (addr == BADADDR)
                break;
            auto insn_head = addr;
            if (!is_head(get_full_flags(addr)))
            {{
                insn_head = prev_head(addr, 0);
            }}
            Message("0x%x: %s\\n", addr, comments[i]);
            set_cmt(insn_head, comments[i], 1);
        }}
    }}
}}
"""
    
    with open(os.path.join(out_dir, "idc_script.idc"), "w") as f:
        f.write(script)
        print("[+] IDC script written to output folder")

def generate_idapython():
    global patterns, comments

    script = f"""# IDAPython script to comment hash values

# set comment in decompiled code
def set_hexrays_comment(address, text):
    cfunc = idaapi.decompile(address)
    tl = idaapi.treeloc_t()
    tl.ea = address
    tl.itp = idaapi.ITP_SEMI
    cfunc.set_user_cmt(tl, text)
    cfunc.save_user_cmts() 

def set_comment(address, text):
    try:
        idc.set_cmt(address, text, 1)
        set_hexrays_comment(address, text)
    except Exception as e:
        print(e)
        return

patterns = {patterns}
comments = {comments}

for i in range(len(patterns)):
    addr = idc.get_inf_attr(INF_MIN_EA)
    while True:
        addr = ida_search.find_binary(addr, idc.BADADDR, patterns[i], 16, ida_search.SEARCH_NEXT | ida_search.SEARCH_DOWN)
        if addr == idc.BADADDR: break
        insn_head = addr
        if not idc.is_head(idc.get_full_flags(addr)):
            insn_head = prev_head(addr)
        print(f"0x{{addr:X}}: {{comments[i]}}")
        set_comment(insn_head, comments[i])
"""
    
    with open(os.path.join(out_dir, "idapython_script.py"), "w") as f:
        f.write(script)
        print("[+] IDAPython script written to output folder")

def check_outdir():
    global current_path, data_dir, out_dir

    current_path = pathlib.Path(__file__).parent.absolute()
    data_dir = os.path.join(current_path, "data")
    out_dir = os.path.join(current_path, "output")
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

def main():
    check_outdir()
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, epilog="""Examples:
    * python uchihash.py --algo crc32 --apis
    * python uchihash.py --algo murmur3 --list mywords.txt
    * python uchihash.py --script myalgo.py --apis --idapython
    * python uchihash.py --search hashmap.txt --hashes myhashes.txt
    """)
    parser.add_argument("--algo", help="Hashing algorithm")
    parser.add_argument("--apis", action="store_true", help="Calculate hashes of APIs")
    parser.add_argument("--keywords", action="store_true", help="Calculate hashes of keywords")
    parser.add_argument("--list", help="Calculate hashes of your own word list")
    parser.add_argument("--script", help="Script file containing your custom hashing algorithm")
    parser.add_argument("--search", help="Search a JSON File containing hashes mapped to words")
    parser.add_argument("--hashes", help="File containing list of hashes to search for")
    parser.add_argument("--idaidc", action="store_true", help="Generate an IDC script to annotate hash values in IDA Pro")
    parser.add_argument("--idapython", action="store_true", help="Generate an IDAPython script to annotate hash values in IDA Pro")

    args = parser.parse_args()

    if args.algo:
        if args.apis:
            calc_hashes("apis_list.txt", args.algo)
        elif args.keywords:
            calc_hashes("keywords_list.txt", args.algo)
        elif args.list:
            calc_hashes(args.list, args.algo)
        else:
            parser.print_help()
    elif args.script:
        if args.apis:
            calc_custom_hash("apis_list.txt", args.script)
        elif args.keywords:
            calc_custom_hash("keywords_list.txt", args.script)
        elif args.list:
            calc_custom_hash(args.list, args.script)
        else:
            parser.print_help()
    elif args.search and args.hashes:
        search_hashes(args.search, args.hashes)
    else:
        parser.print_help()

    if args.idaidc:
        generate_idaidc()
    elif args.idapython:
        generate_idapython()

if __name__ == '__main__':
    main()
