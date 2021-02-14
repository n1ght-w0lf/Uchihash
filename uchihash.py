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

def calc_hashes(filename, algo, gida):
    hashes = {}
    with open(os.path.join(data_dir, filename)) as apis:
        for line in apis:
            line = line.strip()
            hashval = hashme(line.encode(), algo)
            hashes[hashval] = line

    with open(os.path.join(out_dir, "hashmap.txt"), "w") as f:
        json.dump(hashes, f, indent=2)
        print("[+] Hashmap written to output folder")
        if gida: generate_idapython(hashes)

def calc_custom_hash(filename, scriptpath, gida):
    sys.path.append(str(pathlib.PurePath(scriptpath).parent))
    script = importlib.import_module(pathlib.PurePath(scriptpath).stem)
    
    hashes = {}
    with open(os.path.join(data_dir, filename)) as apis:
        for line in apis:
            line = line.strip()
            hashval = script.hashme(line.encode())
            hashes[hashval] = line

    with open(os.path.join(out_dir, "hashmap.txt"), "w") as f:
        json.dump(hashes, f, indent=2)
        print("[+] Hashmap written to output folder")
        if gida: generate_idapython(hashes)

def search_hashes(jfile, hlist, gida):
    with open(jfile) as f:
        hashes = json.load(f)

    res = {}
    with open(hlist) as f:
        for line in f:
            line = hex(int(line.strip(), 16))
            val = hashes.get(line)
            res[line] =  val if val != None else "UNKNOWN"

    with open(os.path.join(out_dir, "search_hashmap.txt"), "w") as f:
        json.dump(res, f, indent=2)
        print("[+] Search hashmap written to output folder")
        if gida: generate_idapython(res)

def generate_idapython(hashes):
    patterns = []
    comments = []
    for h, v in hashes.items():
        h = h[2:]
        h = (len(h)%2 * '0') + h  # padding with '0' if odd length
        h = [h[i:i+2] for i in range(0, len(h), 2)]
        patterns.append(" ".join(h[::-1]))  # search uses little endian
        comments.append(v)

    script = """# IDAPython script to comment hash values

patterns = {}
comments = {}

for i in range(len(patterns)):
    addr = idc.get_inf_attr(INF_MIN_EA)
    while True:
        addr = ida_search.find_binary(addr, idc.BADADDR, patterns[i], 16, ida_search.SEARCH_NEXT | ida_search.SEARCH_DOWN)
        if addr == idc.BADADDR: break
        insn_head = addr
        if not idc.is_head(idc.get_full_flags(addr)):
            insn_head = prev_head(addr)
        idc.set_cmt(insn_head, comments[i], 1)
""".format(patterns, comments)
    
    with open(os.path.join(out_dir, "ida_script.py"), "w") as f:
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
    * python uchihash.py --search hashmap.txt --hashes myhashes.txt
    """)
    parser.add_argument("--algo", help="Hashing algorithm")
    parser.add_argument("--apis", action="store_true", help="Calculate hashes of APIs")
    parser.add_argument("--keywords", action="store_true", help="Calculate hashes of keywords")
    parser.add_argument("--list", help="Calculate hashes of your own word list")
    parser.add_argument("--script", help="Script file containing your custom hashing algorithm")
    parser.add_argument("--search", help="Search a JSON File containing hashes mapped to words")
    parser.add_argument("--hashes", help="File containing list of hashes to search for")
    parser.add_argument("--ida", action="store_true", help="Generate an IDAPython script to annotate hash values")

    args = parser.parse_args()

    if args.algo:
        if args.apis:
            calc_hashes("apis_list.txt", args.algo, args.ida)
        elif args.keywords:
            calc_hashes("keywords_list.txt", args.algo, args.ida)
        elif args.list:
            calc_hashes(args.list, args.algo, args.ida, args.ida)
        else:
            parser.print_help()
    elif args.script:
        if args.apis:
            calc_custom_hash("apis_list.txt", args.script, args.ida)
        elif args.keywords:
            calc_custom_hash("keywords_list.txt", args.script, args.ida)
        elif args.list:
            calc_custom_hash(args.list, args.script, args.ida)
        else:
            parser.print_help()
    elif args.search and args.hashes:
        search_hashes(args.search, args.hashes, args.ida)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
