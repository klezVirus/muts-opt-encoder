#!/usr/bin/python
# ==========================================================================================
# muts-opt-encoder v0.1a
# Date: 05-10-2019
# Author: d3adc0de
# ==========================================================================================
# The script implements the same encoding scheme of add_sub and opt_sub msfvenom encoders
# I called it Muts Optimised Encoder because the original encoding scheme was formerly 
# designed by Muts while developing the famous HP OpenView NNM 7.5.1 exploit.
# (http://www.exploit-db.com/exploits/5342/)
# This encoding scheme is a piece of art in my opinion, as well as its optimised version.
# 
# Output:
# $ python2 .\muts-opt-encoder.py -s 33db6681cbff0f436a0853b80d5be777ffd085c075ecb8743030778bfbaf75e7af75e4ffe7 -m add-sub
# 
# [+] Zeroing out with:
#         - 0x21212121 AND 0x42424242
#
# [+] Searching triples such as 0x?+0x?+0x? = 0x00000000 for any shellcode chunk
#
# | Original     | Reversed     | Two's Comp   | 0x? (1)      | 0x? (2)      | 0x? (3)      |
# -------------------------------------------------------------------------------------------
# | 0xaf75e4ff   | 0xffe475af   | 0x001b8a51   | 0x21212155   | 0x617c217e   | 0x7e7e487d   |
# | 0xfbaf75e7   | 0xe775affb   | 0x188a5005   | 0x21215421   | 0x79217e66   | 0x7e487e47   |
# | 0x3030778b   | 0x8b773030   | 0x7488cfd0   | 0x21212121   | 0x21213031   | 0x32467e7e   |
# | 0x75ecb874   | 0x74b8ec75   | 0x8b47138b   | 0x214b2121   | 0x217e7421   | 0x497e7e48   |
# | 0xffd085c0   | 0xc085d0ff   | 0x3f7a2f01   | 0x43213321   | 0x7e217e62   | 0x7e387e37   |
# | 0x0d5be777   | 0x77e75b0d   | 0x8818a4f3   | 0x21212121   | 0x21792154   | 0x467e6245   |
# | 0x6a0853b8   | 0xb853086a   | 0x47acf796   | 0x4b212121   | 0x7e215821   | 0x7e6a7e54   |
# | 0xcbff0f43   | 0x430fffcb   | 0xbcf00035   | 0x21212139   | 0x2151617e   | 0x7a7e7e7d   |
# | 0x33db6681   | 0x8166db33   | 0x7e9924cd   | 0x21212821   | 0x21217e2e   | 0x3c577e56   |
# ===========================================================================================
#
# $ cat encoder.nasm

# AND EAX, 0x21212121
# AND EAX, 0x42424242
# SUB EAX, 0x21212155
# SUB EAX, 0x617c217e
# SUB EAX, 0x7d7e477e
# PUSH EAX
# ...
#
# How to use:
# Copy and paste the output from encoder.nasm to the nasm_shell tool to genereate the respective shellcode.
#
# ==========================================================================================

from sys import argv, stdout, stderr, version_info
import re, argparse
from struct import *
from binascii import hexlify
import os
import itertools

class BinaryUtils():

    def __init__(self):
        self.max_int = 0xffffffff
        self.max_long = 0xffffffff

    def redef_bytes(self, hex_bytes):
        to_return = list()
        for i in range(0, len(hex_bytes), 2):
            to_return.append(hex_bytes[i:i+2])
        return ''.join(to_return)


    def reverse_bytes(self, hex_bytes):
        to_return = list()
        for i in range(0, len(hex_bytes), 1):
            to_return.insert(0, hex_bytes[i:i+1])
        return ''.join(to_return)

    def twos_comp(self, bytes):
        to_return = self.max_int - int(bytes, 16) + 1
        to_return = self.max_long & to_return
        return pack(">I", to_return)

    def m32_abs_sub(self, x_int32, y_int32):
        x = unpack(">I", x_int32)[0]
        y = unpack(">I", y_int32)[0]
        res = self.max_long & (x - y)
        return "%0.8x" % res

    def m32_add(self, x_int32, y_int32):
        #x = unpack("<I", x_int32)[0]
        x = int(x_int32, 16)
        y = unpack("<I",y_int32)[0]
        return "%0.8x" % (y + x)

    def matrix_3(self, elems):
        return itertools.product(elems,elems,elems)

class AddSubEncoder():

    def __init__(self, charset=None, output=None, mode=None):
        self.charset = sorted(list(charset))
        self.mode = mode
        self.output = output
        self.binutils = BinaryUtils()
        self.headers = ["Original", "Reversed", "Two's Comp", "0x? (1)", "0x? (2)", "0x? (3)"]
        self.header_format = "| {:12} "*(len(self.headers))+"|"
        self.row_format = "| 0x{:10} "*(len(self.headers))+"|"

    def print_headers(self):
        print("[+] Searching triples such as 0x?+0x?+0x? = 0x00000000 for any shellcode chunk\n")
        print(self.header_format.format(*self.headers))
        print("-"+"-"*(15*len(self.headers)))

    def print_footer(self):
        print("="+"="*(15*len(self.headers)) + "\n")

    def encode(self, shellcode):
             
        with open(self.output, self.mode) as fout:

            # Formatting the shellcode 
            formatted = [shellcode[i:i+4] for i in range(0, len(shellcode) -1 , 4)]
            if not formatted[-1:] == "\x00":
                lastlen = 4 - len(formatted[-1:])
                formatted[-1:] += "\x00" * lastlen


            last = "\x00\x00\x00\x00"
            # Reversing lines
            zero_printed = False
            headers_printed = False
            for line in reversed(formatted):
                _bytes = [""] * 3
                found = False
                overflow = False
                # Double check for formatting errors
                if line is None or line == "\x00":
                    continue
                shellcode = line

                for i, j in itertools.product(self.charset,self.charset):
                    b1, b2 = (int(hex(ord(i))[-2:],16), int(hex(ord(j))[-2:],16))

                    if b1 & b2 == 0:
                        _b1, _b2 = (hex(b1)[-2:]*4, hex(b2)[-2:]*4)
                        if not zero_printed:
                            print("\n[+] Zeroing out with:\n\t- 0x{} AND 0x{}\n".format(_b1,_b2))
                            zero_printed = True                        
                        fout.write("AND EAX, 0x{}\nAND EAX, 0x{}\n".format(_b1,_b2))
                        found = True
                        break        
                   
                if not found:
                    print("[-] Could not find a valid combination such as 0x? & 0x? = 0 in the current character set.")
                    exit(1)

                if not headers_printed:
                    self.print_headers()
                    headers_printed = True

                orig="{}".format(hexlify(shellcode))

                # Reversing bytes
                try:
                    shellcode = self.binutils.reverse_bytes(shellcode)
                    rev = "{}".format(hexlify(shellcode))
                except Exception as e:
                    print(e)
                    print("[-] Something went wrong. (#reverse_bytes)")
                    exit()

                # Calculating two's complement
                try:
                    shellcode = self.binutils.twos_comp(hexlify(shellcode))
                    tc = "{}".format(hexlify(shellcode))
                except Exception as e:
                    print(e)
                    print("[-] Something went wrong (#two_comp)") 
                    exit()

                for i in shellcode[::-1]:
                    # Get a byte out of the actual shellcode to encode
                    shellcode_byte = hexlify(i)
                    
                    for j, k, m in self.binutils.matrix_3(self.charset):
                        _j, _k, _m, _sum = (ord(j), ord(k), ord(m), ord(j) + ord(k) + ord(m)) 
                        # Found a valid permutation?
                        if (_sum == int(shellcode_byte, 16)) or (len(hex(_sum)) == 5 and int(hex(_sum)[3:5], 16) == int(shellcode_byte, 16) ):
                            
                            _bytes = [ hex(_iter)[-2:] + _b for _iter, _b in zip([_j,_k,_m], _bytes) ]
                            # Detect overflow
                            _bytes[2] = _bytes[2][:-2] + hex(int(_bytes[2][:2],16)-1)[-2:] if overflow else _bytes[2]
                            # Update overflow
                            overflow = not (_sum == int(shellcode_byte, 16))
                            break

                # Check if the end result is 8 bytes in length
                if all( len(_b) == 8 for _b in _bytes ):
                    print(self.row_format.format(orig,rev,tc,*_bytes))
                    for msg in [ "0x{}".format(_b) for _b in _bytes ]:
                       fout.write("SUB EAX, {}\n".format(msg)) 
                    fout.write("PUSH EAX\n")
                else:
                    print("[-] Could not find a valid triple in the current character set.")
        self.print_footer()

class OptSubEncoder():

    def __init__(self, charset=None, output=None, mode=None):
        self.charset = sorted(list(charset))
        self.mode = mode
        self.output = output
        self.binutils = BinaryUtils()
        self.headers = ["Original", "Reversed", "Opt-Sub", "Two's Comp", "0x? (1)", "0x? (2)", "0x? (3)"]
        self.header_format = "| {:12} "*(len(self.headers))+"|"
        self.row_format = "| 0x{:10} "*(len(self.headers))+"|"

    def print_headers(self):
        print("[+] Searching triples such as 0x?+0x?+0x? = 0x? for any shellcode chunk\n")
        print(self.header_format.format(*self.headers))
        print("-"+"-"*(15*len(self.headers)))

    def print_footer(self):
        print("="+"="*(15*len(self.headers)) + "\n")

    def encode(self, shellcode):
             
        # 4-bytes aligning shellcode
        formatted = [shellcode[i:i+4] for i in range(0, len(shellcode) -1 , 4)]
        if not formatted[-1:] == "\x00":
            lastlen = 4 - len(formatted[-1:])
            formatted[-1:] += "\x00" * lastlen

        with open(self.output, self.mode) as fout:

            for i, j in itertools.product(self.charset,self.charset):
                b1, b2 = (int(hex(ord(i))[-2:],16), int(hex(ord(j))[-2:],16))

                if b1 & b2 == 0:
                    _b1, _b2 = (hex(b1)[-2:]*4, hex(b2)[-2:]*4)
                    print("\n[+] Zeroing out with:\n\t - 0x{} AND 0x{}\n".format(_b1,_b2))                        
                    fout.write("AND EAX, 0x{}\nAND EAX, 0x{}\n".format(_b1,_b2))
                    found = True
                    break

            self.print_headers()

            if not found:
                print("[-] Could not find a valid combination in the current character set.")
                exit(1)

            last = "\x00\x00\x00\x00"
            headers_printed = False
            for line in reversed(formatted):
                _bytes = [""] * 3
                found = False
                overflow = False

                if line is None or line == "\x00":
                    continue
                shellcode = line
                     
                if last and last != "\x00\x00\x00\x00":
                    _last ="{}".format(hexlify(last))
                else:
                    _last="{}".format("00000000")
                orig="{}".format(hexlify(shellcode))

                # Reversing bytes
                try:
                    shellcode = self.binutils.reverse_bytes(shellcode)
                    rev = "{}".format(hexlify(shellcode))
                except Exception as e:
                    print("[-] Something went wrong. (#reverse-bytes)")
                    print 
                    exit()
                tmp = shellcode

                try:
                    shellcode = self.binutils.m32_abs_sub(shellcode,last)
                    optsub = "{}".format(shellcode)
                except Exception as e:
                    print("[-] Something went wrong. (#int32-sub)")
                    exit()
                
                # Calculating two's complement
                try:
                    shellcode = self.binutils.twos_comp(shellcode)
                    tc = "{}".format(hexlify(shellcode))
                except Exception as e:
                    print("[-] Something went wrong (#twos-complement)")
                    exit()
                
                last = tmp
                # Checking if sum of three hex numbers will equal a specific predetemined hex value
                for i in shellcode[::-1]:
                    # Get a byte out of the actual shellcode to encode
                    shellcode_byte = hexlify(i)
                    
                    for j, k, m in self.binutils.matrix_3(self.charset):
                        _j, _k, _m, _sum = (ord(j), ord(k), ord(m), ord(j) + ord(k) + ord(m)) 
                        # Found a valid permutation?
                        if (_sum == int(shellcode_byte, 16)) or (len(hex(_sum)) == 5 and int(hex(_sum)[3:5], 16) == int(shellcode_byte, 16) ):
                            
                            _bytes = [ hex(_iter)[-2:] + _b for _iter, _b in zip([_j,_k,_m], _bytes) ]
                            # Detect overflow
                            _bytes[2] = _bytes[2][:-2] + hex(int(_bytes[2][:2],16)-1)[-2:] if overflow else _bytes[2]
                            # Update overflow
                            overflow = not (_sum == int(shellcode_byte, 16))
                            break

                # Check if the end result is 8 bytes in length
                if all( len(_b) == 8 for _b in _bytes ):
                    print(self.row_format.format(orig,rev,optsub,tc,*_bytes))
                    for msg in [ "0x{}".format(_b) for _b in _bytes ]:
                       fout.write("SUB EAX, {}\n".format(msg)) 
                    fout.write("PUSH EAX\n")
                else:
                    print("[-] Could not find a valid combination in the current character set.")
            self.print_footer()

def validate(instring):
    hexaPattern = re.compile(r'^[0-9a-fA-F]+$')
    m = re.search(hexaPattern, instring)
    if len(instring) % 2 == 0 and m:
        return True
    else:
        print("[-] Wrong input length")
        return False

def checkversion():
    if version_info.major > 2:
        print("\n[!] Python3 is not supported yet. Aborting.\n")
        exit(1)
    return True

def main():

    checkversion()
    # This is an example character-set (can replace it with your own)
    char_set = (
        "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x30\x31"
        "\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x47\x3b"
        "\x3c\x3d\x3e\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d"
        "\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d"
        "\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d"
        "\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d"
        "\x7e"
    )
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        '-f', '--file', type=str, help='Get input from a file')
    group.add_argument(
        '-s', '--stdin', type=str, help='Get input from stdin')
    parser.add_argument(
        '-a', '--append', help='Append NASM instructions in the log file', action="store_true")
    parser.add_argument(
        '-m', '--mode', help='Operational mode', default="opt-sub", choices=["add-sub", "opt-sub"])
    group.add_argument(
        '-o', '--output', type=str, default="encoder.nasm", help='Get input from stdin')

    args = parser.parse_args()

    mode = "a" if args.append else "w"

    encoder = OptSubEncoder(charset=char_set,output=args.output,mode=mode) if args.mode == "opt-sub" else AddSubEncoder(charset=char_set,output=args.output,mode=mode)

    if args.stdin:
        if validate(args.stdin):
            _hex = args.stdin.decode("hex")
            encoder.encode(_hex)

    elif args.file:
        if not os.path.isfile(args.file):
            print("[-] Invalid path")
        try:
            with open(args.file, "rb") as input:
                encoder.encode(input.read())
        except:
            print("[*] Not a binary file, trying ascii hex")
            try:
                with open(args.file, "r") as input:
                    encoder.encode(input.read())
            except:
                print("[-] Unknown file or bad format")

if __name__ == '__main__':
    main()
