#!/usr/bin/env python

# Search and dump the config of Beta Bot samples or memory dumps.
#
# The offset search finds most (all?) currently decryptable configs.
#
# The bruteforce search is slower and requires about 220 times the size
# of the sample in memory to create a search index. This code may need
# to be disabled when dealing with large memory dumps.
#
# Requires PyCrypto

import struct 
import sys
import os
import pprint

from Crypto.Cipher import ARC4

KEY_SEARCH_RANGE = 0x200

HEADER_v1   = "".join([chr(c) for c in [0xce, 0x2a, 0xaa, 0x0f, 0x92, 0xc1]])
HEADER_v1p5 = "".join([chr(c) for c in [0x46, 0x0d, 0xaa, 0x0f, 0x92, 0xc1]])

SIZE_v1   = 0x2ace
SIZE_v1p5 = 0x0d46

def unpack_string(buf, offset):
    null_len = buf[offset:].find('\0')
    return struct.unpack_from("%ds"%(null_len), buf, offset)

def unpack_unicode(buf, offset):
    # Hack: just cut out every second byte:
    bufcopy = buf[offset::2]
    return unpack_string(bufcopy, 0)

def get_decyrpted_config(data, header, search_data, offset, config_size):
    if header in data:
        print " [*] Decrypted version may already exist"

    crypt_offset = data.find(search_data)
    while crypt_offset != -1:
        key_start = crypt_offset + offset
        
        crypt_offset = data.find(search_data, crypt_offset + 1)
        if (key_start < 0) or (key_start + config_size > len(data)):
                continue

        for koffset in range(key_start, key_start + KEY_SEARCH_RANGE):
            key = data[koffset:koffset+0x20:2]
            rc4 = ARC4.new(key)

            needed = rc4.encrypt(header)
            conf_location = data.find(needed)
            if conf_location != -1:
                if data.find(needed, conf_location + 1) != -1:
                    print " [*] Warning, multiple locations found"
                crypted_config = data[conf_location:conf_location+config_size]

                rc4 = ARC4.new(key)
                config = rc4.decrypt(crypted_config)
                return config
    return None

def offset_search_v1(data):
    header = HEADER_v1
    offset = -0xd00 # -0xc52 in my sample

    return get_decyrpted_config(data, header, "crypt32.dll", offset, SIZE_v1)

def offset_search_v1p5(data):
    header = HEADER_v1p5
    offset = -0xf00 # -0xd0e in my sample

    return get_decyrpted_config(data, header, "crypt32.dll", offset, SIZE_v1p5)

def decode_config_v1(data):
    config_struct = {"Config": []}
    if len(data) != SIZE_v1:
        return ""

    # A backup url exists, but it's always the same, so uninteresting
    #(backup_url,) = unpack_string(data, 0x44)
    #config_struct["Backup_URL"] = backup_url

    config_struct["_ver"] = "1.0.2.5"

    (owner,) = unpack_string(data, + 6)
    (s1,) = unpack_unicode(data, 0x14e)
    (s2,) = unpack_unicode(data, 0x24e)
    config_struct["Owner"] = owner
    config_struct["String1"] = s1
    config_struct["String2"] = s2

    for i in range(16): # There are up to 16 configs
        offset = 0x2ce + (i * 640)
        (clen,) = struct.unpack_from("<H", data, offset)

        if clen == 640:
            config = {}
            (host,) = unpack_string(data, offset + 0x066)
            (path,) = unpack_string(data, offset + 0x166)
            (port,) = struct.unpack_from("<H", data, offset + 0x14)
            (ssl, ) = struct.unpack_from("?", data, offset + 0x1e)
            (attempts,) = struct.unpack_from("<H", data, offset + 0x12)
            (key1,) = struct.unpack_from("8s", data, offset + 0x26e)
            (key2,) = struct. unpack_from("8s", data, offset + 0x277)

            config["Host"] = host
            config["Path"] = path
            config["Port"] = port
            config["SSL"] = ssl
            config["Attempts"] = attempts
            config["Key1"] = key1.encode("hex").upper()
            config["Key2"] = key2.encode("hex").upper()
            
            config_struct["Config"].append(config)

    return config_struct

def decode_config_v1p5(data):
    config_struct = {"Config": []}
    if len(data) != SIZE_v1p5:
        return ""

    config_struct["_ver"] = "1.5"
    
    (owner,) = unpack_string(data, + 6)
    (s1,) = unpack_unicode(data, 0x46)
    (s2,) = unpack_unicode(data, 0xc6)
    config_struct["Owner"] = owner
    config_struct["String1"] = s1
    config_struct["String2"] = s2

    for i in range(16): # There are up to 16 configs
        offset = 0x146 + (i * 192)
        (clen,) = struct.unpack_from("<H", data, offset)

        if clen == 192:
            config = {}
            (host,) = unpack_string(data, offset + 0x26)
            (path,) = unpack_string(data, offset + 0x66)
            (port,) = struct.unpack_from("<H", data, offset + 0x14)
            (ssl, ) = struct.unpack_from("?", data, offset + 0x1e)
            (attempts,) = struct.unpack_from("<H", data, offset + 0x12)
            (key1,) = struct.unpack_from("8s", data, offset + 0xae)
            (key2,) = struct. unpack_from("8s", data, offset + 0xb7)

            config["Host"] = host
            config["Path"] = path
            config["Port"] = port
            config["SSL"] = ssl
            config["Attempts"] = attempts
            config["Key1"] = key1.encode("hex").upper()
            config["Key2"] = key2.encode("hex").upper()
            
            config_struct["Config"].append(config)

    return config_struct

def print_config(config):
    print "BetaBot Config (version %s):"%(config["_ver"],)
    print "  Owner: %s"%(config["Owner"],)
    print "  String1: %s"%(config["String1"],)
    print "  String2: %s"%(config["String2"],)
    for (i, c) in enumerate(config["Config"]):
        print "  Config %d:"%(i,)
        SSL = c["SSL"]
        port = c["Port"]

        if SSL:
            url = "https://"
        else:
            url = "http://"

        url = url + c["Host"]

        if not ((port == 80 and not SSL) or (port == 443 and SSL)):
            url = url + ":" + str(port)

        url = url + str(c["Path"])

#        print "Match: %s,%s,%d,%s,%s,%s,%s"%(config["Owner"], config["_ver"],
#                                i+1, url, str(c["Attempts"]), str(c["Key1"]),
#                                str(c["Key2"]))
        print "    URL: " + url
        print "    Attempts: " + str(c["Attempts"])
        print "    Key1: " + str(c["Key1"])
        print "    Key2: " + str(c["Key2"])

def build_index(data):
    indexed = {}

    for i in range(len(data) - 6):
        key = data[i:i+6]
        if key in indexed:
            indexed[key].append(i)
        else:
            indexed[key] = [i]

    return indexed

def bf_search_config(data, data_index, header, size):

    for i in range(len(data) - 0x20):
        key = data[i:i+0x20:2]

        rc4 = ARC4.new(key)
        needed = rc4.decrypt(header)

        if needed in data_index:
            offsets = data_index[needed]
            if len(offsets) > 1:
                print "    [*] Multiple possible config locations found: " + str(offsets)
            offset = offsets[0]

            rc4 = ARC4.new(key)
            return rc4.decrypt(data[offset:offset+size])
    return None


def main():
    if len(sys.argv) != 2:
        print "Usage: {0} <dumpfile>".format(sys.argv[0])
        sys.exit(1)

    with open(sys.argv[1], mode="rb") as sample:
        data = sample.read()

    print " [*] Offset searching for version 1 config"
    config = offset_search_v1(data)
    if config:
        print "   [*] Found version 1 config"
        print_config(decode_config_v1(config))
        return

    print " [*] Offset searching for version 1.5 config"
    config = offset_search_v1p5(data)
    if config:
        print "   [*] Found version 1.5 config"
        print_config(decode_config_v1p5(config))
        return

    print " [*] Building index... ",
    index = build_index(data)
    print "Done"

    print " [*] Bruteforce searching for version 1 config"
    config = bf_search_config(data, index, HEADER_v1, SIZE_v1)
    if config:
        print "    [*] Found version 1 config"
        print_config(decode_config_v1(config))
        return

    print " [*] Bruteforce searching for version 1.5 config"
    config = bf_search_config(data, index, HEADER_v1p5, SIZE_v1p5)
    if config:
        print "    [*] Found version 1.5 config"
        print_config(decode_config_v1p5(config))
        return

    if config:
        sys.exit(0)
    else:
        print "no config"
        sys.exit(1)

if __name__ == "__main__":
    main()
