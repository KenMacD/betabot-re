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

class Config(object):
    """Base class for configurations, subclasses my have the properties:
       To find binary config:
         header         = header of a valid config
         config_size    = size of the full config block with all sections
         needle         = easy to find value close to the config
         needle_offset  = offset from needle to start searching
         config_version = version string for config
       To unpack config:
         owner_offset, s1_offset, s2_offset
         config_section_start, config_section_size
         host_offset, path_offset, port_offset, ssl_offset
         attempts_offset, key1_offset, key2_offset
    """
    num_servers = 16

    @classmethod
    def encrypt(cls, data, key):
        """Encrypt and decrypt are the same for RC4."""
        rc4 = ARC4.new(key)
        return rc4.encrypt(data)

    @classmethod
    def make_key(cls, data, offset):
        """Return every second value for 16 bytes after"""
        return data[offset:offset+0x20:2]

    @classmethod
    def needle_locs(cls, data):
        offset = data.find(cls.needle)
        while offset != -1:
            yield offset
            offset = data.find(cls.needle, offset + 1)

    @classmethod
    def keys(cls, data, location):
        for key_loc in range(location, location + KEY_SEARCH_RANGE):
            yield cls.make_key(data, key_loc)

    @classmethod
    def offset_search(cls, data):
        if cls.header in data:
            offset = data.find(cls.header)
            return data[offset:offset+cls.config_size]

        for needle_loc in cls.needle_locs(data):
            loc = needle_loc + cls.needle_offset

            # Not enough room for a config to exist.
            # Misses a little bit where loc < 0 but loc + search range > 0, but
            # this shouldn't be a problem
            if (loc < 0) or (loc + cls.config_size > len(data)):
                continue

            for key in cls.keys(data, loc):
                needed = cls.encrypt(cls.header, key)
                config_loc = data.find(needed)
                if config_loc != -1:
                    econfig = data[config_loc:config_loc+cls.config_size]
                    config = cls.encrypt(econfig, key)
                    return cls(config)

    def __init__(self, config):
        (self.owner,) = unpack_string(config, self.owner_offset)
        (self.s1,)    = unpack_unicode(config, self.s1_offset)
        (self.s2,)    = unpack_unicode(config, self.s2_offset)

        self.servers = []
        for i in range(self.num_servers):
            offset = self.config_section_start + (i * self.config_section_size)
            (clen,) = struct.unpack_from("<H", config, offset)

            if clen != self.config_section_size:
                continue

            section = {}
            (section["host"],)     = unpack_string(config, offset + self.host_offset)
            (section["path"],)     = unpack_string(config, offset + self.path_offset)
            (section["port"],)     = struct.unpack_from("<H", config, offset + self.port_offset)
            (section["ssl"],)      = struct.unpack_from("?", config, offset + self.ssl_offset)
            (section["attempts"],) = struct.unpack_from("<H", config, offset + self.attempts_offset)
            (section["key1"],)     = struct.unpack_from("8s", config, offset + self.key1_offset)
            (section["key2"],)     = struct.unpack_from("8s", config, offset + self.key2_offset)

            self.servers.append(section)

    def __str__(self):
        lines = []
        lines.append("BetaBot Config (version %s):"%(self.config_version,))
        lines.append("  Owner: %s"%(self.owner,))
        lines.append("  String1: %s"%(self.s1,))
        lines.append("  String2: %s"%(self.s2,))
        for (i, c) in enumerate(self.servers):
            lines.append("  Config %d:"%(i,))
            SSL = c["ssl"]
            port = c["port"]

            if SSL:
                url = "https://"
            else:
                url = "http://"

            url = url + c["host"]

            if not ((port == 80 and not SSL) or (port == 443 and SSL)):
                url = url + ":" + str(port)

            url = url + str(c["path"])

    #        lines.append("Match: %s,%s,%d,%s,%s,%s,%s"%(config["Owner"], config["_ver"],
    #                                i+1, url, str(c["Attempts"]), str(c["Key1"]),
    #                                str(c["Key2"]))
            lines.append("    URL: " + url)
            lines.append("    Attempts: " + str(c["attempts"]))
            lines.append("    Key1: " + str(c["key1"]).encode("hex").upper())
            lines.append("    Key2: " + str(c["key2"]).encode("hex").upper())

        return "\n".join(lines)


class Config_v1(Config):
    config_version = "1.0.2.5"
    header         = "".join([chr(c) for c in [0xce, 0x2a, 0xaa, 0x0f, 0x92, 0xc1]])
    config_size    = 0x2ace
    needle         = "crypt32.dll"
    needle_offset  = -0xd00 # -0xc52

    owner_offset = 6
    s1_offset    = 0x14e
    s2_offset    = 0x24e
    # A backup url exists, but it's always the same, so uninteresting
    #(backup_url,) = unpack_string(data, 0x44)
    #config_struct["Backup_URL"] = backup_url

    config_section_start = 0x2ce
    config_section_size  = 640

    host_offset     = 0x66
    path_offset     = 0x166
    port_offset     = 0x14
    ssl_offset      = 0x1e
    attempts_offset = 0x12
    key1_offset     = 0x26e
    key2_offset     = 0x277

class Config_v1p5(Config):
    config_version = "1.5"
    header         = "".join([chr(c) for c in [0x46, 0x0d, 0xaa, 0x0f, 0x92, 0xc1]])
    config_size    = 0x0d46
    needle         = "crypt32.dll"
    needle_offset  = -0xd80 # -0xd0e

    owner_offset = 6
    s1_offset    = 0x46
    s2_offset    = 0xc6

    config_section_start = 0x146
    config_section_size  = 192

    host_offset     = 0x26
    path_offset     = 0x66
    port_offset     = 0x14
    ssl_offset      = 0x1e
    attempts_offset = 0x12
    key1_offset     = 0xae
    key2_offset     = 0xb7

class Config_v1p6(Config_v1p5):
    config_version = "1.6"
    header         = "".join([chr(c) for c in [0x46, 0x0d, 0xaa, 0x0f, 0x92, 0xc1]])
    config_size    = 0x0d46
    needle         = "crypt32.dll"
    needle_offset  = -0xd80 # -0xd0e

    @classmethod
    def make_key(cls, data, offset):
        key = super(Config_v1p6, cls).make_key(data, offset)
        return "".join([chr(ord(x) ^ 0x2e) for x in key])

    @classmethod
    def encrypt(cls, data, key):
        decrypt = super(Config_v1p6, cls).encrypt(data, key)
        xdecrypt = ""
        for i in range(len(decrypt)):
            xdecrypt += chr(ord(decrypt[i]) ^ ord(key[i%4]))
        return xdecrypt

    def __init__(self, config):
        super(Config_v1p6, self).__init__(config)
        for server in self.servers:
            server['host'] = self._deobfuscate_host(server['host'])

    def _deobfuscate_host(self, host):
        slen = len(host)

        array = [ord(x) for x in host]

        if slen < 8 or slen > 0x40:
            return host

        val_0 = array[0]

        loc1 = (val_0 + 2 * slen) % (slen - 2) + 1
        loc2 = (val_0 + 8 * (slen + 1)) % (slen - 3) + 2

        xor1 = 655  * val_0 % 3 + 24
        xor2 = 1424 * val_0 % 6 + 23

        if xor1 != array[loc1]:
            array[loc1] ^= xor1

        if xor2 != array[loc2]:
            array[loc2] ^= xor2

        return "".join([chr(x) for x in array])

def unpack_string(buf, offset):
    null_len = buf[offset:].find('\0')
    return struct.unpack_from("%ds"%(null_len), buf, offset)

def unpack_unicode(buf, offset):
    # Hack: just cut out every second byte:
    bufcopy = buf[offset::2]
    return unpack_string(bufcopy, 0)

def main():
    if len(sys.argv) != 2:
        print "Usage: {0} <dumpfile>".format(sys.argv[0])
        sys.exit(1)

    with open(sys.argv[1], mode="rb") as sample:
        data = sample.read()

    print " [*] Offset searching for version 1 config"
    config = Config_v1.offset_search(data)
    if config:
        print "   [*] Found version 1 config"
        print str(config)
        return

    print " [*] Offset searching for version 1.5 config"
    config = Config_v1p5.offset_search(data)
    if config:
        print "   [*] Found version 1.5 config"
        print str(config)
        return

    print " [*] Offset searching for version 1.6 config"
    config = Config_v1p6.offset_search(data)
    if config:
        print "   [*] Found version 1.6 config"
        print str(config)
        return

    print " [*] No configs found"

if __name__ == "__main__":
    main()
