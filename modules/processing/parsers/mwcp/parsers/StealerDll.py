import re
import os.path
from Crypto.Cipher import AES
import binascii
from mwcp.malwareconfigparser import malwareconfigparser
import hashlib
import yara

rules = yara.compile(source='rule urls { strings: $a1 = /https?:\/\/[a-zA-Z0-9\/\-_\.&\+\?]+/ ascii wide condition: all of them }')

mz = "MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
js_checks = ["var BV = \"3.0\";\r", "var BV = \"4.0\";\r", "var BV = \"4.4\";\r", "var BV = \"5.0\";\r",
             "var researchers = \"We are not co", "<package >\r\n<com", "var BV = \"5.2\";\r"]


def get_utf_strings(data, length):
    pat = re.compile(ur'(?:[A-Fa-f0-9][\x00]){' + str(length) + ur',}')
    words = [w.decode('utf-16le') for w in pat.findall(data)]
    return words


def decode_str(k, d):
    temp = bytearray(binascii.unhexlify(d))
    temp_k = bytearray(k, 'ascii')
    for i in range(len(temp)):
        temp[i] ^= temp_k[(i + 1) % len(temp_k)]
    return str(temp)


def brute_it(init_k, data, decoded):
    test = ""
    key = init_k
    while test != decoded:
        for val in "0123456789":
            test = decode_str(key + val, data)
            if test[len(key) - 1] == decoded[len(key) - 1]:
                key += val
                break
    return key


def clean_strings(decstrs):
    outlist = []
    for dstr in decstrs:
        try:
            newstr = dstr.decode('ascii')
        except UnicodeDecodeError:
            newstr = dstr.encode('hex')
        outlist.append(newstr)

    return outlist


def decoder(reporter):
    secondary_files = []
    data = reporter.data
    dropped_path = os.path.join(reporter.analysis_path, "files")
    uni_words = get_utf_strings(data, 3)
    poss_keys = filter(lambda x: len(x) < 9, uni_words)
    poss_matches = filter(lambda x: len(x) == 32, uni_words)
    # poss_matches_check = map(lambda x: x[:8], poss_matches)
    poss_xorvals = filter(lambda x: len(x) == 64, uni_words)

    done = False
    k = ''
    xorval = ''
    decoded_strings = []

    for k in poss_keys:
        poss_matches_check = map(lambda x: x[:len(k) - 1], poss_matches)
        for x in poss_xorvals:
            test = decode_str(k, x)[:len(k) - 1]
            if test in poss_matches_check:
                done = True
                key = k
                xorval = x
                break
        if done == True:
            break

    if done:
        mval = [x for x in poss_matches if test == x[:len(k) - 1]]
        mval = mval[0]
        full_key = brute_it(key, xorval, mval)
        reporter.add_metadata("FULL_KEY", full_key)
        for word in uni_words:
            try:
                decoded_strings.append(decode_str(full_key, word))
            except:
                pass
        poss_aes_keys = []
        poss_aes_iv = []
        for dec in decoded_strings:
            if len(dec) == 32:
                poss_aes_keys.append(dec)
            elif len(dec) == 16:
                poss_aes_iv.append(dec)
        reporter.add_metadata("AES_KEY_CANDIDATES", clean_strings(poss_aes_keys))
        reporter.add_metadata("AES_IV_CANDIDATES", clean_strings(poss_aes_iv))
        for key in poss_aes_keys:
            for iv in poss_aes_iv:
                aes = AES.new(key, AES.MODE_CBC, iv)
                mzcheck = aes.encrypt(mz)
                aes = AES.new(key, AES.MODE_CBC, iv)
                jschecks = []
                for js in js_checks:
                    aes = AES.new(key, AES.MODE_CBC, iv)
                    jschecks.append(aes.encrypt(js))
                if mzcheck in data:
                    reporter.add_metadata("MZ_KEY", key)
                    reporter.add_metadata("MZ_IV", iv)
                    aes = AES.new(key, AES.MODE_CBC, iv)
                    off_to_mz = data.find(mzcheck)
                    temp = data[off_to_mz:]
                    if len(temp) % 16 != 0:
                        temp = temp[:-(len(temp) % 16)]
                    test = aes.decrypt(temp)
                    if 'This program' in test:
                        reporter.add_metadata("CONTAINS_PE", "Yes")
                        secondary_files.append(test)
                for jscheck in jschecks:
                    if jscheck in data:
                        aes = AES.new(key, AES.MODE_CBC, iv)
                        off_to_js = data.find(jscheck)
                        temp = data[off_to_js:]
                        if len(temp) % 16 != 0:
                            temp = temp[:-(len(temp) % 16)]
                        test = aes.decrypt(temp)
                        if 'var Gate' in test or 'package' in test:
                            reporter.add_metadata("CONTAINS_JS", "Yes")
                            secondary_files.append(test)

    sec_urls = []
    sec_hashes = []
    for sec in secondary_files:
        sec_hash = hashlib.sha256(sec).hexdigest()
        sec_hashes.append(sec_hash)
        open(os.path.join(dropped_path, sec_hash), 'wb').write(sec)
        open(os.path.join(dropped_path, sec_hash + "_info.txt"), 'w').write(sec_hash)
        matches = rules.match(data=sec)
        if matches:
            matches = matches[0].strings
            for match in matches:
                u = match[2]
                if 'http' in u:
                    sec_urls.append(u)
                else:
                    sec_urls.append(u.decode('utf-16').decode('ascii'))

    reporter.add_metadata("DECODED_STRINGS", clean_strings(decoded_strings))
    reporter.add_metadata("URLS", filter(lambda x: x[:4] == 'http' and len(x) > 5, decoded_strings))
    if sec_urls:
        reporter.add_metadata("SECONDARY_URLS", sec_urls)

    return


class StealerDll(malwareconfigparser):
    def __init__(self, reporter=None):
        malwareconfigparser.__init__(self, description='StealerDll decoder.', author='enzok', reporter=reporter)

    def run(self):
        decoder(self.reporter)


