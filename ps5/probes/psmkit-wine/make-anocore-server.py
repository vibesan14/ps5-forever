# Generates the AnoCore server constants that get sewn into the title and the
# Wine payload. Everything derives from the shipped launcher kit's
# server-root.cer and server-name/server-host text files, exactly how
# Trust-Server-Certificate.cmd treats a PC:
#  - the registry blob user.reg gets is the serialized certificate context
#    crypt32 writes (serialize.c CRYPT_SerializeStoreElement): a
#    WINE_CERT_PROP_HEADER {CERT_CERT_PROP_ID(32), 1, cb} followed by the DER
#    bytes, stored under HKCU\Software\Microsoft\SystemCertificates\Root\
#    Certificates\<upper SHA-1 of the DER>.
#  - the resolver name is server-host.txt, the address is the first token of
#    server-name.txt (the hosts-file order in that file).
# ASCII only: the generated header keeps to plain text on purpose.
import binascii, hashlib, pathlib, re
HERE = pathlib.Path(r'C:\Users\Admin\Documents\Проект по умолчанию\ps5-forever\ps5\probes\psmkit-wine')

kit = pathlib.Path(r'C:\AnoCore-Server\player-launcher\AnoWoW-Launcher')
out = pathlib.Path(HERE) / 'anocore-server.h'

der = (kit / 'server-root.cer').read_bytes()
sha1 = hashlib.sha1(der).hexdigest().upper()
host = (kit / 'server-host.txt').read_text(encoding='ascii').strip()
name_first_token = (kit / 'server-name.txt').read_text(encoding='ascii').split()[0]
# server-name.txt holds "<address> <name>": the hosts-file style one line.
if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', name_first_token):
    address, name = name_first_token, host
else:
    name, address = host, name_first_token

# WINE_CERT_PROP_HEADER: propID=CERT_CERT_PROP_ID (32), unknown=1, cb=len(der)
blob = (32).to_bytes(4, 'little') + (1).to_bytes(4, 'little') + len(der).to_bytes(4, 'little') + der
hexarray = ','.join('%02X' % b for b in blob)

# Self-check: simulate crypt32/serialize.c CRYPT_findPropID over our own blob.
def find_prop_id(data, prop_id):
    i = 0
    while i < len(data):
        if len(data) - i < 12:
            raise AssertionError('short header')
        prop, unknown, cb = int.from_bytes(data[i:i+4], 'little'), int.from_bytes(data[i+4:i+8], 'little'), int.from_bytes(data[i+8:i+12], 'little')
        if i + 12 + cb > len(data):
            raise AssertionError('cb overruns')
        if not prop:
            raise AssertionError('zero prop terminates')
        if unknown != 1:
            raise AssertionError('unknown != 1')
        if prop == prop_id:
            return i, cb
        i += 12 + cb
    raise AssertionError('prop not found')

off, cb = find_prop_id(blob, 32)
assert off == 0 and cb == len(der), 'header is not the certificate'
assert hashlib.sha1(blob[12:]).hexdigest().upper() == sha1, 'hash mismatch'

header = f'''/* AnoCore server constants, generated from the launcher kit
 * (server-root.cer, server-host.txt, server-name.txt) - regenerate with
 * ps5/probes/psmkit-wine/make-anocore-server.py, never hand-edit.
 *
 * The certificate blob is the serialized certificate context crypt32 stores
 * in its registry-backed root store (serialize.c CRYPT_SerializeStoreElement):
 * WINE_CERT_PROP_HEADER {{CERT_CERT_PROP_ID (32), 1, cb}} + DER bytes. Wine's
 * CRYPT_ReadSerializedElement takes exactly the DER that follows, and the
 * registry key name is the SHA-1 of the DER for RegReadSerializedFromReg to
 * approve the entry. {len(blob)} bytes total, {len(der)} of them DER. */
#ifndef ANOCORE_SERVER_H
#define ANOCORE_SERVER_H

#define ANOCORE_SERVER_NAME  "{name}"
#define ANOCORE_SERVER_ADDRESS "{address}"

/* SHA-1 thumbprint of the server root certificate, the registry key name.
 * Windows shows it in certmgr; keep verifying an install against it. */
#define ANOCORE_SERVER_CERT_KEY "{sha1}"

/* The raw Blob value of the SystemCertificates\\Root entry. */
#define ANOCORE_SERVER_CERT_BLOB_BYTES {len(blob)}
#define ANOCORE_SERVER_CERT_DER_BYTES {len(der)}
#define ANOCORE_SERVER_CERT_BLOB "{hexarray}"

#endif /* ANOCORE_SERVER_H */
'''
out.write_text(header, encoding='ascii', newline='\n')
# The title's start screen shows the server name as a plain display string
# (ps5/title has no include path for the generated header); the generator
# keeps that literal in sync with the constants.
menu = (HERE.parent.parent / 'title' / 'forever-menu.c').read_text(encoding='utf-8')
assert name in menu, 'forever-menu.c lost the AnoCore server name'
print('der:', len(der), 'blob:', len(blob), 'sha1:', sha1)
print('name:', name, 'address:', address)
print('wrote:', out)
