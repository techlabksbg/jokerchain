# Joker-Chain
# 
# Eine experimentelle Buchhaltung zur Verwaltung der Miniaufgaben-Joker
# Enthält zwar Elemente, die auch in einer Blockchain zur Anwendung kommen,
# ist aber definitiv keine Blockchain.
#
# Dokumentation siehe https://fginfo.ksbg.ch/dokuwiki/doku.php?id=lehrkraefte:blc:informatik:glf22:crypto:joker-chain
# 

import subprocess
import os
import hashlib
import time


# Globale Variablen
PRIVATE_KEY_FILE = "secret-private-key-joker.pem"
PUBLIC_KEY_FILE = "public-key-joker.pem"
JOKER_CHAIN_FILE = "joker-chain.md"
JOKER_CHAIN_URL = "https://fginfo.ksbg.ch/~ivo/"+JOKER_CHAIN_FILE
TEMP_FILE = "tempfile.bin"
TEMP_KEY_FILE = "tempkey.pem"
SIGNATURE_FILE = "signature.bin"
SIGNATURE_FILE64 = "signature.b64"


#################################
# Diese Box wurde mit           #
#                               #
# boxprint("Diese Box...\n...") #
#                               #
# ausgegeben                    #
#################################
def boxprint(what):
    zeilen = what.split("\n")
    l = max([len(zeile) for zeile in zeilen])
    print("\n")
    print("#"*(l+4))
    for zeile in zeilen:
        print("# "+zeile+" "*(l-len(zeile))+" #")
    print("#"*(l+4))



# Führt eine Kommandozeile aus, die als Liste der einzelnen Element gegeben ist.
# Optional kann ein Kommentar davor ausgeben werden.
# Die Funktion liefert den Output des Kommandos als Byte-Sequenz
def run_command(cmd, comment=""):
    if comment:
        boxprint(comment)
    cmdline = " ".join(["'"+c.replace("'", "\\'")+"'" if "'" in c else c for c in cmd])
    print(cmdline)
    result = subprocess.run(cmd, capture_output=True);
    if result.returncode!=0:
        print(result)
        raise ChildProcessError("Kommando fehlgeschlagen")
    return result.stdout



# Generiert einen neues Schlüsselpaar.
def new_key_pair():
    if os.path.exists(PRIVATE_KEY_FILE) or os.path.exists(PUBLIC_KEY_FILE):
        raise FileExistsError("Oops! Mindestens eine der Schlüsseldateien "+PRIVATE_KEY_FILE+" oder "+PUBLIC_KEY_FILE+" existiert bereits")

    run_command(['openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', PRIVATE_KEY_FILE], comment="Generierung des privaten Schlüssels.\nGut aufbewahren, backupen, und geheim halten.\n -> Datei "+PRIVATE_KEY_FILE)
    run_command(['openssl', 'ec', '-in', PRIVATE_KEY_FILE, '-pubout', '-out', PUBLIC_KEY_FILE], comment="Ausgabe des öffentlichen Schlüssels\n -> "+PUBLIC_KEY_FILE+"\nDiesen Schlüssel dem Admin schicken")

def get_public_key():
    if not os.path.exists(PUBLIC_KEY_FILE):
        raise FileNotFoundError("Oops. Die Datei "+PUBLIC_KEY_FILE+" mit dem öffentlichen Schlüssel nicht gefunden.")
    public = ""
    with open(PUBLIC_KEY_FILE, encoding="utf8") as f:
        for line in f:
            public+=line
    return public

def show_public_key():
    public = get_public_key();
    boxprint("Ihr öffentlicher Schlüssel.\nDiesen per Email dem Admin schicken.")
    print(public)


# Gets SHA256 of data (byte array)
def get_hash_from_data(data):
    return hashlib.sha224(data).hexdigest()[0:8]


# Reads a file into a byte array
def file_to_byte_array(dateiname):
    with open(dateiname, "rb") as f:
        data=f.read()
    return data

def get_hash_from_file(dateiname):
    return get_hash_from_data(file_to_byte_array(dateiname))

def get_hash_from_key_file(pemfile):
    binary_key = run_command(['openssl', 'pkey', '-pubin', '-in', pemfile, '-outform', 'der'])
    return get_hash_from_data(binary_key);


def timestamp():
    return "## timestamp\n"+str(time.time())+"\n"

def unterschreiben(data):
    if type(data) is str:
        data = bytes(data, encoding="ascii")
    with open(TEMP_FILE, "wb") as f:
        f.write(data)
    run_command(['openssl', 'dgst', '-sha256', '-sign', PRIVATE_KEY_FILE, '-out', SIGNATURE_FILE, TEMP_FILE])
    signature = run_command(['openssl', 'enc', '-base64', '-in', SIGNATURE_FILE]);
    return signature.decode("ascii")

def unterschrift_pruefen(data, signature, pubkey):
    if type(data) is str:
        data = bytes(data, encoding="ascii")
    with open(TEMP_FILE, "wb") as f:
        f.write(data)
    with open(SIGNATURE_FILE64, "w") as f:
        f.write(signature)
    with open(TEMP_KEY_FILE, "w") as f:
        f.write(pubkey)

    run_command(['openssl', 'enc', '-base64', '-d', '-in', SIGNATURE_FILE64, '-out', SIGNATURE_FILE])
    result = run_command(['openssl', 'dgst', '-sha256', '-verify', TEMP_KEY_FILE, '-signature', SIGNATURE_FILE, TEMP_FILE]).decode("ascii")
    # boxprint(result.strip())
    return result=="Verified OK\n"


def new_joker_chain():
    entry = "#root\n## publickey\n"
    if not os.path.exists(PUBLIC_KEY_FILE):
        new_key_pair()
    entry += get_public_key()
    entry += "## keyhash\n"
    entry += get_hash_from_key_file(PUBLIC_KEY_FILE)+"\n";
    entry += timestamp()
    entry += "## signature\n"
    signed = entry
    signature = unterschreiben(entry)
    entry += signature+"\n"
    # print(entry)
    # unterschrift_pruefen(signed, signature, get_public_key())
    return entry


def delete_temp_files():
    for file in [TEMP_FILE, TEMP_KEY_FILE, SIGNATURE_FILE, SIGNATURE_FILE64]:
        if os.path.exists(file):
            os. remove(file)


# new_key_pair()
delete_temp_files()
new_joker_chain()


