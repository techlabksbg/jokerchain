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
import argparse # Kommandozeilenargumente lesen, siehe https://docs.python.org/3/library/argparse.html
import requests


# Globale Variablen
PRIVATE_KEY_FILE = "secret-private-key-joker.pem"
PUBLIC_KEY_FILE = "public-key-joker.pem"
JOKER_CHAIN_FILE = "joker-chain.md"
JOKER_CHAIN_URL = "https://fginfo.ksbg.ch/~ivo/"+JOKER_CHAIN_FILE
TEMP_FILE = "tempfile.bin"
TEMP_KEY_FILE = "tempkey.pem"
SIGNATURE_FILE = "signature.bin"
SIGNATURE_FILE64 = "signature.b64"

# Dictionary mit allen wichtigen Einträgen zur aktuellen JokerChain
JOKER_CHAIN = {'lines':[], 'adminhash':'', 'adminkey':'', 'myhash':'', 'mypubkey':'', 'tokens':[], 'admin':False, 'keys':{}}


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
    run_command(['openssl', 'ec', '-in', PRIVATE_KEY_FILE, '-pubout', '-out', PUBLIC_KEY_FILE], comment="Konvertierung des öffentlichen Schlüssels\n -> "+PUBLIC_KEY_FILE+"\nDiesen Schlüssel dem Admin schicken")

# Gets the public key from the pem file (in ASCII-armored multiline form)
def get_public_key():
    if not os.path.exists(PUBLIC_KEY_FILE):
        raise FileNotFoundError("Oops. Die Datei "+PUBLIC_KEY_FILE+" mit dem öffentlichen Schlüssel nicht gefunden.")
    public = ""
    with open(PUBLIC_KEY_FILE, encoding="ascii") as f:
        for line in f:
            public+=line
    return public

def show_public_key():
    public = get_public_key();
    boxprint("Ihr öffentlicher Schlüssel.\nDiesen per Email dem Admin schicken.")
    print(public)


# Gets SHA256 of data (byte array)
def get_hash_from_data(data):
    if type(data) is str:
        data = bytes(data, encoding="ascii")
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

def get_hash_from_key(keydata):
    with open(TEMP_KEY_FILE, "w") as f:
        f.write(keydata)
    return get_hash_from_key_file(TEMP_KEY_FILE)

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


def save_joker_chain():
    chain = "\n".join(JOKER_CHAIN['lines'])+"\n"
    with open(JOKER_CHAIN_FILE, "w") as f:
        f.write(chain)
    boxprint("JokeChain saved to "+JOKER_CHAIN_FILE)

def load_joker_chain():
    with open(JOKER_CHAIN_FILE, "r") as f:
        JOKER_CHAIN['lines'] = [l.strip() for l in f.readlines() if len(l)>0]
    parse_joker_chain()

def new_joker_chain():
    if os.path.exists(JOKER_CHAIN_FILE):
        raise FileExistsError("Die Datei "+JOKER_CHAIN_FILE+" existiert bereits.")
    entry = "# root\n## publickey\n"
    if not os.path.exists(PUBLIC_KEY_FILE):
        new_key_pair()
    entry += get_public_key()
    entry += "## keyhash\n"
    JOKER_CHAIN['myhash'] = get_hash_from_key_file(PUBLIC_KEY_FILE)
    entry += JOKER_CHAIN['myhash']+"\n";
    entry += timestamp()
    entry += "## signature\n"
    signed = entry
    signature = unterschreiben(entry)
    entry += signature
    JOKER_CHAIN['lines']=entry.strip().split("\n")
    JOKER_CHAIN['admin']=True
    # print(entry)
    # unterschrift_pruefen(signed, signature, get_public_key())
    with open(JOKER_CHAIN_FILE, "w") as f:
        f.write(entry)
    boxprint("New joker chain initialized")
    return entry

# publishes the JokerChain
def publish_joker_chain():
    run_command(['scp', JOKER_CHAIN_FILE, 'ivo@fginfo:public_html/.'])


def get_joker_chain_online():
    response = requests.get('https://fginfo.ksbg.ch/~ivo/'+JOKER_CHAIN_FILE)
    if response.status_code != 200:
        raise FileNotFoundError("Die aktuelle JokerChain konnte nicht vom Server geladen werden, Statuscode: "+response.status_code)
    JOKER_CHAIN['lines'] = response.text.strip().split("\n")
    boxprint("JokerChain vom Server geladen")
    save_joker_chain()


def delete_temp_files():
    for file in [TEMP_FILE, TEMP_KEY_FILE, SIGNATURE_FILE, SIGNATURE_FILE64]:
        if os.path.exists(file):
            os. remove(file) 

def complete_delete():
    delete_temp_files()
    for file in [JOKER_CHAIN_FILE, PUBLIC_KEY_FILE, PRIVATE_KEY_FILE]:
        if os.path.exists(file):
            os. remove(file) 

def add_user(pub_key_file, numtokens=5):
    if not JOKER_CHAIN['admin']:
        raise PermissionError("Sie sind nicht Admin dieser Joker-Chain und können darum keine Nutzer hinzufügen")
    entry = "# user\n## publickey\n"
    pubkey = file_to_byte_array(pub_key_file).decode("ascii")
    entry += pubkey
    entry += "## hash\n"
    entry += get_hash_from_data(pubkey)+"\n"
    entry += "## tokens\n"
    t = time.time()
    entry +=" ".join([get_hash_from_data(str(t+i)) for i in range(numtokens)])+"\n"
    JOKER_CHAIN['lines']+=entry.strip().split("\n")
    return entry

def is_end_of_section(pos):
    return pos==len(JOKER_CHAIN['lines']) or JOKER_CHAIN['lines'][pos][0]=="#"

def parse_entry(pos):
    pos+=1
    entry = ""
    while not is_end_of_section(pos):
        entry += JOKER_CHAIN['lines'][pos]+"\n"
        pos+=1
    return pos, entry


def parse_root(pos):
    pos+=1
    if JOKER_CHAIN['lines'][pos] != "## publickey":
        raise RuntimeError("Erste subsection vom root muss ## publickey sein")
    pos, JOKER_CHAIN['adminkey'] = parse_entry(pos)
    if JOKER_CHAIN['lines'][pos] != "## keyhash":
        raise RuntimeError("Zweite subsection vom root muss ## keyhash sein")
    pos, hash = parse_entry(pos)
    JOKER_CHAIN['adminhash'] = hash.strip()
    print("adminhash=%s, myhash=%s" % (JOKER_CHAIN['adminhash'], JOKER_CHAIN['myhash']))
    JOKER_CHAIN['admin'] = JOKER_CHAIN['adminhash']==JOKER_CHAIN['myhash']
    if get_hash_from_key(JOKER_CHAIN['adminkey'])!=JOKER_CHAIN['adminhash']:
        raise ValueError("Oops! Der Hash vom öffentlichen Admin-Schlüssel ist falsch")
    if JOKER_CHAIN['lines'][pos] != "## timestamp":
        raise RuntimeError("Dritte subsection vom root muss ## timestamp sein")
    pos, t = parse_entry(pos)
    if JOKER_CHAIN['lines'][pos] != "## signature":
        raise RuntimeError("Vierte subsection vom root muss ## signature sein")
    sigtext = "\n".join(JOKER_CHAIN['lines'][0:(pos+1)])+"\n"
    pos, sig = parse_entry(pos)
    if not unterschrift_pruefen(sigtext, sig, JOKER_CHAIN['adminkey']):
        raise ValueError("Oops! Die Root-Unterschrift ist falsch.")
    JOKER_CHAIN['keys'][JOKER_CHAIN['adminhash']] = JOKER_CHAIN['adminkey']
    return pos

def parse_user(pos):
    pos+=1
    head = JOKER_CHAIN['lines'][pos]
    while head[0:2]=="##":
        print("parse_user on ->%s<-" % head)
        if head == "## publickey":
            pos, userkey = parse_entry(pos)
        elif head == "## hash":
            pos, userhash = parse_entry(pos)
            userhash = userhash.strip()
        elif head == "## tokens":
            pos, tokens = parse_entry(pos)
        else:
            raise RuntimeError("Kaputte JokerChain! Keine Ahnung, was der Header ->"+head+"<- in der user-Section soll.")
        if pos==len(JOKER_CHAIN['lines']):
            break
        head = JOKER_CHAIN['lines'][pos]
    JOKER_CHAIN['keys'][userhash] = userkey

def parse_joker_chain():
    if not os.path.exists(PUBLIC_KEY_FILE):
        raise FileExistsError
    JOKER_CHAIN['mypubkey'] = get_public_key()
    JOKER_CHAIN['myhash'] = get_hash_from_key_file(PUBLIC_KEY_FILE)
    # Current line to parse
    pos = 0
    while pos<len(JOKER_CHAIN['lines']):
        head = JOKER_CHAIN['lines'][pos]
        print("Parsing ->%s<-" % head)
        if head=="# root":
            pos = parse_root(pos)
        elif head=="# user":
            pos = parse_user(pos)
        else:
            raise RuntimeError("Kaputte JokerChain! Header der Form ->"+head+"<- unbekannt.")
        



# complete_delete()
# new_key_pair()
# new_joker_chain()
# publish_joker_chain()
# get_joker_chain_online()
load_joker_chain()
print(add_user('testuser.pem'))
delete_temp_files()


