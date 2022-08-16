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
import time, datetime
import argparse
import requests
import re

# Globale Variablen
PRIVATE_KEY_FILE = "secret-private-key-joker.pem"
PUBLIC_KEY_FILE = "public-key-joker.pem"
JOKER_CHAIN_FILE = "joker-chain.md"
JOKER_CHAIN_URL = "https://bloechligair.ch/jokerchain/"
HASH_TO_NAME_FILE = "hash2name.txt"
TEMP_FILE = "tempfile.bin"
TEMP_KEY_FILE = "tempkey.pem"
SIGNATURE_FILE = "signature.bin"
SIGNATURE_FILE64 = "signature.b64"

# Dictionary mit allen wichtigen Einträgen zur aktuellen JokerChain
JOKER_CHAIN = {}

def reset_joker_chain_in_memory():
    global JOKER_CHAIN
    if 'args' in JOKER_CHAIN:
        args = JOKER_CHAIN['args']
    else:
        args = None
    JOKER_CHAIN = {'lines':[], 'adminhash':'', 'adminkey':'', 'myhash':'', 'mypubkey':'', 'tokens':{}, 'admin':False, 'keys':{}, 'transactions':{}, 'names':{}, 'args':args, 'signed':False}


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
    cmdline = "\033[32m" + " ".join(["'"+c.replace("'", "\\'")+"'" if "'" in c else c for c in cmd])+"\033[0m"
    if JOKER_CHAIN['args'].verbose:
        print(cmdline)
    result = subprocess.run(cmd, capture_output=True);
    if result.returncode!=0:
        print(result)
        raise ChildProcessError("Kommando fehlgeschlagen")
    return result.stdout



# Generiert einen neues Schlüsselpaar.
def new_key_pair():
    if os.path.exists(PRIVATE_KEY_FILE) or os.path.exists(PUBLIC_KEY_FILE):
        if not JOKER_CHAIN['args'].force:
            raise FileExistsError("Oops! Mindestens eine der Schlüsseldateien "+PRIVATE_KEY_FILE+" oder "+PUBLIC_KEY_FILE+" existiert bereits")
        else:
            boxprint("Schlüssel werden unwiderruflich überschrieben!")

    run_command(['openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', PRIVATE_KEY_FILE], comment="Generierung des privaten Schlüssels.\nGut aufbewahren, backupen, und geheim halten.\n -> Datei "+PRIVATE_KEY_FILE)
    run_command(['openssl', 'ec', '-in', PRIVATE_KEY_FILE, '-pubout', '-out', PUBLIC_KEY_FILE], comment="Konvertierung des öffentlichen Schlüssels\n -> "+PUBLIC_KEY_FILE+"\nDiesen Schlüssel dem Admin schicken")
    print("Ihr öffentlicher Schlüssel:")
    print(get_public_key())

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


def check_last_signature(pos, hash):
    while JOKER_CHAIN['lines'][pos] != '## signature':
        pos-=1
    sigtext = "\n".join(JOKER_CHAIN['lines'][0:(pos+1)])+"\n"
    pos, sig = parse_entry(pos)
    if not unterschrift_pruefen(sigtext, sig, JOKER_CHAIN['keys'][hash]):
        raise ValueError("Oops! Die Unterschrift vom Benutzer %s ist falsch." % hash)
    if JOKER_CHAIN['args'].verbose:
        print("Unterschrift von %s in Zeile %d erfolgreich überprüft." % (hash, pos))

def redeem_joker(datum):
    if not re.match(r"^202[2-5]-(0[1-9]|1[0-2])-([0-2][0-9]|3[0-1])$", datum):
        raise RuntimeError("Das Datum muss in der Form JJJJ-MM-DD sein, z.B. 2022-08-15. Und nicht %s" % datum)
    heute = datetime.datetime.now().strftime("%Y-%m-%d")
    if datum<=heute:
        raise RuntimeError("Joker können nur in der Zukunft eingelöst werden (bis spätestens 23:59:59 am Vortag)")
    myhash = JOKER_CHAIN['myhash']
    if len(JOKER_CHAIN['tokens'][myhash])==0:
        raise PermissionError("Tut mir leid, Sie haben keine Joker mehr.")
    token = JOKER_CHAIN['tokens'][myhash].pop()
    JOKER_CHAIN['transactions'][myhash] = ["Ein Joker am %s eingelöst. Anzahl Joker: %d" % (datum, len(JOKER_CHAIN['tokens'][myhash]))]
    entry = "# usejoker\n## sender\n"+myhash+"\n## token\n"+token+"\n## usedate\n"+datum+"\n"+timestamp()
    JOKER_CHAIN['lines'] += entry.strip().split("\n")
    entry +=sign_chain()
    save_joker_chain()
    if JOKER_CHAIN['args'].verbose:
        print(entry)
    add_block_online(entry)
    return entry

def transfer_joker(dsthash):
    if not dsthash in JOKER_CHAIN['keys']:
        raise RuntimeError("Der Hash %s existiert nicht in der JokerChain." % dsthash)
    srchash = JOKER_CHAIN['myhash'];
    if (len(JOKER_CHAIN['tokens'][srchash])==0):
        raise RuntimeError("Überweisung nicht möglich, Sie haben keine Joker mehr!")
    token = JOKER_CHAIN['tokens'][srchash].pop()
    datum = datetime.datetime.now().strftime("%Y-%m-%d")
    JOKER_CHAIN['transactions'][hash] = ["Ein Joker am %s an %s transferiert. Anzahl Joker: %d" % (datum, dsthash, len(JOKER_CHAIN['tokens'][srchash]))]
    entry = "# transfer\n## sender\n"+srchash+"\n## token\n"+token+"\n## receiver\n"+dsthash+"\n"+timestamp()
    JOKER_CHAIN['lines'] += entry.strip().split("\n")
    entry +=sign_chain()
    save_joker_chain()
    if JOKER_CHAIN['args'].verbose:
        print(entry)
    add_block_online(entry)
    return entry


def save_joker_chain():
    chain = "\n".join(JOKER_CHAIN['lines'])+"\n"
    with open(JOKER_CHAIN_FILE, "w") as f:
        f.write(chain)
    if JOKER_CHAIN['args'].verbose:
        print("JokerChain saved to "+JOKER_CHAIN_FILE)

def load_joker_chain():
    if not os.path.exists(JOKER_CHAIN_FILE):
        if JOKER_CHAIN['args'].verbose:
            print("Datei %s existiert nicht. Versuche Download." % JOKER_CHAIN_FILE)
        get_joker_chain_online()
    reset_joker_chain_in_memory()
    if not os.path.exists(JOKER_CHAIN_FILE):
        raise FileNotFoundError("Datei %s nicht gefunden..." % JOKER_CHAIN_FILE)
    
    with open(JOKER_CHAIN_FILE, "r") as f:
        JOKER_CHAIN['lines'] = [l.strip() for l in f.readlines() if len(l)>0]
    if os.path.exists(HASH_TO_NAME_FILE):
        with open(HASH_TO_NAME_FILE, "r") as f:
            lines = [l.strip() for l in f.readlines()]
            JOKER_CHAIN['names'] = {lines[i]: lines[i + 1] for i in range(0, len(lines), 2)}
    parse_joker_chain()

def new_joker_chain():
    reset_joker_chain_in_memory()
    if os.path.exists(JOKER_CHAIN_FILE):
        if JOKER_CHAIN['args'].force:
            if JOKER_CHAIN['args'].verbose:
                print("Deleting jokerchain and making new chain as admin")
            os.remove(JOKER_CHAIN_FILE)
        else:
            raise FileExistsError("Die Datei "+JOKER_CHAIN_FILE+" existiert bereits.")
    entry = "# root\n## publickey\n"
    if not os.path.exists(PUBLIC_KEY_FILE):
        new_key_pair()
    entry += get_public_key()
    entry += "## keyhash\n"
    JOKER_CHAIN['myhash'] = get_hash_from_key_file(PUBLIC_KEY_FILE)
    entry += JOKER_CHAIN['myhash']+"\n";    
    JOKER_CHAIN['lines']=entry.strip().split("\n")
    JOKER_CHAIN['admin']=True
    sign_chain()
    save_joker_chain()

def sign_chain():
    if JOKER_CHAIN['admin']:
        entry = "# rootsignature\n"+timestamp()+"## signature\n"
    else:
        entry = "## signature\n"
    signature = unterschreiben("\n".join(JOKER_CHAIN['lines'])+"\n"+entry)
    entry += signature
    JOKER_CHAIN['lines']+=entry.strip().split("\n")
    return entry


# Gets the JokerChain from Server, parses it and saves it
def get_joker_chain_online():
    if JOKER_CHAIN['args'].verbose:
        print("Getting chain from "+JOKER_CHAIN_URL)
    response = requests.get(JOKER_CHAIN_URL)
    if response.status_code != 200:
        raise FileNotFoundError("Die aktuelle JokerChain konnte nicht vom Server geladen werden, Statuscode: "+response.status_code)
    reset_joker_chain_in_memory()
    JOKER_CHAIN['lines'] = response.text.strip().split("\n")
    if JOKER_CHAIN['args'].verbose:
        boxprint("JokerChain vom Server geladen")
    parse_joker_chain()
    save_joker_chain()

def add_block_online(block):
    response = requests.post(JOKER_CHAIN_URL, data={'block':block})
    if response.status_code != 200:
        raise FileNotFoundError("Der neue Block konnte nicht an den Server gesendet werden, Statuscode: "+response.status_code+"\nResponse: "+response.text)
    if JOKER_CHAIN['args'].verbose:
        print(response.text)
    get_joker_chain_online()

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
    hash = get_hash_from_key(pubkey)
    entry += hash + "\n"
    entry += "## tokens\n"
    t = time.time()
    tokens = [get_hash_from_data(str(t+i)) for i in range(numtokens)]
    entry +=" ".join(tokens)+"\n"
    JOKER_CHAIN['lines']+=entry.strip().split("\n")
    JOKER_CHAIN['keys'][hash]= pubkey
    JOKER_CHAIN['tokens'][hash] = tokens
    entry += sign_chain()
    with open(HASH_TO_NAME_FILE, "a") as f:
        f.write(hash+"\n"+pub_key_file[0:-4]+"\n")
    save_joker_chain()
    add_block_online(entry)
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

def timestamp_to_date(ts):
    return datetime.datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d")

def getSubsections(pos, subsections):
    section = JOKER_CHAIN['lines'][pos]
    pos+=1
    res = {}
    for i,subsection in enumerate(subsections):
        if JOKER_CHAIN['lines'][pos] != "## "+subsection:
            raise RuntimeError("Die %d. subsection von %s muss %s sein (nicht %s)." % (i,section, subsection, JOKER_CHAIN['lines'][pos]))
        pos, e = parse_entry(pos)
        res[subsection]=e.strip()
    return pos, res

def assert_user_hash_exists(hash):
    if not hash in JOKER_CHAIN['keys']:
        raise RuntimeError("Der Benutzer %s ist nicht in der Joker-Chain eingetragen" % hash)

def assert_user_has_token(userhash, token):
    assert_user_hash_exists(userhash)
    if not token in JOKER_CHAIN['tokens'][userhash]:
        raise RuntimeError("Der Benutzer %s hat keinen Token %s" % (userhash, token))


def parse_root(pos):
    JOKER_CHAIN['signed'] = False
    pos, e = getSubsections(pos, ["publickey", "keyhash"])
    hash = e['keyhash']
    JOKER_CHAIN['adminkey'] = e['publickey']
    JOKER_CHAIN['adminhash'] = hash
    JOKER_CHAIN['keys'][hash] = JOKER_CHAIN['adminkey']
    JOKER_CHAIN['admin'] = JOKER_CHAIN['adminhash']==JOKER_CHAIN['myhash']
    JOKER_CHAIN['tokens'][hash.strip()]=[]
    if get_hash_from_key(JOKER_CHAIN['adminkey'])!=JOKER_CHAIN['adminhash']:
        raise ValueError("Oops! Der Hash vom öffentlichen Admin-Schlüssel ist falsch")
    if JOKER_CHAIN['args'].verbose:
        print("Admin-Block gelesen, und Hash vom public-key verifiziert.")
    return pos

def parse_rootsignature(pos):
    pos, e = getSubsections(pos, ["timestamp", "signature"])
    check_last_signature(pos-1, JOKER_CHAIN['adminhash'])
    if JOKER_CHAIN['args'].verbose:
        print("Admin-Unterschrift der Joker-Chain bis Zeile %d überprüft." % pos)
    JOKER_CHAIN['signed'] = True
    return pos
    

def parse_user(pos):
    JOKER_CHAIN['signed'] = False
    pos, e = getSubsections(pos, ["publickey", "hash", "tokens"])
    tokens = e['tokens'].split(" ")
    userhash = e['hash']
    userkey = e['publickey']
    if get_hash_from_key(userkey)!=userhash:
        raise ValueError("Oops! Der Hash vom öffentlichen User-Schlüssel ist falsch")
    JOKER_CHAIN['keys'][userhash] = userkey
    JOKER_CHAIN['tokens'][userhash] = tokens
    JOKER_CHAIN['transactions'][userhash] = ["Start mit %d jokern. Anzahl Joker: %d" % (len(tokens), len(tokens))]
    if JOKER_CHAIN['args'].verbose:
        print("\033[35mUser mit hash %s und %d Jokern hinzugefügt.\033[0m" % (userhash, len(tokens)))
    return pos

def parse_usejoker(pos):
    JOKER_CHAIN['signed'] = False
    pos, e = getSubsections(pos, ["sender", "token", "usedate", "timestamp", "signature"])
    assert_user_has_token(e['sender'], e['token'])
    datumsigned = timestamp_to_date(e['timestamp'])
    if datumsigned>=e['usedate']:
        raise RuntimeError("In section usejoker: Datum des Jokereinsatzes ist %d, der Eintrag wurde aber erst am %d erstellt." % (datum, datumsigned))
    check_last_signature(pos-1, e['sender'])
    if JOKER_CHAIN['args'].verbose:
        print("User-Unterschrift der Joker-Chain bis Zeile %d überprüft." % pos)
    hash = e['sender']
    token = e['token']
    datum = e['usedate']
    JOKER_CHAIN['tokens'][hash].remove(token)
    JOKER_CHAIN['transactions'][hash] += ["Ein Joker am %s eingelöst. Anzahl Joker: %d" % (datum, len(JOKER_CHAIN['tokens'][hash]))]
    if JOKER_CHAIN['args'].verbose:
        print("\033[35mUser %s hat token %s am %s eingelöst.\033[0m" % (hash, token, datum))
    return pos

def parse_transfer(pos):
    JOKER_CHAIN['signed'] = False
    pos, e = getSubsections(pos, ["sender", "token", "receiver", "timestamp", "signature"])
    assert_user_has_token(e['sender'], e['token'])
    assert_user_hash_exists(e['receiver'])
    check_last_signature(pos-1, e['sender'])
    JOKER_CHAIN['tokens'][e['sender']].remove(e['token'])
    JOKER_CHAIN['tokens'][e['receiver']].append(e['token'])
    JOKER_CHAIN['transactions'][e['sender']].append("Ein Joker am %s an %s transferiert. Anzahl Joker: %d" % (timestamp_to_date(e['timestamp']), e['receiver'], len(JOKER_CHAIN['tokens'][e['sender']])))
    JOKER_CHAIN['transactions'][e['receiver']].append("Ein Joker am %s von %s transferiert bekommen. Anzahl Joker: %d" % (timestamp_to_date(e['timestamp']), e['sender'], len(JOKER_CHAIN['tokens'][e['receiver']])))
    return pos

def add_block(datei):
    if not JOKER_CHAIN['admin']:
        raise PermissionError("Nur der Admin kann Blöcke aus einer Datei anhängen.")
    if not os.path.exists(datei):
        raise FileNotFoundError("Die Datei mit dem neuen Block existiert nicht: "+datei)
    pos = len(JOKER_CHAIN['lines'])
    lines = file_to_byte_array(datei).decode("ascii").strip().split("\n")
    print("Attempting to add\n"+"\n".join(lines))
    JOKER_CHAIN['lines'] += lines
    try:
        parse_joker_chain(pos)
        return True
    except:
        return False


def parse_joker_chain(pos = None):
    if pos==None:
        if not os.path.exists(PUBLIC_KEY_FILE):
            print("Keine Schlüsseldateien gefunden. Diese müssen im Verzeichnis liegen, wo das Programm ausgeführt wird. Eventuell müssen Sie erst Schlüssel erzeugen, mit der -n Option.")
        else:
            JOKER_CHAIN['mypubkey'] = get_public_key()
            JOKER_CHAIN['myhash'] = get_hash_from_key_file(PUBLIC_KEY_FILE)
        # Current line to parse
        if JOKER_CHAIN['lines'][0] != "# root":
            raise RuntimeError("Erste section in der JokerChain muss # root sein")
        pos = parse_root(0)
    while pos<len(JOKER_CHAIN['lines']):
        head = JOKER_CHAIN['lines'][pos]
        # print("Parsing ->%s<-" % head)
        JOKER_CHAIN['signed'] = False
        if head=="# user":
            pos = parse_user(pos)
        elif head=="# rootsignature":
            pos = parse_rootsignature(pos)
        elif head=="# usejoker":
            pos = parse_usejoker(pos)
        elif head=="# transfer":
            pos = parse_transfer(pos)
        else:
            raise RuntimeError("Kaputte JokerChain! Header der Form ->"+head+"<- unbekannt.")
    if JOKER_CHAIN['signed']:
        boxprint("JokerChain geladen und vollständig verifiziert.")
    else:
        boxprint("JokerChain geladen und auf Korrektheit überprüft.\nEs ist aber noch eine Admin-Unterschrift ausstehend.")
    if JOKER_CHAIN['myhash'] in JOKER_CHAIN['tokens']:
        if JOKER_CHAIN['args'].verbose:
            print("Ihre Transaktionen für das Konto %s:" % JOKER_CHAIN['myhash'])
            for t in JOKER_CHAIN['transactions'][JOKER_CHAIN['myhash']]:
                print(t)
        print("Anzahl Joker auf Ihrem Konto mit Hash %s: %d" % (JOKER_CHAIN['myhash'], len(JOKER_CHAIN['tokens'][JOKER_CHAIN['myhash']])))
    else:
        if len(JOKER_CHAIN['mypubkey'])>0:
            print("Sie haben noch keine Joker. Senden Sie Ihren public-Key per e-mail dem Administrator:")
            print(JOKER_CHAIN['mypubkey'])
        else:
            print("Sie müssen erst noch ein Schlüsselpaar erzeugen, mit der -n Option.")


# Kommandozeilenargumente festlegen und auswerten

parser = argparse.ArgumentParser(description='Joker-Chain Tools.\nAlles was Sie zum Verwalten, Transferieren und Einlösen Ihrer Joker brauchen.')
parser.add_argument('-v', '--verbose', action='store_true', help="Zusätzliche Programminformationen ausgaben.")
parser.add_argument('-f', '--force', action='store_true', help="Dateien überschreiben.")

commands = parser.add_mutually_exclusive_group()
commands.add_argument('-d', '--datum', nargs=1, type=str, help="Joker zum Datum im Dormat JJJJ-MM-DD einlösen.")
commands.add_argument('-t', '--transfer', nargs=1, type=str, help="Joker an user mit dem hash TRANSFER überweisen.")
commands.add_argument('-n', '--newkeys', action='store_true', help="Neues Schlüsselpaar erzeugen. Erzeugt die Dateien public-key-joker.pem und secret-private-key-joker.pem")
commands.add_argument('-u', '--update', action='store_true', help="Letzte Version vom Server laden.")
commands.add_argument('-i', '--initialize', action='store_true', help="Komplett neue Chain als Admin anlegen.")
commands.add_argument('-a', '--adduserkeyfile', nargs=1, type=str, help="Mit Angabe einer Datei mit öffentlichem Schlüssel als Admin einen neuen User mit Jokern hinzufügen.")
commands.add_argument('-s', '--sign', action='store_true', help="Als Admin die aktuelle Chain signieren")
commands.add_argument('-b', '--blockfile', nargs=1, type=str, help="Als Admin einen weiteren Abschnitt aus einer Datei hinzufügen (wenn dieser korrekt ist)")
args = parser.parse_args()

reset_joker_chain_in_memory()
JOKER_CHAIN['args'] = args

if args.datum:
    get_joker_chain_online()
    redeem_joker(args.datum[0])
elif args.transfer:
    get_joker_chain_online()
    transfer_joker(args.transfer[0])
elif args.newkeys:
    new_key_pair()
elif args.update:
    get_joker_chain_online()
elif args.initialize:
    new_joker_chain()
    save_joker_chain()
elif args.adduserkeyfile:
    load_joker_chain()
    add_user(args.adduserkeyfile[0])
elif args.sign:
    load_joker_chain()
    if not JOKER_CHAIN['signed']:
        sign_chain()
        save_joker_chain()
    else:
        print("Chain is already signed!")
elif args.blockfile:
    load_joker_chain()
    if (add_block(args.blockfile[0])):
        if not JOKER_CHAIN['signed']:
            sign_chain()
        save_joker_chain()
else:
    get_joker_chain_online()
delete_temp_files()
