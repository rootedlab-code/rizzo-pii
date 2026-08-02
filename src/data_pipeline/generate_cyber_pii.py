#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dati sintetici del GENERE documentale mancante: i documenti di sicurezza.

Il modello e' addestrato su prosa legale italiana. I report di assessment, le
timeline forensi, i ticket di incidente e gli estratti di log sono un altro
registro — piu' tecnico, con italiano e inglese mescolati, elenchi e frammenti di
comando — e li' i tag che il modello DEVE trovare (FULLNAME, ORG, EMAIL, DATE,
TELEPHONENUM) peggiorano. Quelli sono anche i tag che la rete regex non copre:
sono proprio il lavoro del modello.

Due modalita', stesso codice:

  DEFAULT — i valori cyber (IP, domini, hash, percorsi) compaiono nella prosa
    SENZA etichetta. La tassonomia non cambia, `num_labels` non cambia, il
    checkpoint resta compatibile. Serve a due cose insieme: insegnare il genere
    documentale, e insegnare che un indirizzo IP e' `O` — un modello che non ne ha
    mai visto uno puo' etichettarlo come qualcos'altro.

  --label-cyber — gli stessi valori escono ETICHETTATI (B-IP, I-IP, ...). Cambia
    `num_labels`, quindi impone un riaddestramento completo e rende incompatibile
    il checkpoint attuale. Tenuto separato e non default proprio per questo: i
    valori cyber sono strutturati e la rete regex+validatori li copre gia' in modo
    esatto, quindi il beneficio marginale e' basso e il costo alto.

Principio del progetto rispettato alla lettera ("LLM autore, codice
etichettatore", vedi CLAUDE.md): il testo con i soli segnaposto e' scritto a mano
o da Gemini, i valori li inietta il codice — quindi le label BIO sono esatte per
costruzione e nessuna PII reale viene mai prodotta.

  INVARIANTE NON NEGOZIABILE: ogni valore generato viene dagli spazi riservati
  alla documentazione — RFC 5737 e RFC 1918 (IPv4), RFC 3849 (IPv6), RFC 2606
  (domini), RFC 5398 (ASN), RFC 7042 (MAC). Un dataset sintetico non deve
  contenere un indirizzo instradabile che appartiene a qualcuno. C'e' un test che
  lo verifica su decine di migliaia di valori generati.

Nessun file upstream viene modificato: gli slot si registrano in
generate_synthetic_pii.SLOTS, che e' un registro nome->generatore riletto da
build_example a ogni chiamata.

    python src/data_pipeline/generate_cyber_pii.py -n 5000
    python src/data_pipeline/generate_cyber_pii.py -n 5000 --label-cyber
    python src/data_pipeline/generate_cyber_pii.py -n 5000 --gemini --per-type 2
"""

import collections
import hashlib
import ipaddress
import json
import random
import re
import string
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "data_pipeline"))

# .env PRIMA di importare i moduli che leggono le env var a import-time
# (llm_template_bank fissa API_KEY quando viene importato).
try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except ImportError:
    pass

import generate_synthetic_pii as gen  # noqa: E402
# NB: llm_template_bank sostituisce sys.stdout con un nuovo TextIOWrapper a
# import-time. Importarlo pigramente dentro una funzione fa SPARIRE tutto cio' che
# era gia' stato stampato e non ancora scaricato: va importato qui, prima di
# qualsiasi print. (Stessa ragione per cui contribute_dataset.py lo importa in cima.)
import llm_template_bank as tb  # noqa: E402

sys.path.insert(0, str(ROOT / "src" / "app"))
import detectors_cyber  # noqa: E402

# Stessa lista di TLD dei detector: il controllo sugli spazi documentali deve sapere
# cos'e' davvero un dominio, altrimenti scambia 'index.html' per uno.
_REAL_TLDS = {t.lower() for t in detectors_cyber.TLDS}

OUT_DIR = ROOT / "dataset" / "synthetic"
BANK_PATH = OUT_DIR / "security_templates.json"
GENERATOR_VERSION = "1.0.0"

# Dopo tante chiamate fallite di fila si smette. Il 429 di quota non e' transitorio:
# insistere non lo risolve e consuma quello che resta.
MAX_CONSECUTIVE_FAILURES = 3

# --------------------------------------------------------------------------- #
# Spazi documentali — l'invariante di sicurezza di questo modulo                #
# --------------------------------------------------------------------------- #
# RFC 5737: riservati agli esempi, non instradabili, non appartengono a nessuno.
DOC_NETS_V4 = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
# RFC 1918: reti private, per l'infrastruttura "interna" dei documenti.
PRIVATE_NETS_V4 = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
DOC_NET_V6 = "2001:db8::/32"                    # RFC 3849
DOC_ASN_RANGES = ((64496, 64511), (65536, 65551))   # RFC 5398
DOC_MAC_PREFIX = "00:00:5e:00:53"               # RFC 7042 §2.1.2

# RFC 2606 + i sottodomini che si costruiscono sopra.
DOC_TLDS = ("example", "test", "invalid")
DOC_SLD = ("example.com", "example.org", "example.net")

_ALL_DOC_NETS = tuple(ipaddress.ip_network(n) for n in DOC_NETS_V4 + PRIVATE_NETS_V4)
_DOC_NET_V6 = ipaddress.ip_network(DOC_NET_V6)

_HEX = "0123456789abcdef"
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Parole con cui si compongono host e percorsi: nessuna e' un marchio reale.
_HOST_WORDS = ("srv", "web", "mail", "vpn", "db", "app", "node", "gw", "proxy",
               "backup", "share", "dc", "fs", "log", "ns")
_SUB_WORDS = ("portale", "intranet", "clienti", "servizi", "posta", "cdn", "api",
              "download", "update", "static", "auth")
_BAD_WORDS = ("update-secure", "login-verify", "cdn-delivery", "doc-share",
              "invoice-portal", "secure-mail", "cloud-sync", "account-check")
_USERS = ("m.rossi", "a.bianchi", "g.ferrari", "l.russo", "f.esposito", "s.romano",
          "admin", "svc_backup", "operatore", "helpdesk")
_PATH_WORDS = ("Documenti", "Desktop", "Download", "AppData", "Temp", "backup",
               "condivisa", "archivio", "export", "log")


# --------------------------------------------------------------------------- #
# Etichettatura: lo stesso generatore serve le due modalita'                    #
# --------------------------------------------------------------------------- #
CYBER_LABELS = ("IP", "DOMAIN", "URL", "HASH", "MAC", "ASN", "WALLET",
                "CLOUDID", "PATH", "USER")

_label_cyber = False


def set_label_cyber(enabled):
    """True = i valori cyber escono etichettati (cambia num_labels: riaddestramento).

    Stato di modulo, come ACTIVE_DETECTORS in app.py: i generatori sono chiamati da
    build_example senza poter ricevere parametri, quindi la modalita' va letta da
    qualche parte al momento della chiamata."""
    global _label_cyber
    _label_cyber = bool(enabled)


def _lab(label):
    return label if _label_cyber else None


# --------------------------------------------------------------------------- #
# Generatori di valori — SEMPRE dentro gli spazi documentali                    #
# --------------------------------------------------------------------------- #
def _addr_in(net_str):
    net = ipaddress.ip_network(net_str)
    # niente network address ne' broadcast: sarebbero indirizzi non assegnabili
    size = net.num_addresses
    offset = random.randint(1, size - 2) if size > 2 else 0
    return str(net.network_address + offset)


def _ipv4():
    return _addr_in(random.choice(DOC_NETS_V4 + PRIVATE_NETS_V4))


def _ipv6():
    # /32 documentale: si sorteggiano solo i 96 bit bassi, il prefisso resta 2001:db8
    tail = random.getrandbits(96)
    return str(ipaddress.IPv6Address(int(_DOC_NET_V6.network_address) + tail)).lower()


def _hostname():
    return f"{random.choice(_HOST_WORDS)}{random.randint(1, 99):02d}"


def _domain(hostile=False):
    """Dominio in spazio RFC 2606. hostile=True usa parole da phishing, ma il TLD
    resta documentale: la forma e' credibile, il dominio non esiste."""
    word = random.choice(_BAD_WORDS if hostile else _SUB_WORDS)
    if random.random() < 0.35:
        return f"{word}.{random.choice(DOC_SLD)}"
    return f"{word}.{random.choice(DOC_TLDS)}"


def _hex(n):
    return "".join(random.choice(_HEX) for _ in range(n))


def _b58check(version=0x00):
    """Indirizzo Bitcoin con checksum Base58Check VALIDO su payload casuale.

    Serve valido perche' il nostro detector lo verifica: un wallet finto ma
    malformato non verrebbe rilevato e il dato di test non misurerebbe nulla."""
    payload = bytes([version]) + random.getrandbits(160).to_bytes(20, "big")
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    num = int.from_bytes(payload + checksum, "big")
    out = ""
    while num:
        num, rem = divmod(num, 58)
        out = _B58[rem] + out
    return "1" * (len(payload + checksum) - len((payload + checksum).lstrip(b"\x00"))) + out


# --------------------------------------------------------------------------- #
# Slot (nome -> [(testo, label)], come i generatori del progetto)               #
# --------------------------------------------------------------------------- #
def ip_piece():
    return [(_ipv4(), _lab("IP"))]


def ip6_piece():
    return [(_ipv6(), _lab("IP"))]


def cidr_piece():
    """Sottorete casuale di una rete privata.

    L'offset si sorteggia invece di prendere net.subnets().next(): quello ritorna
    sempre la PRIMA sottorete, e il dataset conterrebbe solo 10.0.0.0/16."""
    net = ipaddress.ip_network(random.choice(PRIVATE_NETS_V4))
    prefix = random.choice((16, 20, 24))
    if prefix <= net.prefixlen:
        return [(str(net), _lab("IP"))]
    step = 2 ** (net.max_prefixlen - prefix)
    base = int(net.network_address) + random.randrange(net.num_addresses // step) * step
    return [(str(ipaddress.ip_network((base, prefix))), _lab("IP"))]


def domain_piece():
    return [(_domain(), _lab("DOMAIN"))]


def bad_domain_piece():
    return [(_domain(hostile=True), _lab("DOMAIN"))]


def url_piece():
    scheme = random.choice(("https", "http"))
    path = "/".join(random.choice(("static", "cgi-bin", "api", "files", "u", "dl"))
                    for _ in range(random.randint(1, 2)))
    tail = random.choice((".php", ".js", ".bin", ".zip", "", "/index.html"))
    return [(f"{scheme}://{_domain(hostile=random.random() < 0.5)}/{path}{tail}",
             _lab("URL"))]


def hash_piece():
    return [(_hex(random.choice((32, 40, 64))), _lab("HASH"))]


def mac_piece():
    return [(f"{DOC_MAC_PREFIX}:{random.randint(0, 255):02x}", _lab("MAC"))]


def asn_piece():
    lo, hi = random.choice(DOC_ASN_RANGES)
    return [(f"AS{random.randint(lo, hi)}", _lab("ASN"))]


def wallet_piece():
    return [(_b58check(), _lab("WALLET"))]


def cloudid_piece():
    kind = random.random()
    if kind < 0.4:
        val = "AKIA" + "".join(random.choice(string.ascii_uppercase + string.digits)
                               for _ in range(16))
    elif kind < 0.7:
        val = f"i-{_hex(17)}"                       # istanza EC2
    else:
        val = f"arn:aws:s3:::backup-{random.choice(_SUB_WORDS)}-{random.randint(100, 999)}"
    return [(val, _lab("CLOUDID"))]


def path_piece():
    user = random.choice(_USERS)
    if random.random() < 0.5:
        val = "C:\\Users\\" + user + "\\" + "\\".join(
            random.choice(_PATH_WORDS) for _ in range(random.randint(1, 2)))
    else:
        val = "/home/" + user + "/" + "/".join(
            random.choice(_PATH_WORDS).lower() for _ in range(random.randint(1, 2)))
    return [(val, _lab("PATH"))]


def user_piece():
    user = random.choice(_USERS)
    if random.random() < 0.5:
        return [(f"{random.choice(('CORP', 'AZIENDA', 'INTRANET'))}\\{user}", _lab("USER"))]
    return [(f"{user}@{_domain()}", _lab("USER"))]


def host_piece():
    """Nome host nudo: NON e' un dominio, resta testo normale in entrambe le modalita'."""
    return [(_hostname(), None)]


def port_piece():
    return [(str(random.choice((22, 80, 443, 445, 3389, 8080, 8443, 53, 25))), None)]


def cve_piece():
    """Riferimento pubblico: non e' un dato di nessuno, non va MAI etichettato.

    Serve nel testo perche' la keeplist dei detector deve poterlo incontrare."""
    return [(f"CVE-{random.randint(2019, 2026)}-{random.randint(1000, 49999)}", None)]


SLOTS = {
    "IPADDR": ip_piece, "IPV6": ip6_piece, "CIDR": cidr_piece,
    "DOMAIN": domain_piece, "BADDOMAIN": bad_domain_piece, "URL": url_piece,
    "HASH": hash_piece, "MAC": mac_piece, "ASN": asn_piece, "WALLET": wallet_piece,
    "CLOUDID": cloudid_piece, "FILEPATH": path_piece, "ACCOUNT": user_piece,
    "HOSTNAME": host_piece, "PORT": port_piece, "CVE": cve_piece,
}


def register():
    """Inserisce gli slot cyber nel registro di generate_synthetic_pii.

    SLOTS li' e' una mappa nome->funzione riletta da build_example a ogni chiamata:
    estenderla e' l'uso previsto del registro, e lascia il file upstream intatto."""
    gen.SLOTS.update(SLOTS)
    return SLOTS


# --------------------------------------------------------------------------- #
# Template di genere sicurezza — scritti a mano, solo segnaposto                #
# --------------------------------------------------------------------------- #
# Le PII usano gli slot GIA' ESISTENTI del progetto (sono i tag che il modello deve
# imparare); i valori cyber usano i nostri. Nessun nome proprio inline: e' il
# principio "LLM autore, codice etichettatore" e c'e' un test che lo verifica.
TEMPLATES = [
    # --- verbale / notifica di incidente ---
    "Il {DATE} alle ore 09:14 il SOC di {ORG} ha rilevato traffico anomalo dall'host "
    "{HOSTNAME} ({IPADDR}) verso {BADDOMAIN} sulla porta {PORT}.",

    "Segnalazione ricevuta da {FULLNAME} ({EMAIL}) in data {DATE}: la postazione "
    "{HOSTNAME} contatta ripetutamente {IPADDR} senza motivo apparente.",

    "In data {DATE} l'utenza {ACCOUNT} ha effettuato l'accesso da {IPADDR}, "
    "geolocalizzato fuori dal perimetro aziendale di {ORG}.",

    "Il referente tecnico {FULLNAME}, raggiungibile al numero {PHONE}, conferma che "
    "il segmento {CIDR} e' dedicato alle postazioni amministrative.",

    # --- timeline forense ---
    "{DATE} 03:22 - primo accesso non autorizzato all'host {HOSTNAME} ({IPADDR}) "
    "tramite l'utenza {ACCOUNT}.\n"
    "{DATE} 03:41 - scaricato il file da {URL}, hash SHA-256 {HASH}.\n"
    "{DATE} 04:07 - persistenza creata in {FILEPATH}.",

    "Alle 02:15 il processo ha scritto in {FILEPATH} un artefatto con hash {HASH}; "
    "alle 02:19 lo stesso artefatto risulta trasmesso verso {IPADDR}.",

    "La ricostruzione mostra il seguente percorso: {IPADDR} -> {HOSTNAME} -> "
    "{BADDOMAIN}. L'ultimo salto avviene su infrastruttura annunciata da {ASN}.",

    # --- ticket / triage ---
    "Ticket n. 4821 aperto da {FULLNAME} il {DATE}. Priorita' alta. Sistema coinvolto: "
    "{HOSTNAME}, indirizzo {IPADDR}, MAC {MAC}.",

    "Triage: l'allegato ricevuto all'indirizzo {EMAIL} contiene un file con hash {HASH}. "
    "L'analisi dinamica mostra una connessione verso {URL}.",

    "In risposta al ticket, {FULLNAME} di {ORG} ha isolato l'host {HOSTNAME} dalla rete "
    "{CIDR} e revocato le credenziali dell'utenza {ACCOUNT}.",

    "Escalation: il caso passa a {FULLNAME} ({EMAIL}, {PHONE}) per la verifica "
    "dell'esposizione della chiave {CLOUDID}.",

    # --- estratti di log e comandi ---
    "Estratto del log del firewall:\n"
    "  {DATE} 11:02:44 DENY {IPADDR}:{PORT} -> {IPADDR}:{PORT}\n"
    "  {DATE} 11:02:51 ALLOW {IPADDR}:{PORT} -> {IPADDR}:{PORT}",

    "Il record DNS interrogato dall'host compromesso risolveva {BADDOMAIN} "
    "sull'indirizzo {IPADDR}, poi ruotato su {IPV6}.",

    "Nel journal compare la riga: connessione da {ACCOUNT} verso {IPADDR} porta {PORT}, "
    "chiusa dopo 3 secondi.",

    "Sono stati raccolti gli artefatti in {FILEPATH} e in {FILEPATH}; entrambi "
    "riconducibili all'utenza {ACCOUNT}.",

    # --- comunicazioni al cliente / esecutivo ---
    "Gentile {FULLNAME}, come concordato le trasmettiamo il riepilogo dell'attivita' "
    "svolta per {ORG} in data {DATE}. Per chiarimenti puo' scrivere a {EMAIL}.",

    "Il perimetro concordato con {ORG} comprende la rete {CIDR} e i sistemi esposti "
    "sugli indirizzi {IPADDR} e {IPADDR}.",

    "Si raccomanda a {ORG} di applicare la patch per {CVE} su tutti i sistemi del "
    "segmento {CIDR} entro il {DATE}.",

    "La valutazione di impatto e' stata condivisa con {FULLNAME} il {DATE}; il costo "
    "stimato del fermo servizio ammonta a {AMOUNT}.",

    "Referente per il seguito: {FULLNAME}, {ORG}, {EMAIL}, tel. {PHONE}. "
    "Sede operativa in {ADDRESS}.",

    # --- indicatori, elenchi, exfil ---
    "Indicatori di compromissione rilevati:\n"
    "  - {IPADDR}\n  - {BADDOMAIN}\n  - {HASH}\n  - {URL}",

    "Il riscatto e' stato richiesto in criptovaluta all'indirizzo {WALLET}, con "
    "scadenza indicata al {DATE}.",

    "I dati risultano trasferiti verso lo storage {CLOUDID}, con accesso effettuato "
    "dall'indirizzo {IPADDR}.",

    "Il dominio {BADDOMAIN} e' registrato da meno di trenta giorni e risolve su "
    "{IPADDR}, all'interno del sistema autonomo {ASN}.",

    "Le credenziali dell'utenza {ACCOUNT} risultano riutilizzate su {DOMAIN}, "
    "circostanza segnalata a {FULLNAME} il {DATE}.",

    # --- verifiche e chiusura ---
    "Verifica di chiusura del {DATE}: l'host {HOSTNAME} ({IPADDR}) risulta "
    "reinstallato, la regola verso {BADDOMAIN} e' attiva, {CVE} risulta corretta.",

    "Nessuna evidenza residua nei percorsi {FILEPATH}; il monitoraggio su {CIDR} "
    "prosegue per trenta giorni, come concordato con {FULLNAME}.",
]


# --------------------------------------------------------------------------- #
# Template da Gemini (facoltativi): stessa macchina del progetto                #
# --------------------------------------------------------------------------- #
ALLOWED_SLOTS = set(SLOTS) | {
    "FULLNAME", "ORG", "EMAIL", "PHONE", "DATE", "CITY", "ADDRESS", "AMOUNT",
}

DOC_TYPES = [
    "verbale di rilevazione di un incidente informatico",
    "timeline forense di una compromissione",
    "ticket di incident response con note di triage",
    "estratto di log di firewall commentato",
    "comunicazione al cliente sull'esito di un assessment",
    "sommario esecutivo di un test di sicurezza",
]

PROMPT = """Sei un analista di sicurezza italiano. Scrivi un {doc_type} REALISTICO
(da 6 a 14 righe), nel registro tecnico che si usa davvero in questi documenti.

REGOLA ASSOLUTA: NON scrivere MAI dati concreti. Al loro posto usa ESCLUSIVAMENTE
questi segnaposto, che verranno sostituiti dal codice:
{slot_list}

Non inventare nomi di persone, aziende, indirizzi IP, domini, hash o percorsi:
usa il segnaposto corrispondente. Non aggiungere segnaposto non elencati.
Rispondi con il solo testo del documento, senza commenti e senza markdown.

{slot_hints}"""

SLOT_HINTS = """  {IPADDR}    = indirizzo IP  |  {CIDR} = rete in notazione CIDR
  {HOSTNAME}  = nome host nudo (non un dominio)  |  {PORT} = numero di porta
  {BADDOMAIN} = dominio riconducibile all'attaccante  |  {DOMAIN} = dominio legittimo
  {ACCOUNT}   = utenza di dominio o indirizzo di accesso
  {FILEPATH}  = percorso su disco  |  {CLOUDID} = identificativo di risorsa cloud
  {CVE}       = riferimento pubblico a una vulnerabilita'"""


# Termini tecnici che nei documenti di sicurezza si scrivono in maiuscolo. Servono a
# togliere i falsi positivi di find_stray_names, che e' tarato sulla prosa legale
# italiana dove due maiuscole di fila sono quasi sempre "Nome Cognome": qui sono
# "Security Operations Center" o "Remote Code Execution", e senza questo elenco si
# scartava oltre meta' dei template.
#
# Il filtro e' ADDITIVO e il nucleo della guardia resta: una coppia viene perdonata
# solo se ENTRAMBE le parole sono qui dentro. "Mario Rossi" viene scartato come
# prima, e anche "Security Rossi" — che e' il caso che conta davvero, il nome vero
# accanto al termine tecnico.
#
# Nessun termine di questo elenco e' un cognome o un nome italiano plausibile: e' il
# criterio con cui e' stato compilato, e va applicato a ogni aggiunta futura.
SECURITY_CAPITALIZED = frozenset("""
Access Account Action Active Alert Analysis Assessment Attack Audit Authentication
Availability Backup Beacon Blocked Breach Category Chain Cloud Code Command Compliance
Compromise Confidentiality Containment Content Control Critical Custody Data Database
Defender Denied Destination Detection Directory Domain Encryption Endpoint Escalation
Evidence Executive Execution Exfiltration Exploit Exposure Filtering Finding Findings
Firewall Forensic Center Framework Gateway Governance Hardening Hash High Host Identity
Impact Incident Indicator Injection Integrity Intelligence Isolation Lateral Least
Level Lockdown Log Logging Low Malicious Malware Management Medium Mitigation Monitoring
Movement Network Note Notes Operations Owner Patch Payload Penetration Perimeter
Persistence Phishing Policy Port Priority Privilege Protocol Quarantined Ransomware
Recovery Remediation Remote Report Response Review Risk Scope Scanning Security Session
Severity Source Status Summary Surface Test Testing Threat Ticket Timeline Traffic
Triage Update Vector Vulnerability
Analisi Assessment Attivita Chiusura Compromissione Contenimento Criticita Evidenze
Impatto Incidente Informatico Isolamento Mitigazione Perimetro Procedere Raccomandazioni
Remediazione Rilevazione Rischio Riscontro Riepilogo Segnalazione Severita Sicurezza
Valutazione Verifica Vulnerabilita
""".split())


def _is_technical_pair(pair):
    """True se una coppia segnalata e' fatta di soli termini tecnici.

    L'elisione si taglia come fa il guard upstream (dell'Host -> Host): senza,
    "l'Isolamento dell'Host" resterebbe un falso positivo."""
    return all(w.split("'")[-1].strip(".:;,") in SECURITY_CAPITALIZED
               for w in pair.split())


def _titled_names(text):
    """Nomi preceduti da un titolo scritto CON il punto: 'Sig. Bianchi', 'Dott. Neri'.

    Copre un caso che il guard upstream lascia passare: li' il salto di fine frase
    ('if a[-1] in ".:;!?": continue') scatta prima del controllo sui titoli, quindi
    'Sig Bianchi' viene intercettato ma 'Sig. Bianchi' — cioe' il modo normale di
    scriverlo — no. Vale anche per il dataset legale: da segnalare a monte."""
    titles = "|".join(re.escape(t) for t in sorted(tb.TITLES, key=len, reverse=True))
    rx = re.compile(rf"\b({titles})\.\s+([A-ZÀ-Þ][A-Za-zÀ-ÿ']+)")
    return [f"{m.group(1)}. {m.group(2)}" for m in rx.finditer(text)
            if m.group(2) not in SECURITY_CAPITALIZED]


def find_stray_names(text):
    """find_stray_names del progetto, meno i falsi positivi del gergo di sicurezza
    e piu' i nomi con titolo puntato che il guard upstream non vede."""
    masked = re.sub(r"\{\w+\}", " ", text)          # i segnaposto non sono nomi
    return ([p for p in tb.find_stray_names(text) if not _is_technical_pair(p)]
            + _titled_names(masked))


SMOKE_ROUNDS = 5          # quante righe di prova si costruiscono da un template
NEAR_DUPLICATE_RATIO = 0.90


# Parole che non possono chiudere una frase: se il testo finisce qui, e' stato
# tagliato a meta'. E' un elenco chiuso e piccolo di proposito — vedi looks_truncated.
_DANGLING_WORDS = frozenset("""
di del dello della dei degli delle d
a al allo alla ai agli alle ad
da dal dallo dalla dai dagli dalle
in nel nello nella nei negli nelle
con col coi su sul sullo sulla sui sugli sulle
per tra fra e ed o od ma che se come quando mentre perche
il lo la i gli le un uno una un' l
non si ci vi ne piu meno molto anche gia ancora
verso presso secondo durante mediante oltre senza dopo prima
sono stato stata stati state viene vengono essere stare
""".split())


def looks_truncated(text):
    """True se il testo e' visibilmente tagliato a meta'.

    RETE DI SICUREZZA, non il controllo principale: la verita' sul troncamento la
    dice `finish_reason == "length"`, che openai_compat_call legge direttamente dalla
    risposta. Questa funzione serve solo dove quel campo non e' disponibile (la strada
    Gemini) e per i template gia' in banca da prima.

    Volutamente TIMIDA. La versione precedente pretendeva punteggiatura terminale e
    bocciava frasi complete a cui mancava solo il punto — che nelle voci di elenco e
    nelle timeline sono la norma: su un campione di tre risposte ne scartava due,
    entrambe integre. Ora segnala solo cio' che non puo' chiudere una frase: una
    parola funzione appesa ('...cancellazione di'), o una sillabazione spezzata."""
    tail = text.rstrip()
    if not tail:
        return True
    if tail.endswith("-"):                       # sillabazione interrotta
        return True
    last = re.findall(r"[A-Za-zÀ-ÿ']+", tail)
    return bool(last) and last[-1].casefold().strip("'") in _DANGLING_WORDS


def smoke_template(text, rounds=SMOKE_ROUNDS):
    """Costruisce qualche riga dal template e la valida. Messaggio d'errore o None.

    E' il controllo piu' forte che si possa fare su un template, perche' non giudica
    il testo: guarda cosa PRODUCE. Intercetta gli slot che generano entita'
    sovrapposte — che to_bio scarterebbe in silenzio, facendo sparire un'etichetta
    senza che nulla lo segnali — e qualunque incoerenza di offset."""
    register()
    for _ in range(rounds):
        try:
            built, entities = gen.build_example(0, [text])
        except (KeyError, IndexError, ValueError) as exc:
            return f"la costruzione fallisce: {type(exc).__name__} {exc}"
        tokens, bio = gen.to_bio(built, entities)
        err = validate_record({"source_text": built, "entities": entities,
                               "tokens": tokens, "bio_labels": bio})
        if err:
            return err
        spans = sorted((e["start"], e["end"]) for e in entities)
        for (_, end), (start, _) in zip(spans, spans[1:]):
            if end > start:
                return "produce entita' sovrapposte (to_bio ne perderebbe una)"
    return None


def is_near_duplicate(text, others, ratio=NEAR_DUPLICATE_RATIO):
    """True se il template e' quasi identico a uno gia' presente.

    I modelli, sullo stesso tipo di documento, riscrivono spesso la stessa struttura
    cambiando due parole: due template gemelli non sono varieta', sono lo stesso
    scheletro contato due volte."""
    import difflib
    a = " ".join(text.split()).casefold()
    for other in others:
        b = " ".join(other.split()).casefold()
        if difflib.SequenceMatcher(None, a, b).ratio() >= ratio:
            return True
    return False


def clean_and_validate(text):
    """Come llm_template_bank.clean_and_validate, ma sui NOSTRI segnaposto.

    Riusa find_stray_names: e' la guardia che scarta i template in cui l'LLM ha
    scritto un nome proprio invece di usare il segnaposto, ed e' esattamente cio'
    che tiene in piedi il principio 'LLM autore, codice etichettatore'."""
    if not text:
        return None
    text = re.sub(r"^```.*?\n|```$", "", text.strip(), flags=re.MULTILINE).strip()
    slots = set(gen.SLOT_RE.findall(text))
    if not slots:
        return None
    unknown = slots - ALLOWED_SLOTS
    if unknown:
        print(f"  scartato: segnaposto non consentiti {sorted(unknown)}")
        return None
    stray = find_stray_names(text)
    if stray:
        print(f"  scartato: probabili nomi inline non taggati {sorted(set(stray))[:8]}")
        return None
    # L'invariante va verificata QUI, non solo sulle righe generate: se il modello
    # scrive un indirizzo letterale invece del segnaposto, a valle ogni riga nata da
    # quel template verrebbe scartata in silenzio e non si capirebbe perche'.
    outside = in_documentation_space(text)
    if outside:
        print(f"  scartato: valori letterali fuori dagli spazi documentali "
              f"{sorted(set(outside))[:5]}")
        return None
    if looks_truncated(text):
        print("  scartato: sembra troncato a meta' (limite di token del modello)")
        return None
    # ultimo e piu' severo: non si giudica il testo, si guarda cosa PRODUCE
    err = smoke_template(text)
    if err:
        print(f"  scartato: non produce righe valide — {err}")
        return None
    return text


def load_bank(path=BANK_PATH):
    """Template Gemini accumulati nelle esecuzioni precedenti.

    Scarta quelli che oggi non passerebbero i controlli: la banca e' su disco e
    sopravvive alle correzioni del codice, quindi cio' che era accettabile ieri va
    riverificato, non dato per buono."""
    path = Path(path)
    if not path.is_file():
        return []
    try:
        items = json.loads(path.read_text("utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"ATTENZIONE: banca template illeggibile ({path}): {exc}")
        return []
    out = [t for t in items if isinstance(t, str) and clean_and_validate(t)]
    if len(out) != len(items):
        print(f"  {len(items) - len(out)} template della banca non passano piu' i "
              f"controlli e sono stati ignorati")
    return out


def save_bank(templates, path=BANK_PATH):
    """Aggiunge i template nuovi alla banca, senza duplicati. Scrittura atomica."""
    path = Path(path)
    existing = []
    if path.is_file():
        try:
            existing = [t for t in json.loads(path.read_text("utf-8")) if isinstance(t, str)]
        except (json.JSONDecodeError, OSError):
            existing = []
    merged = list(existing)
    added = 0
    for t in templates:
        if t in merged or is_near_duplicate(t, merged):
            continue
        merged.append(t)
        added += 1
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(merged, ensure_ascii=False, indent=2), "utf-8")
    tmp.replace(path)
    return added, len(merged)


# --------------------------------------------------------------------------- #
# Provider: qualunque endpoint OpenAI-compatible                                #
# --------------------------------------------------------------------------- #
# Un solo formato copre il modello locale (ollama espone /v1/chat/completions) e
# ogni servizio cloud che parla la stessa API. La scelta del provider diventa
# configurazione, non codice.
#
# I controlli restano il cancello: clean_and_validate rifiuta i segnaposto
# sconosciuti, i nomi inline e i valori letterali fuori dagli spazi documentali.
# Un modello piu' debole quindi non produce dati sbagliati, produce solo un tasso
# di accettazione piu' basso — la qualita' del provider e' una questione di resa,
# non di correttezza.
DEFAULT_LLM_BASE_URL = "http://127.0.0.1:11434/v1"     # ollama in locale

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def openai_compat_call(prompt, base_url, model, api_key=None, timeout=300,
                       temperature=1.0, max_tokens=3000):
    """Una chiamata a un endpoint OpenAI-compatible. None se fallisce.

    Toglie gli eventuali blocchi <think>: i modelli locali con ragionamento esplicito
    (Qwen3 e simili) li antepongono alla risposta, e finirebbero nel template."""
    import urllib.error
    import urllib.request

    url = base_url.rstrip("/") + "/chat/completions"
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        with urllib.request.urlopen(
                urllib.request.Request(url, data=payload, headers=headers),
                timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        print(f"  errore dal provider: {exc}")
        return None
    try:
        choice = data["choices"][0]
        text = choice["message"]["content"]
    except (KeyError, IndexError, TypeError):
        print(f"  risposta inattesa dal provider: {str(data)[:160]}")
        return None
    # finish_reason e' la VERITA' sul troncamento: 'length' significa che il modello
    # e' stato tagliato dal limite di token. Indovinarlo dal testo — come facevo —
    # boccia le frasi complete a cui manca solo il punto finale, che nelle voci di
    # elenco e nelle timeline sono la norma.
    if choice.get("finish_reason") == "length":
        print("  risposta troncata dal limite di token (finish_reason=length)")
        return None
    return _THINK_RE.sub("", text or "").strip() or None


def make_caller(provider, base_url=None, model=None):
    """Ritorna la funzione prompt -> testo|None per il provider scelto.

    Astrae l'UNICA cosa che cambia fra i provider — come si ottiene del testo da un
    prompt — lasciando identici il resto del giro: prompt, validazione, banca."""
    import os
    if provider == "gemini":
        if not os.environ.get("GEMINI_API_KEY"):
            print("GEMINI_API_KEY non impostata.")
            return None
        return lambda p: tb.call_gemini(p, retries=1)

    base_url = base_url or os.environ.get("PII_LLM_BASE_URL") or DEFAULT_LLM_BASE_URL
    model = model or os.environ.get("PII_LLM_MODEL")
    if not model:
        print("Nessun modello indicato: usa --llm-model o PII_LLM_MODEL.")
        return None
    key = os.environ.get("PII_LLM_KEY")
    print(f"Provider OpenAI-compatible: {base_url} [{model}]"
          + ("" if key else "  (senza chiave: endpoint locale)"))
    return lambda p: openai_compat_call(p, base_url, model, key)


def llm_templates(per_type, call, label="modello", bank_path=BANK_PATH):
    """Fa scrivere nuovi template di genere sicurezza. [] se il provider non risponde.

    Ogni template accettato finisce SUBITO nella banca, non a fine giro: le chiamate
    costano tempo e credito, e un'interruzione (timeout, Ctrl-C, rete) non deve
    buttare via cio' che era gia' stato pagato. Con bank_path=None non si salva —
    serve ai test, che non devono scrivere nella banca vera."""
    if call is None:
        return []
    slot_list = "\n".join(f"  {{{s}}}" for s in sorted(ALLOWED_SLOTS))
    out, total, done, refused, no_answer, streak = [], len(DOC_TYPES) * per_type, 0, 0, 0, 0
    print(f"Scrivo {total} template con {label} ...")
    for doc_type in DOC_TYPES:
        for _ in range(per_type):
            if streak >= MAX_CONSECUTIVE_FAILURES:
                break
            done += 1
            # "nessuna risposta" e "template rifiutato" sono due esiti diversi e vanno
            # detti diversamente: confonderli fa sembrare un problema di quota un
            # problema di qualita' dei template, e si va a cercare nel posto sbagliato.
            raw = call(PROMPT.format(doc_type=doc_type, slot_list=slot_list,
                                     slot_hints=SLOT_HINTS))
            if raw is None:
                no_answer += 1
                streak += 1
                esito = "nessuna risposta dal modello"
            else:
                streak = 0
                text = clean_and_validate(raw)
                if text:
                    out.append(text)
                    esito = "OK"
                    if bank_path is not None:
                        save_bank([text], bank_path)      # subito, non a fine giro
                else:
                    refused += 1
                    esito = "scartato"
            print(f"  [{done:>3}/{total}] {doc_type:52s} {esito}")
        if streak >= MAX_CONSECUTIVE_FAILURES:
            break

    if streak >= MAX_CONSECUTIVE_FAILURES:
        # senza questo si bruciava l'intera quota a ritentare, e ogni tentativo la
        # riduce ancora: il 429 non e' un errore transitorio da cui si esce insistendo
        print(f"\nInterrotto dopo {streak} chiamate fallite di fila: il modello non "
              f"risponde (quota, chiave, modello o rete). Non insisto: se e' quota, "
              f"ogni tentativo consuma quello che resta.")
    print(f"Template nuovi validi: {len(out)}/{done} tentati "
          f"({refused} rifiutati dai controlli, {no_answer} senza risposta)")
    return out


# --------------------------------------------------------------------------- #
# Validazione delle righe prodotte                                             #
# --------------------------------------------------------------------------- #
_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9][A-Za-z0-9\-]*\.)+([A-Za-z]{2,})\b")

# Domini dei generatori UPSTREAM (email_piece / PEC): non sono RFC 2606 ma sono la
# scelta del progetto, e questo modulo non li produce ne' li cambia.
UPSTREAM_DOC_DOMAINS = ("example.it", "pec.it")


def _is_doc_domain(value):
    value = value.lower().rstrip(".")
    if value.rsplit(".", 1)[-1] in DOC_TLDS:              # *.example / *.test / *.invalid
        return True
    return any(value == d or value.endswith("." + d)
               for d in DOC_SLD + UPSTREAM_DOC_DOMAINS)


def in_documentation_space(text):
    """Elenco delle violazioni dell'invariante: valori fuori dagli spazi riservati.

    Vale su TUTTO il testo, non solo sulle entita': un indirizzo instradabile non
    diventa accettabile perche' non e' etichettato.

    Per i domini si guardano SOLO i token il cui ultimo pezzo e' un TLD vero, presi
    dalla stessa lista che usano i detector. Senza quel filtro la regex di forma
    scambia per domini gli username ('m.rossi'), i nomi di file ('index.html') e le
    estensioni negli URL — e un controllo che grida sempre viene disattivato."""
    bad = []
    for m in _IP_RE.finditer(text):
        try:
            addr = ipaddress.ip_address(m.group())
        except ValueError:
            continue
        if not any(addr in net for net in _ALL_DOC_NETS):
            bad.append(m.group())
    for m in _DOMAIN_RE.finditer(text):
        if m.group(1).lower() in _REAL_TLDS and not _is_doc_domain(m.group()):
            bad.append(m.group())
    return bad


# --------------------------------------------------------------------------- #
# Deduplicazione — le stesse regole del dataset 'clean' del progetto            #
# --------------------------------------------------------------------------- #
# La pipeline di pulizia del progetto non sta nel repo: e' documentata nella card
# di rizzoaiacademy/anonimizzazione-testi-italiano-clean. I primi due passaggi sono
# quelli che contano per dati generati da template:
#
#   1. deduplicazione esatta di source_text
#   2. cap a N righe per SCHELETRO (il testo con i valori delle entita' rimessi al
#      loro tag) — non per template: un template con casualita' interna produce
#      scheletri diversi, ed e' varieta' vera.
#
# Qui lo scheletro normalizza anche cifre e sequenze esadecimali, perche' nella
# modalita' predefinita i valori cyber NON sono entita': senza, un IP diverso a ogni
# riga farebbe sembrare unica una struttura che e' identica.
DEFAULT_CAP_PER_SKELETON = 20

_HEXRUN_RE = re.compile(r"[0-9a-f]{8,}", re.IGNORECASE)
_DIGITS_RE = re.compile(r"\d+")


def _cyber_spans(text):
    """Span dei valori cyber secondo i detector del progetto."""
    out = []
    for label, rx, validator, _strict in detectors_cyber.DETECTORS:
        for m in rx.finditer(text):
            if validator is None or validator(m.group()):
                out.append((m.start(), m.end(), label))
    return out


def skeleton(rec):
    """Struttura di una riga, indipendente dai valori iniettati.

    Maschera le entita' etichettate E i valori cyber riconosciuti dai detector, cosi'
    la stessa struttura da' lo stesso scheletro nelle due modalita' di etichettatura.

    Perche' servono i detector e non basta normalizzare cifre ed esadecimali: domini,
    percorsi e utenze sono fatti di PAROLE. Misurato sul dataset da 11.163 righe,
    senza questo passaggio gli scheletri risultavano 10.376 invece di 7.188 e lo
    scheletro piu' frequente compariva 131 volte invece delle 20 del cap — cioe' il
    cap non mordeva, perche' due righe identiche nella struttura sembravano diverse
    solo per il dominio che contenevano."""
    text = rec["source_text"]
    spans = [(e["start"], e["end"], e["label"]) for e in rec["entities"]]
    spans += _cyber_spans(text)
    spans.sort()

    out, pos = [], 0
    for start, end, label in spans:
        if start < pos:                       # sovrapposto a uno span gia' preso
            continue
        out.append(text[pos:start])
        out.append("{" + label + "}")
        pos = end
    out.append(text[pos:])
    s = _HEXRUN_RE.sub("§", "".join(out))
    return _DIGITS_RE.sub("#", s)


def dedupe(rows, cap=DEFAULT_CAP_PER_SKELETON):
    """Applica deduplicazione esatta e cap per scheletro. Ritorna (righe, statistiche)."""
    seen_text, per_skeleton, out = set(), collections.Counter(), []
    n_dup = n_cap = 0
    for rec in rows:
        if rec["source_text"] in seen_text:
            n_dup += 1
            continue
        seen_text.add(rec["source_text"])
        if cap:
            key = skeleton(rec)
            if per_skeleton[key] >= cap:
                n_cap += 1
                continue
            per_skeleton[key] += 1
        out.append(rec)
    return out, {"duplicati_esatti": n_dup, "oltre_il_cap": n_cap,
                 "scheletri": len(per_skeleton)}


def validate_record(rec):
    """Controlli strutturali + invariante degli spazi documentali. None = valido."""
    if len(rec["tokens"]) != len(rec["bio_labels"]):
        return "tokens/bio_labels di lunghezza diversa"
    for e in rec["entities"]:
        if rec["source_text"][e["start"]:e["end"]] != e["value"]:
            return f"offset entita' incoerente: {e}"
    bad = in_documentation_space(rec["source_text"])
    if bad:
        return f"valori fuori dagli spazi documentali: {sorted(set(bad))[:5]}"
    return None


# --------------------------------------------------------------------------- #
# Generazione                                                                  #
# --------------------------------------------------------------------------- #
def build(n, templates, handle="local", seed=None):
    """Genera n righe nel formato del progetto. Ritorna (righe, conteggi, scartate)."""
    if seed is not None:
        random.seed(seed)
    register()
    rows, counts, bad = [], {}, 0
    for _ in range(n):
        tid = random.randrange(len(templates))
        text, entities = gen.build_example(tid, templates)
        tokens, bio = gen.to_bio(text, entities)
        rec = {
            "source_text": text,
            "language": "it",
            "template_id": tid,
            "entities": entities,
            "tokens": tokens,
            "bio_labels": bio,
            "meta": {"contributor": handle, "seed": seed, "synthetic": True,
                     "generator_version": GENERATOR_VERSION,
                     "genre": "security", "cyber_labeled": _label_cyber},
        }
        err = validate_record(rec)
        if err:
            bad += 1
            continue
        for e in entities:
            counts[e["label"]] = counts.get(e["label"], 0) + 1
        rows.append(rec)
    return rows, counts, bad


def main():
    import argparse
    ap = argparse.ArgumentParser(
        description="Genera documenti di sicurezza sintetici nel formato del progetto.")
    ap.add_argument("-n", type=int, default=5000, help="numero di righe (default 5000)")
    ap.add_argument("--out", default=None, help="file .jsonl di destinazione")
    ap.add_argument("--seed", type=int, default=42, help="seed RNG (default 42)")
    ap.add_argument("--label-cyber", action="store_true",
                    help="etichetta anche i valori cyber (CAMBIA num_labels: impone "
                         "il riaddestramento completo, checkpoint attuale incompatibile)")
    ap.add_argument("--gemini", action="store_true",
                    help="scorciatoia per --provider gemini")
    ap.add_argument("--provider", choices=("gemini", "openai"), default=None,
                    help="da chi far scrivere i template nuovi. 'gemini' usa "
                         "GEMINI_API_KEY; 'openai' un qualunque endpoint "
                         "OpenAI-compatible (ollama in locale, Groq, Cerebras, "
                         "OpenRouter, Together, Mistral, GitHub Models...)")
    ap.add_argument("--llm-base-url", default=None,
                    help=f"URL base OpenAI-compatible (default {DEFAULT_LLM_BASE_URL}, "
                         f"anche via PII_LLM_BASE_URL)")
    ap.add_argument("--llm-model", default=None,
                    help="nome del modello per --provider openai (anche PII_LLM_MODEL)")
    ap.add_argument("--per-type", type=int, default=2,
                    help="quanti template per tipo di documento chiedere al modello")
    ap.add_argument("--templates-only", action="store_true",
                    help="raccogli solo template nella banca, NON rigenerare il dataset "
                         "(altrimenti ogni giro di raccolta lo sovrascrive)")
    ap.add_argument("--cap-per-skeleton", type=int, default=DEFAULT_CAP_PER_SKELETON,
                    help=f"massimo di righe per scheletro, come il dataset 'clean' del "
                         f"progetto (default {DEFAULT_CAP_PER_SKELETON}; 0 = nessun cap)")
    args = ap.parse_args()

    set_label_cyber(args.label_cyber)
    templates = list(TEMPLATES)

    # La banca su disco e' cio' che rende utile una quota giornaliera piccola: senza,
    # i template pagati oggi si buttano a fine esecuzione e domani si riparte da zero.
    banked = load_bank()
    if banked:
        print(f"Banca template: {len(banked)} da esecuzioni precedenti")
        templates += banked

    provider = args.provider or ("gemini" if args.gemini else None)
    if provider:
        label = f"Gemini [{tb.MODEL}]" if provider == "gemini" else "il provider configurato"
        caller = make_caller(provider, args.llm_base_url, args.llm_model)
        new = [t for t in llm_templates(args.per_type, caller, label)
               if t not in templates]
        if new:
            # llm_templates ha gia' salvato ognuno appena accettato: qui si riporta
            # solo il totale, senza riscrivere.
            print(f"Banca: +{len(new)} template nuovi (totale {len(load_bank())}) "
                  f"-> {BANK_PATH}")
            templates += new
        else:
            # senza questo, quota esaurita o chiave assente producevano in silenzio un
            # dataset con la sola varieta' gia' disponibile
            print("\nATTENZIONE: nessun template NUOVO dal provider "
                  "(quota, chiave, modello o rete).\n"
                  f"  Si prosegue con i {len(templates)} template gia' disponibili.\n")

    suffix = "cyberlabeled" if args.label_cyber else "plain"
    out_path = Path(args.out) if args.out else OUT_DIR / f"synthetic_security_it_{suffix}.jsonl"

    print("=" * 70)
    print("Documenti di sicurezza sintetici — nessun valore reale, mai")
    print(f"modalita': {'tag cyber ETICHETTATI (riaddestramento)' if args.label_cyber else 'tag invariati'}"
          f" | template: {len(templates)} | n={args.n} | seed={args.seed}")
    print("=" * 70)

    if args.templates_only:
        print(f"\n(--templates-only) Banca a {len(load_bank())} template. "
              f"Dataset NON rigenerato.")
        return

    rows, counts, bad = build(args.n, templates, seed=args.seed)
    if bad:
        print(f"ATTENZIONE: {bad} righe scartate dal self-check")

    rows, stat = dedupe(rows, args.cap_per_skeleton)
    if args.cap_per_skeleton:
        print(f"Deduplicazione (regole del dataset 'clean'): "
              f"{stat['duplicati_esatti']} duplicati esatti, "
              f"{stat['oltre_il_cap']} oltre il cap di {args.cap_per_skeleton} per "
              f"scheletro, {stat['scheletri']} scheletri distinti")
    counts = collections.Counter(e["label"] for r in rows for e in r["entities"])

    print(f"Righe valide: {len(rows)}. Entita' per label:")
    for label, c in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {label:16s} {c}")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    tmp.replace(out_path)
    print(f"\nScritto -> {out_path}")


if __name__ == "__main__":
    main()
