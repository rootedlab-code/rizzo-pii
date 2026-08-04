# -*- coding: utf-8 -*-
"""
Scope: di CHI e' un valore rilevato.

Il tagger dice QUALE tipo e' un valore (IP, DOMAIN, HASH); la policy dice COSA
farne. Fra i due manca la domanda che in un documento di sicurezza decide tutto:
l'indirizzo appena trovato e' del cliente o dell'attaccante? Hanno la stessa
forma e trattamento opposto — mascherare l'infrastruttura dell'attaccante rende
il report illeggibile, lasciare in chiaro quella del cliente e' la fuga di dati
che il tool dovrebbe impedire. Un asse per tag non puo' distinguerli: "IP" e' un
solo tag.

Quattro ruoli:

    own        infrastruttura del cliente / della parte lesa / propria
    adversary  infrastruttura dell'avversario
    public     riferimenti pubblici (vendor, documentazione)
    unknown    non determinato — fallback, e la policy lo maschera

Risoluzione, in quest'ordine:

    1. LISTE ESPLICITE     deterministiche, hanno sempre la precedenza
    2. CONTESTO            indizi testuali attorno al valore — SPENTO per default
    3. unknown             tutto cio' che resta

Il principio che governa ogni caso dubbio e' **fail-closed**: nell'incertezza si
risponde `unknown`, che a valle significa "maschera". In un tool di privacy un
falso negativo e' un dato sensibile in chiaro, un falso positivo e' una parola
illeggibile: non sono errori simmetrici. Per questo indizi di ruoli diversi nella
stessa finestra non "vincono ai punti" — annullano la decisione.

La stessa asimmetria e' il motivo per cui **il contesto e' opt-in**. Un `own`
sbagliato dedotto dal testo produce mascheramento in piu', innocuo; un
`adversary` sbagliato produce un dato sensibile in chiaro. Un'euristica non deve
poter sbloccare il "lascia in chiaro" da sola: chi la vuole dichiara quali ruoli
puo' assegnare, con `context.roles`. Dimenticarsene maschera di piu', mai di
meno. (Il caso che ha imposto la regola: la sola parola "payload" a 53 caratteri
di distanza bastava a marcare `adversary` un indirizzo del cliente non elencato.)

Il file di scope contiene gli indirizzi del cliente e gli indicatori
dell'avversario: e' il file piu' sensibile del sistema. Sta FUORI dalla repo, uno
per ingaggio, indicato da PII_SCOPE_FILE o da --scope-file. Non ha un percorso di
default: senza configurazione non c'e' scope, tutto e' `unknown` e quindi
mascherato — il comportamento storico, invariato.

    {
      "own":       {"IP": ["10.0.0.0/8", "203.0.113.5"], "DOMAIN": ["cliente.example"]},
      "adversary": {"IP": ["198.51.100.7"], "DOMAIN": ["evil.example"]},
      "public":    {"DOMAIN": ["vendor.example"]},
      "context":   {"roles": ["adversary"], "window": 60, "cues": {"adversary": ["c2"]}}
    }

Senza `context.roles` il blocco `context` non accende nulla: decidono solo le
liste. `cues` e' facoltativo — omesso, si usano gli indizi predefiniti.

I valori dello scope non escono MAI dal modulo: `counts()` espone quanti sono per
ruolo e per tag, mai quali. L'unica eccezione e' il messaggio di ScopeError su un
valore contraddittorio, che va mostrato a chi sta correggendo il proprio file.

Modulo puro (nessun import di torch/flask): testabile senza modello.
"""

import ipaddress
import json
import os
import re
import sys
from collections import namedtuple
from pathlib import Path

import detectors_cyber
import server_config

# Ruoli assegnabili da file.
ROLE_OWN = "own"
ROLE_ADVERSARY = "adversary"
ROLE_PUBLIC = "public"
ROLES = (ROLE_OWN, ROLE_ADVERSARY, ROLE_PUBLIC)

# Fallback: non assegnabile da file, e' cio' che resta quando nulla ha deciso.
ROLE_UNKNOWN = "unknown"

# Da dove viene la decisione (finisce nell'output, serve a capire perche').
SOURCE_LIST = "list"
SOURCE_CONTEXT = "context"
SOURCE_DEFAULT = "default"

ENV_SCOPE_FILE = "PII_SCOPE_FILE"

DEFAULT_WINDOW = 60          # caratteri a sinistra e a destra del valore

# Indizi testuali predefiniti. Volutamente pochi e inequivocabili: un indizio
# sbagliato su `adversary` lascia un dato in chiaro. `public` non ha indizi di
# default — si assegna solo per elenco esplicito.
DEFAULT_CUES = {
    ROLE_ADVERSARY: ("c2", "c&c", "command and control", "attaccante", "attacker",
                     "malevolo", "malevola", "malicious", "malware", "threat actor",
                     "ioc", "indicator of compromise", "phishing", "esfiltrazione",
                     "exfiltration", "beacon", "payload"),
    ROLE_OWN: ("cliente", "client", "nostro", "nostra", "interno", "interna",
               "vittima", "victim", "assistito", "in perimetro", "in scope"),
}

# Come confrontare un valore con le liste, per famiglia di tag. Tutto cio' che non
# e' elencato qui usa il confronto esatto normalizzato.
# I tag che un file di scope puo' portare. Non e' la tassonomia completa: sono i
# valori di cui ha senso dichiarare il proprietario in un ingaggio. Un tag fuori da
# qui non fara' mai match — le sue voci starebbero nel file senza proteggere nulla —
# quindi viene segnalato al caricamento invece di essere accettato in silenzio.
KNOWN_SCOPE_LABELS = frozenset({
    "IP", "DOMAIN", "URL", "EMAIL", "HASH", "WALLET", "MAC", "ASN",
    "CLOUDID", "USER", "PATH", "FULLNAME", "ORG", "TELEPHONENUM",
})

_IP_LABELS = frozenset({"IP"})
_HOST_LABELS = frozenset({"DOMAIN"})
_URL_LABELS = frozenset({"URL"})

ScopeMatch = namedtuple("ScopeMatch", "role source")

_UNRESOLVED = ScopeMatch(ROLE_UNKNOWN, SOURCE_DEFAULT)


class ScopeError(Exception):
    """File di scope illeggibile, malformato o contraddittorio.

    E' un'eccezione e non un avviso perche' un file di scope che non fa quello che
    l'utente crede e' peggio di nessun file di scope: si lavorerebbe su un intero
    ingaggio convinti di una protezione che non c'e'."""


def _warn(message):
    print(f"[scope] {message}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# Normalizzazione e confronto
# --------------------------------------------------------------------------- #
def _norm(value):
    """Forma canonica per il confronto: defangata, senza spazi ai bordi, minuscola."""
    return detectors_cyber.refang(str(value)).strip().casefold()


def _host_of(value):
    """Host di una URL, o None. Accetta anche gli schemi defangati (hxxps://)."""
    m = re.match(r"[A-Za-z][A-Za-z0-9+.\-]*://([^/\s?#]+)", _norm(value))
    if not m:
        return None
    host = m.group(1).rsplit("@", 1)[-1]          # via le credenziali in-URL
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host   # via la porta


def _domain_matches(value, entry):
    """Un dominio corrisponde a una voce se e' quella voce o un suo sottodominio.

    Il confronto e' per etichette e non per suffisso di stringa: `evilcliente.example`
    NON e' un sottodominio di `cliente.example`, e trattarlo come tale assegnerebbe a
    un dominio dell'attaccante il ruolo del cliente."""
    value, entry = value.rstrip("."), entry.rstrip(".")
    return value == entry or value.endswith("." + entry)


def _as_network(entry):
    """Voce di lista IP come rete (un singolo indirizzo e' una /32 o /128). None se
    non e' un indirizzo valido."""
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None


def _ip_matches(value, entry):
    """Un IP corrisponde se e' contenuto nella rete della voce. Anche il valore puo'
    essere una rete (i detector riconoscono il CIDR): allora deve esserne sottorete."""
    net = _as_network(entry)
    if net is None:
        return False
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        sub = _as_network(value)
        if sub is None or sub.version != net.version:
            return False
        return sub.subnet_of(net)
    return addr.version == net.version and addr in net


def _matches(label, value, entry):
    """Confronto valore/voce secondo la famiglia del tag."""
    if label in _IP_LABELS:
        return _ip_matches(value, entry)
    if label in _HOST_LABELS:
        return _domain_matches(value, entry)
    if label in _URL_LABELS:
        return value == entry
    return value == entry


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #
class Scope:
    """Assegna un ruolo a un valore rilevato.

    lists:         {ruolo: {tag: [voci]}} — le voci sono normalizzate qui dentro.
    window:        ampiezza in caratteri della finestra di contesto per lato.
    cues:          {ruolo: [indizi testuali]}; None = DEFAULT_CUES.
    context_roles: ruoli che il contesto PUO' assegnare. Vuoto (default) = contesto
                   spento, decidono solo le liste.
    """

    def __init__(self, lists=None, window=DEFAULT_WINDOW, cues=None, context_roles=()):
        self.lists = {role: {} for role in ROLES}
        for role, by_label in (lists or {}).items():
            for label, entries in (by_label or {}).items():
                self.lists[role][str(label).upper()] = tuple(_norm(e) for e in entries)
        self.window = int(window)
        self.context_roles = tuple(r for r in ROLES if r in tuple(context_roles))
        self.cues = {r: tuple(c) for r, c in (DEFAULT_CUES if cues is None else cues).items()
                     if r in ROLES and c}
        self._cue_res = {role: re.compile("|".join(re.escape(c) for c in items),
                                          re.IGNORECASE)
                         for role, items in self.cues.items()}
        self._check_contradictions()

    # -- caricamento ------------------------------------------------------- #
    def _check_contradictions(self):
        """Uno stesso valore in due ruoli e' un errore, non una precedenza da inventare.

        E' esattamente il caso in cui indovinare produce la fuga: se scegliessimo
        `adversary` su un valore che l'utente ha anche messo in `own`, lo lasceremmo
        in chiaro."""
        seen = {}
        for role in ROLES:
            for label, entries in self.lists[role].items():
                for entry in entries:
                    key = (label, entry)
                    other = seen.get(key)
                    if other and other != role:
                        raise ScopeError(
                            f"il valore {entry!r} e' elencato come {label} sia in "
                            f"'{other}' sia in '{role}': correggi il file di scope, "
                            f"non posso decidere io quale dei due vale")
                    seen[key] = role

    # -- interrogazione ---------------------------------------------------- #
    def _from_lists(self, label, value):
        """Ruolo da elenco esplicito, o None. Per una URL si guarda anche l'elenco dei
        domini: chi elenca `evil.example` una volta non deve rielencarne ogni URL."""
        norm = _norm(value)
        host = _host_of(value) if label in _URL_LABELS else None
        for role in ROLES:
            by_label = self.lists[role]
            if any(_matches(label, norm, e) for e in by_label.get(label, ())):
                return role
            if host and any(_domain_matches(host, e) for e in by_label.get("DOMAIN", ())):
                return role
        return None

    def _from_context(self, text, start, end):
        """Ruolo dagli indizi attorno al valore, o None.

        Indizi di piu' ruoli nella stessa finestra -> None: la frase parla di entrambe
        le parti e il contesto non e' in grado di decidere. Meglio `unknown`, cioe'
        mascherato, che una scelta a maggioranza su un dato sensibile.

        L'ambiguita' si valuta su TUTTI gli indizi, anche quelli di ruoli che il
        contesto non ha il permesso di assegnare: una frase che nomina sia il cliente
        sia l'attaccante resta ambigua a prescindere da cosa e' abilitato, e filtrare
        prima farebbe sparire proprio il segnale che deve bloccare la decisione."""
        if not self.context_roles or not text or start is None or end is None:
            return None
        window = text[max(0, start - self.window):end + self.window]
        hits = [role for role, rx in self._cue_res.items() if rx.search(window)]
        if len(hits) != 1:
            return None
        return hits[0] if hits[0] in self.context_roles else None

    def role_of(self, label, value, text=None, start=None, end=None):
        """ScopeMatch(role, source) per un'entita' rilevata.

        text/start/end sono opzionali: senza di essi il contesto non viene consultato
        e restano solo le liste."""
        label = str(label).upper()
        role = self._from_lists(label, value)
        if role:
            return ScopeMatch(role, SOURCE_LIST)
        role = self._from_context(text, start, end)
        if role:
            return ScopeMatch(role, SOURCE_CONTEXT)
        return _UNRESOLVED

    # -- rilevamento da dichiarazione -------------------------------------- #
    def declared_entities(self, text):
        """Entita' dai valori DICHIARATI nel file di scope, cercati come sottostringhe.

        Chi scrive un valore qui dentro sta dicendo «questo e' del mio cliente» o
        «questo e' dell'avversario». E' una dichiarazione, non un'ipotesi da far
        confermare a una regex: senza questo metodo lo scope assegna ruoli soltanto
        a cio' che i detector hanno gia' trovato, e un valore dichiarato ma non
        rilevato esce in chiaro proprio mentre il file dice di proteggerlo.

        Misurato su un audit reale: il dominio del committente era elencato come
        `own` ed e' uscito in chiaro **7 volte**, perche' il suo TLD non e' fra i
        119 della lista del detector `DOMAIN`. La lista dei TLD non potra' mai essere completa — i
        gTLD sono oltre millecinquecento — ma la dichiarazione dell'analista si'.

        Per i domini valgono anche i sottodomini: chi dichiara `example.com` non deve
        rielencare `mx.example.com`."""
        fuori = []
        for role in ROLES:
            for label, entries in self.lists[role].items():
                sotto = r"(?:[A-Za-z0-9_-]+\.)*" if label in _HOST_LABELS else ""
                for entry in entries:
                    rx = re.compile(rf"(?<![\w.\-]){sotto}{re.escape(entry)}(?![\w\-])",
                                    re.IGNORECASE)
                    for m in rx.finditer(text):
                        fuori.append({"label": label, "start": m.start(), "end": m.end(),
                                      "score": 1.0, "validated": True, "source": "scope"})
        return fuori

    # -- introspezione (mai i valori) -------------------------------------- #
    def is_empty(self):
        return not any(self.lists[role] for role in ROLES)

    def counts(self):
        """Quante voci per ruolo e per tag. Deliberatamente NON i valori: e' cio' che
        puo' essere mostrato nell'interfaccia o restituito da un endpoint."""
        return {role: {label: len(entries)
                       for label, entries in sorted(self.lists[role].items())}
                for role in ROLES if self.lists[role]}

    def as_dict(self):
        return {"counts": self.counts(), "window": self.window,
                "context_roles": list(self.context_roles),
                "cues": {role: len(items) for role, items in sorted(self.cues.items())}}

    def __repr__(self):
        n = sum(len(e) for role in ROLES for e in self.lists[role].values())
        return f"Scope({n} voci, window={self.window})"


# --------------------------------------------------------------------------- #
# Caricamento da file
# --------------------------------------------------------------------------- #
def scope_path(cli_path=None):
    """Percorso del file di scope: CLI > env > puntatore. None = nessuno configurato.

    Non c'e' un percorso di default: il file appartiene all'ingaggio, non
    all'installazione, e trovarne uno per caso sarebbe il modo peggiore di scoprire che
    esiste. Il **puntatore** (`engagement.json`) non e' un default: e' una scelta che
    l'utente ha fatto e che sopravvive al riavvio, senza la quale l'app desktop non
    avrebbe modo di ricordare l'ingaggio su cui sta lavorando.

    Contiene un percorso, mai dei valori, e il lato Python lo legge soltanto: lo scrive
    il dialogo nativo del sistema operativo. Un `POST /scope` renderebbe l'endpoint un
    oracolo di lettura del filesystem, e i messaggi di ScopeError citano un valore preso
    dal file."""
    raw = cli_path or os.environ.get(ENV_SCOPE_FILE) or server_config.saved_scope_file()
    return Path(raw).expanduser() if raw else None


def _parse_lists(data, warn):
    lists = {}
    for role in ROLES:
        by_label = data.get(role)
        if by_label is None:
            continue
        if not isinstance(by_label, dict):
            raise ScopeError(f"'{role}' deve essere un oggetto {{tag: [valori]}}, "
                             f"trovato {type(by_label).__name__}")
        clean = {}
        for label, entries in by_label.items():
            if isinstance(entries, str) or not isinstance(entries, (list, tuple)):
                raise ScopeError(f"'{role}.{label}' deve essere una lista di stringhe")
            if str(label).upper() not in KNOWN_SCOPE_LABELS:
                # Un tag che nessuna entita' porta non fa MAI match: le sue voci
                # esistono nel file e non proteggono niente. E' successo davvero, con
                # `domains` al posto di `domain`, su un audit reale.
                warn(f"'{role}.{label}': tag sconosciuto, quelle voci non "
                     f"proteggeranno nulla. Attesi: "
                     f"{', '.join(sorted(KNOWN_SCOPE_LABELS))}")
            values = [str(e).strip() for e in entries if str(e).strip()]
            if values:
                clean[label] = values
        lists[role] = clean

    unknown = [k for k in data if k not in ROLES and k != "context"]
    if unknown:
        warn(f"chiavi ignorate nel file di scope: {', '.join(sorted(unknown))} "
             f"(attese: {', '.join(ROLES)}, context)")
    return lists


def _parse_context(data, warn):
    ctx = data.get("context") or {}
    if not isinstance(ctx, dict):
        raise ScopeError("'context' deve essere un oggetto")

    window = ctx.get("window", DEFAULT_WINDOW)
    try:
        window = int(window)
    except (TypeError, ValueError):
        raise ScopeError(f"'context.window' deve essere un intero, trovato {window!r}")
    if window < 0:
        raise ScopeError("'context.window' non puo' essere negativo")

    raw_roles = ctx.get("roles", ())
    if isinstance(raw_roles, str) or not isinstance(raw_roles, (list, tuple)):
        raise ScopeError("'context.roles' deve essere una lista di ruoli")
    context_roles = [str(r).strip().lower() for r in raw_roles if str(r).strip()]
    unknown = [r for r in context_roles if r not in ROLES]
    if unknown:
        warn(f"ruoli sconosciuti in context.roles, ignorati: {', '.join(sorted(unknown))} "
             f"(attesi: {', '.join(ROLES)})")
        context_roles = [r for r in context_roles if r in ROLES]

    raw_cues = ctx.get("cues")
    if raw_cues is not None and (not isinstance(raw_cues, dict)):
        raise ScopeError("'context.cues' deve essere un oggetto {ruolo: [indizi]}")
    if raw_cues is not None and context_roles == []:
        warn("'context.cues' e' presente ma 'context.roles' e' vuoto: il contesto "
             "resta spento e gli indizi non verranno usati")
    cues = None
    if raw_cues is not None:
        cues = {}
        for role, items in raw_cues.items():
            if role not in ROLES:
                warn(f"indizi ignorati per il ruolo sconosciuto '{role}'")
                continue
            if isinstance(items, str) or not isinstance(items, (list, tuple)):
                raise ScopeError(f"'context.cues.{role}' deve essere una lista di stringhe")
            cues[role] = [str(i).strip().casefold() for i in items if str(i).strip()]
    return window, cues, context_roles


def load_scope(cli_path=None, warn=_warn):
    """Costruisce lo Scope dal file indicato da CLI o da PII_SCOPE_FILE.

    Nessun percorso configurato -> Scope vuoto: ogni valore e' `unknown`, che la
    policy maschera. E' il comportamento storico, quindi il default non cambia.

    Un percorso configurato ma illeggibile, malformato o contraddittorio solleva
    ScopeError: proseguire in silenzio significherebbe lavorare su un ingaggio
    intero credendo attiva una configurazione che non lo e'."""
    path = scope_path(cli_path)
    if path is None:
        return Scope()
    if not path.is_file():
        raise ScopeError(f"file di scope inesistente: {path}")
    try:
        data = json.loads(path.read_text("utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ScopeError(f"file di scope illeggibile ({path}): {exc}") from exc
    if not isinstance(data, dict):
        raise ScopeError(f"il file di scope deve contenere un oggetto JSON: {path}")

    window, cues, context_roles = _parse_context(data, warn)
    return Scope(lists=_parse_lists(data, warn), window=window, cues=cues,
                 context_roles=context_roles)
