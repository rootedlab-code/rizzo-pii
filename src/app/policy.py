# -*- coding: utf-8 -*-
"""
Politica di anonimizzazione: per ogni tag decide se MASCHERARE l'entita' con un
placeholder reversibile (comportamento storico, default) o LASCIARLA IN CHIARO.

Perche' serve: alcuni compiti chiesti al modello di frontiera dipendono proprio dai
valori che l'anonimizzazione rimuove — il confronto fra due importi dello stesso
contratto, l'eta' e il sesso in uno studio clinico. Con la policy l'utente sceglie
per tag cosa esce dal documento; senza configurazione si maschera tutto, come prima.

Risoluzione con precedenza, la stessa catena di server_config:

    CLI  >  env (PII_PROFILE / PII_KEEP_TAGS)  >  policy.json  >  default

Il profilo da' un insieme di tag di partenza; i tag indicati esplicitamente si
AGGIUNGONO a quelli del profilo (unione). Per mascherare tutto: profilo "full",
nessun tag.

policy.json sta nella stessa directory di config.json (server_config.config_dir())
ma e' un file SEPARATO: config.json e' scritto anche dall'app Tauri dal lato Rust,
che lo riscrive come {"host", "port"} e cancellerebbe una chiave estranea.

    Formato:  {"profile": "clinical", "keep_tags": ["AMOUNT"]}

Oltre al tag, la decisione puo' dipendere dal RUOLO del valore (vedi scope.py):
in un report di sicurezza l'IP del cliente e quello dell'attaccante hanno lo
stesso tag e trattamento opposto. `keep_tags` resta la regola incondizionata
("questo tag in chiaro sempre"), `keep_roles` e' la regola condizionata
("questo tag in chiaro solo quando e' di quel ruolo"):

    {"profile": "security-report", "keep_roles": {"adversary": ["IP", "DOMAIN"]}}

La dipendenza va in una sola direzione — policy conosce il vocabolario dei ruoli
di scope, scope non sa nulla della policy — perche' e' la policy a decidere, e
per decidere deve poter nominare cio' su cui decide.

Il modulo e' puro (nessun import di torch/flask/transformers): si puo' testare e
usare senza caricare il modello.
"""

import json
import os
import sys
from collections import namedtuple
from pathlib import Path

import scope
import server_config

# Azioni possibili su un'entita' rilevata.
ACTION_MASK = "mask"    # -> [TAG_n] + voce nel dizionario reversibile
ACTION_KEEP = "keep"    # -> resta in chiaro nel testo anonimizzato
ACTIONS = (ACTION_MASK, ACTION_KEEP)

# Motivo riportato nell'output per un'entita' rilevata ma non mascherata.
REASON_CONFIG = "excluded_by_config"   # tenuta per il suo tag, qualunque sia il ruolo
REASON_SCOPE = "excluded_by_scope"     # tenuta perche' quel tag + quel ruolo

# Esito completo: cosa fare e perche'. action() ne restituisce solo il primo campo,
# per non cambiare una firma su cui il resto dell'app gia' si appoggia.
Decision = namedtuple("Decision", "action reason")

_MASKED = Decision(ACTION_MASK, None)

DEFAULT_PROFILE = "full"

# Profili preconfezionati: nome -> tag lasciati in chiaro SEMPRE.
PROFILES = {
    "full": (),                                        # maschera tutto (storico)
    "clinical": ("AGE", "GENDER", "DATE", "TIME"),     # cartelle/studi clinici
    "compare-amounts": ("AMOUNT",),                    # confronti fra importi
    "security-report": (),                             # vedi PROFILE_ROLES
}

# Tag lasciati in chiaro solo per un dato ruolo. Tenuto separato da PROFILES perche'
# quello e' un elenco piatto di tag: fonderli avrebbe cambiato una struttura pubblica.
#
# 'security-report': gli indicatori dell'avversario sono l'OGGETTO del documento —
# mascherarli lo rende inutile — mentre tutto cio' che e' del cliente, o di ruolo non
# determinato, resta mascherato. PATH e USER sono volutamente esclusi: un percorso
# contiene spesso lo username di una macchina compromessa, cioe' del cliente, e nel
# dubbio si maschera. Chi li vuole se li aggiunge nel proprio policy.json.
_IOC_TAGS = ("IP", "DOMAIN", "URL", "HASH", "WALLET", "ASN", "MAC", "CLOUDID")
PROFILE_ROLES = {
    "security-report": {
        scope.ROLE_ADVERSARY: _IOC_TAGS,
        scope.ROLE_PUBLIC: _IOC_TAGS,
    },
}

# Cosa serve a un profilo per fare quello che dice. Dichiarato come DATO, perche' un
# profilo che promette e non mantiene e' peggio di un profilo assente.
#
# 'security-report' e' inerte per DUE cause indipendenti, e ne basta una: senza il
# pacchetto 'cyber' le sue label non sono nella tassonomia e resolve_roles le scarta,
# quindi keep_roles esce VUOTO — cioe' il profilo diventa un sinonimo esatto di 'full';
# e senza un file di scope nessuna entita' ha un ruolo, quindi regole per ruolo non
# possono applicarsi a nulla. La prima causa si puo' rimuovere da soli (basta accendere
# il pacchetto); la seconda no, ed e' per questo che va DETTA all'utente.
#
# `packs` lo risolve chi accende i detector; `scope` lo puo' verificare solo l'app, che
# e' l'unica a sapere se un file d'ingaggio e' caricato.
PROFILE_REQUIRES = {
    "security-report": {"packs": ("cyber",), "scope": True},
}

# Identificatori diretti: lasciarli in chiaro e' una scelta legittima ma pesante,
# quindi la si segnala una volta al caricamento. Non e' un divieto.
HIGH_RISK_TAGS = frozenset({
    "FULLNAME", "CF", "PIVA", "IBAN", "CREDITCARDNUMBER", "ID_DOC",
    "EMAIL", "TELEPHONENUM",
})

POLICY_FILENAME = "policy.json"


def _warn(message: str) -> None:
    print(f"[policy] {message}", file=sys.stderr)


def policy_path() -> Path:
    """Percorso di policy.json (stessa directory di config.json)."""
    return server_config.config_dir() / POLICY_FILENAME


def load_file() -> dict:
    """Legge policy.json; ritorna {} se manca o e' corrotto (come server_config)."""
    p = policy_path()
    if p.exists():
        try:
            data = json.loads(p.read_text("utf-8"))
            if isinstance(data, dict):
                return data
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def save_file(profile: str, keep_tags, keep_roles=None, detectors=None) -> None:
    """Scrive policy.json (crea la directory se necessario).

    keep_roles finisce nel file solo se c'e': un file senza quella chiave e' un file
    di una configurazione senza ruoli, non un file a cui manca qualcosa.

    `detectors` sta QUI e non in config.json perche' config.json e' riscritto per
    intero da due parti — Tauri dal lato Rust e POST /config dal modale — e una chiave
    estranea verrebbe cancellata al primo salvataggio di host/porta. E' la stessa
    ragione per cui esiste questo file. Sta con la policy, e non fra le impostazioni
    d'avvio, perche' come la policy si cambia a caldo: e' "cosa cerco" accanto a
    "cosa ne faccio"."""
    d = server_config.config_dir()
    d.mkdir(parents=True, exist_ok=True)
    payload = {"profile": profile, "keep_tags": list(parse_tags(keep_tags))}
    roles = parse_roles(keep_roles)
    if roles:
        payload["keep_roles"] = {r: list(t) for r, t in sorted(roles.items())}
    if detectors:
        payload["detectors"] = sorted({str(p).strip().lower() for p in detectors if str(p).strip()})
    (d / POLICY_FILENAME).write_text(json.dumps(payload, indent=2), "utf-8")


def saved_detectors() -> list:
    """I pacchetti di detector salvati in policy.json, o [] se non ce ne sono.

    `policy.py` non li interpreta: sa solo che sono nomi da conservare e da
    restituire. Chi decide quali esistano e' `app.py`, che ha il registro dei
    pacchetti — invertire quella dipendenza legherebbe il modulo puro all'app."""
    raw = load_file().get("detectors")
    if not raw:
        return []
    items = raw.replace(",", " ").split() if isinstance(raw, str) else list(raw)
    return [str(i).strip().lower() for i in items if str(i).strip()]


def parse_tags(raw) -> tuple:
    """Normalizza una lista di tag scritta come stringa o come lista.

    Accetta "age, gender" oppure ["AGE", "GENDER"]; ritorna una tupla di tag in
    MAIUSCOLO, senza vuoti e senza duplicati, nell'ordine di apparizione.
    """
    if raw is None:
        return ()
    items = raw.replace(";", ",").split(",") if isinstance(raw, str) else list(raw)
    out = []
    for item in items:
        tag = str(item).strip().upper()
        if tag and tag not in out:
            out.append(tag)
    return tuple(out)


def parse_roles(raw) -> dict:
    """Normalizza {ruolo: tag} in {ruolo-minuscolo: tupla-di-tag-maiuscoli}.

    Come parse_tags, normalizza soltanto la FORMA: non verifica che i ruoli
    esistano ne' che i tag siano nella tassonomia. Quella e' validazione, e sta in
    load_policy dove c'e' un warn a cui riportarla."""
    if not raw:
        return {}
    if not isinstance(raw, dict):
        raise TypeError(f"keep_roles deve essere un dizionario, non {type(raw).__name__}")
    out = {}
    for role, tags in raw.items():
        parsed = parse_tags(tags)
        if parsed:
            out[str(role).strip().lower()] = parsed
    return out


class Policy:
    """Cosa fare di ogni entita' rilevata.

    keep_tags:  tag lasciati in chiaro SEMPRE, qualunque sia il ruolo.
    keep_roles: {ruolo: [tag]} — tag lasciati in chiaro SOLO per quel ruolo.

    Le due regole non si contraddicono mai per costruzione: keep_tags e'
    incondizionata e viene valutata per prima, keep_roles la raffina.
    """

    def __init__(self, keep_tags=(), profile: str = DEFAULT_PROFILE, keep_roles=None):
        self.profile = profile
        self.keep_tags = frozenset(parse_tags(keep_tags))
        self.keep_roles = {r: frozenset(t) for r, t in parse_roles(keep_roles).items()}

    def decide(self, label: str, role=None) -> Decision:
        """Azione + motivo per un'entita'.

        role=None (o un ruolo senza regole) ricade sul solo keep_tags: e' il
        comportamento di prima dell'esistenza dei ruoli, quindi chi non configura
        nulla non vede alcuna differenza."""
        tag = str(label).upper()
        if tag in self.keep_tags:
            return Decision(ACTION_KEEP, REASON_CONFIG)
        if role and tag in self.keep_roles.get(role, ()):
            return Decision(ACTION_KEEP, REASON_SCOPE)
        return _MASKED

    def action(self, label: str, role=None) -> str:
        """ACTION_KEEP se l'entita' va lasciata in chiaro, altrimenti ACTION_MASK."""
        return self.decide(label, role).action

    def keeps(self, label: str, role=None) -> bool:
        return self.action(label, role) == ACTION_KEEP

    def as_dict(self) -> dict:
        """Rappresentazione serializzabile (risposta API / UI).

        keep_roles compare solo se c'e': una policy senza ruoli deve serializzarsi
        esattamente come prima che i ruoli esistessero."""
        out = {"profile": self.profile, "keep_tags": sorted(self.keep_tags)}
        if self.keep_roles:
            out["keep_roles"] = {r: sorted(t) for r, t in sorted(self.keep_roles.items())}
        return out

    def __repr__(self):
        roles = f", keep_roles={ {r: sorted(t) for r, t in self.keep_roles.items()} }" \
                if self.keep_roles else ""
        return (f"Policy(profile={self.profile!r}, "
                f"keep_tags={sorted(self.keep_tags)}{roles})")


def _profile_tags(name: str, warn) -> tuple:
    """Tag del profilo; profilo sconosciuto -> avviso e default."""
    if name in PROFILES:
        return PROFILES[name]
    warn(f"profilo sconosciuto '{name}': uso '{DEFAULT_PROFILE}'. "
         f"Disponibili: {', '.join(sorted(PROFILES))}")
    return PROFILES[DEFAULT_PROFILE]


def load_policy(cli_keep_tags=None, cli_profile=None, known_tags=None, warn=_warn) -> Policy:
    """Risolve la policy con la catena CLI > env > policy.json > default.

    cli_keep_tags / cli_profile: valori da riga di comando (None = non specificati).
    known_tags: tassonomia valida (label del modello + della rete regex). I tag non
        riconosciuti vengono segnalati e ignorati, non fanno fallire il caricamento.
    warn: funzione di avviso, iniettabile nei test.

    Il primo livello che fornisce dei tag vince (non si sommano fra loro); i tag del
    profilo si aggiungono sempre.
    """
    cfg = load_file()

    profile = (cli_profile
               or os.environ.get("PII_PROFILE")
               or cfg.get("profile")
               or DEFAULT_PROFILE)
    profile = str(profile).strip().lower()

    explicit = ()
    for source in (cli_keep_tags, os.environ.get("PII_KEEP_TAGS"), cfg.get("keep_tags")):
        explicit = parse_tags(source)
        if explicit:
            break

    tags = list(_profile_tags(profile, warn))
    for tag in explicit:
        if tag not in tags:
            tags.append(tag)

    if known_tags:
        known = {str(t).upper() for t in known_tags}
        unknown = [t for t in tags if t not in known]
        if unknown:
            warn(f"tag non presenti nella tassonomia, ignorati: {', '.join(unknown)}")
        tags = [t for t in tags if t in known]

    risky = sorted(t for t in tags if t in HIGH_RISK_TAGS)
    if risky:
        warn(f"ATTENZIONE: identificatori diretti lasciati IN CHIARO: {', '.join(risky)}")

    roles = resolve_roles(profile, cfg.get("keep_roles"), known_tags, warn)
    return Policy(keep_tags=tags, profile=profile, keep_roles=roles)


def resolve_roles(profile, cfg_roles, known_tags=None, warn=_warn) -> dict:
    """Regole per ruolo = quelle del profilo UNITE a quelle di policy.json.

    Unione e non "il primo che parla vince", a differenza di keep_tags: qui non c'e'
    una catena CLI/env da rispettare (un dizionario ruolo->tag non si scrive su una
    riga di comando senza inviti all'errore di battitura), quindi il profilo da' la
    base e il file la estende.

    Un ruolo inesistente o un tag fuori tassonomia vengono segnalati e scartati: come
    per keep_tags, una regola che non si applichera' mai non deve far fallire l'avvio,
    ma non deve nemmeno restare invisibile."""
    merged = {}
    for source in (PROFILE_ROLES.get(profile, {}), cfg_roles):
        try:
            parsed = parse_roles(source)
        except TypeError as exc:
            warn(f"keep_roles ignorato: {exc}")
            continue
        for role, tags in parsed.items():
            merged.setdefault(role, [])
            merged[role] += [t for t in tags if t not in merged[role]]

    unknown_roles = [r for r in merged if r not in scope.ROLES]
    if unknown_roles:
        warn(f"ruoli sconosciuti in keep_roles, ignorati: {', '.join(sorted(unknown_roles))} "
             f"(attesi: {', '.join(scope.ROLES)})")
    merged = {r: t for r, t in merged.items() if r in scope.ROLES}

    if known_tags:
        known = {str(t).upper() for t in known_tags}
        dropped = sorted({t for tags in merged.values() for t in tags if t not in known})
        if dropped:
            warn(f"tag di keep_roles non presenti nella tassonomia, ignorati: "
                 f"{', '.join(dropped)}")
        merged = {r: [t for t in tags if t in known] for r, tags in merged.items()}

    return {r: t for r, t in merged.items() if t}
