# -*- coding: utf-8 -*-
"""La tassonomia del modello finto: imposta da chi ne dipende, non subita dall'ordine.

Ogni file di test installa il proprio stub di `transformers` con
`sys.modules.setdefault`, quindi vince quello del **primo file importato**: `app.nlp`
e' uno solo per processo, e `known_tags()` lo legge a ogni chiamata. Un'asserzione
sulle label del modello diventa cosi' verde nella suite intera e rossa da sola — o
viceversa — a seconda dell'ordine di scoperta dei file. E' il difetto D9 del piano, e
lo stesso motivo per cui `test_model_info` chiede il conteggio al modello caricato
invece di fissarlo.

La regola: **chi dipende dalle label del modello se le impone**, qui e adesso, e le
restituisce a fine test. Ogni file resta libero di dichiarare la tassonomia che gli
serve — quella scelta e' informazione, non duplicazione — senza dover sperare di
arrivare per primo.

Non si chiama `test_*.py` di proposito: non deve essere raccolto da `discover`.
"""

import types


class ModelloFinto:
    """Pipeline di token-classification finta: non predice nulla, espone la tassonomia.

    Non predire niente e' voluto: i test che la usano misurano la rete deterministica,
    la policy o la tassonomia — cioe' il codice — e un modello che inventasse entita'
    aggiungerebbe rumore che non appartiene a nessuna delle tre."""

    def __init__(self, etichette):
        self.model = types.SimpleNamespace(config=types.SimpleNamespace(
            label2id={nome: i for i, nome in enumerate(etichette)}))

    def __call__(self, texts, *args, **kwargs):
        return [[] for _ in texts] if isinstance(texts, list) else []


def imponi(test, app, etichette):
    """Fa vedere ad `app` un modello con queste etichette, per la durata del test.

    Il ripristino e' registrato con `addCleanup`: vale anche se il test fallisce a
    meta', e non obbliga chi la usa ad avere un tearDown proprio."""
    test.addCleanup(setattr, app, "nlp", app.nlp)
    app.nlp = ModelloFinto(etichette)
    return app.nlp
