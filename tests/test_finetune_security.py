# -*- coding: utf-8 -*-
"""
Test del fine-tuning sui documenti di sicurezza (src/training/finetune_security.py).

E' lo script che decide come si spendono le ore di GPU, ed era l'unico del progetto
senza copertura. I test qui sorvegliano tre cose che, sbagliate, non fanno fallire
niente: fanno girare la corsa e produrre un modello diverso da quello che si crede
di aver addestrato.

  - quali parametri restano addestrabili con --freeze-encoder (§2.5: asserire cio'
    che DEVE esserlo, non solo cio' che non deve);
  - che le righe interamente `O` entrino nel training, perche' sono la meta' del
    motivo per cui il fine-tuning esiste;
  - che finetune.json registri ogni leva, batch EFFICACE compreso (§2.3).

Torch e' sostituito da uno stub, come negli altri test d'integrazione: qui non si
addestra nulla, si verifica come viene preparato l'addestramento.

    python -m unittest discover -s tests
"""

import json
import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "training"))


def _install_stubs():
    """Aumenta il torch gia' presente invece di sostituirlo.

    Gli altri test d'integrazione registrano un proprio stub di torch, e chi arriva
    per primo vince: `setdefault` di un modulo intero avrebbe lasciato in piedi il
    loro, privo di `torch.utils`. Con torch vero installato non tocca nulla."""
    torch = sys.modules.setdefault("torch", types.ModuleType("torch"))
    if not hasattr(torch, "cuda"):
        torch.cuda = types.SimpleNamespace(is_available=lambda: False)
    if not hasattr(torch, "utils"):
        utils = types.ModuleType("torch.utils")
        utils.data = types.ModuleType("torch.utils.data")
        utils.data.Dataset = object
        torch.utils = utils
        sys.modules["torch.utils"] = utils
        sys.modules["torch.utils.data"] = utils.data


_install_stubs()

import finetune_security as fs      # noqa: E402

# I nomi veri dei parametri di rizzoaiacademy/rizzo-pii-0.3B, campionati alle due
# estremita': l'encoder (`model.*`) e la testa (`head.*` + `classifier.*`).
NOMI_VERI = [
    "model.embeddings.tok_embeddings.weight",
    "model.layers.0.attn.Wqkv.weight",
    "model.layers.21.mlp.Wo.weight",
    "model.final_norm.weight",
    "head.dense.weight",
    "head.norm.weight",
    "classifier.weight",
    "classifier.bias",
]

LABEL2ID = {"O": 0, "B-FULLNAME": 1, "I-FULLNAME": 2, "B-DATE": 3, "B-IBAN": 4}
TAG_MAP = {"GIVENNAME": "FULLNAME", "SURNAME": "FULLNAME"}
DROP = {"TITLE"}


class FakeEncoding(dict):
    """Cio' che il tokenizer restituisce, ridotto al contratto che build_dataset usa."""

    def __init__(self, parole):
        super().__init__(input_ids=list(range(len(parole))),
                         attention_mask=[1] * len(parole))
        self._word_ids = list(range(len(parole)))

    def word_ids(self):
        return self._word_ids


def fake_tokenizer(tokens, is_split_into_words=True, truncation=True, max_length=None):
    """Un subword per parola: cosi' l'allineamento etichette/subword e' l'identita'
    e il test misura la logica di build_dataset, non quella del tokenizer."""
    return FakeEncoding(tokens[:max_length] if max_length else tokens)


def riga(parole, etichette):
    return {"tokens": parole, "bio_labels": etichette}


class TestFreezeEncoder(unittest.TestCase):
    """La leva piu' forte contro la dimenticanza, e la piu' facile da sbagliare in
    silenzio: aggancia un sottoinsieme piu' piccolo del previsto e la corsa parte
    lo stesso."""

    def test_the_whole_head_stays_trainable_and_the_encoder_does_not(self):
        agganciati, orfani = fs.head_parameters(NOMI_VERI)
        self.assertEqual(orfani, [])
        # l'insieme ESATTO, non "almeno questi": e' il punto della §2.5
        self.assertEqual(sorted(agganciati), [
            "classifier.bias", "classifier.weight",
            "head.dense.weight", "head.norm.weight"])

    def test_no_encoder_parameter_is_hooked(self):
        agganciati, _ = fs.head_parameters(NOMI_VERI)
        self.assertEqual([n for n in agganciati if n.startswith("model.")], [])

    def test_a_prefix_matching_nothing_is_reported_not_ignored(self):
        # il guasto silenzioso: cambia l'architettura di base, `head.` non aggancia
        # piu' nulla e resta il solo `classifier` — lo 0,011% dei pesi invece dello
        # 0,2%. Senza questa segnalazione la corsa gira per ore e costa
        solo_classifier = ["model.layers.0.attn.Wqkv.weight",
                           "classifier.weight", "classifier.bias"]
        agganciati, orfani = fs.head_parameters(solo_classifier)
        self.assertEqual(orfani, ["head."])
        self.assertEqual(sorted(agganciati), ["classifier.bias", "classifier.weight"])

    def test_a_generator_is_consumed_as_a_list_would_be(self):
        # model.named_parameters() e' un generatore, e la funzione lo scorre una volta
        # per prefisso: passandolo cosi', `head.` lo esauriva e `classifier.` risultava
        # orfano. Il difetto e' esistito, e i test non lo vedevano perche' gli
        # passavano una lista — il gemello fra la forma del test e quella d'uso
        agganciati, orfani = fs.head_parameters(n for n in NOMI_VERI)
        self.assertEqual(orfani, [])
        self.assertEqual(len(agganciati), 4)

    def test_nothing_hooked_at_all_is_reported_for_every_prefix(self):
        agganciati, orfani = fs.head_parameters(["model.layers.0.attn.Wqkv.weight"])
        self.assertEqual(agganciati, [])
        self.assertEqual(sorted(orfani), sorted(fs.HEAD_PREFIXES))


class TestAllOhRowsAreKept(unittest.TestCase):
    """Le righe senza alcuna entita' insegnano il negativo: che un indirizzo IP, un
    hash e un identificativo cloud sono `O`. Sono il 15,8% del corpus bilanciato e
    chiudono una delle due lacune misurate (~2.700 entita' inventate). Una versione
    precedente le scartava."""

    def test_a_row_with_no_entity_produces_an_example(self):
        righe = [riga(["Il", "server", "203.0.113.42", "risponde"], ["O"] * 4)]
        ds = fs.build_dataset(righe, fake_tokenizer, LABEL2ID, TAG_MAP, DROP)
        self.assertEqual(len(ds), 1)
        self.assertEqual(set(ds[0]["labels"]), {LABEL2ID["O"]})

    def test_every_row_reaches_the_training_set(self):
        righe = ([riga(["testo", "tecnico", "senza", "PII"], ["O"] * 4)] * 7 +
                 [riga(["Mario", "Rossi", "ha", "firmato"],
                       ["B-GIVENNAME", "B-SURNAME", "O", "O"])] * 3)
        ds = fs.build_dataset(righe, fake_tokenizer, LABEL2ID, TAG_MAP, DROP)
        self.assertEqual(len(ds), 10)

    def test_a_row_whose_only_tag_is_dropped_is_kept_as_all_oh(self):
        # TITLE finisce in DROP: la riga diventa interamente `O` per rimappatura, non
        # per costruzione. Resta comunque, e per la stessa ragione
        righe = [riga(["Il", "dottor", "presente"], ["O", "B-TITLE", "O"])]
        ds = fs.build_dataset(righe, fake_tokenizer, LABEL2ID, TAG_MAP, DROP)
        self.assertEqual(len(ds), 1)
        self.assertEqual(set(ds[0]["labels"]), {LABEL2ID["O"]})


class TestBioRemapping(unittest.TestCase):

    def test_given_and_surname_become_the_tag_the_model_knows(self):
        r = riga(["Mario", "Rossi"], ["B-GIVENNAME", "B-SURNAME"])
        self.assertEqual(fs.bio_of(r, LABEL2ID, TAG_MAP, DROP),
                         ["B-FULLNAME", "B-FULLNAME"])

    def test_a_dropped_type_becomes_oh(self):
        r = riga(["dottor"], ["B-TITLE"])
        self.assertEqual(fs.bio_of(r, LABEL2ID, TAG_MAP, DROP), ["O"])

    def test_a_label_the_model_does_not_know_becomes_oh(self):
        # senza questo, si addestrerebbe su etichette assenti da label2id e ogni
        # occorrenza diventerebbe rumore
        r = riga(["203.0.113.42"], ["B-IPADDR"])
        self.assertEqual(fs.bio_of(r, LABEL2ID, TAG_MAP, DROP), ["O"])

    def test_tags_of_reports_the_remapped_types(self):
        r = riga(["Mario", "Rossi", "il", "01/02/2024"],
                 ["B-GIVENNAME", "B-SURNAME", "O", "B-DATE"])
        self.assertEqual(fs.tags_of(r, TAG_MAP, DROP), {"FULLNAME", "DATE"})


class TestStratifiedRehearsal(unittest.TestCase):
    """Il ripasso serve a coprire i tag che i dati NUOVI non contengono: sono
    esattamente quelli che degradano."""

    def setUp(self):
        self.pool = ([riga(["catastale"], ["B-CATASTO"])] * 5 +
                     [riga(["targa"], ["B-TARGA"])] * 2 +
                     [riga(["Mario"], ["B-GIVENNAME"])] * 50)
        self.nuove = [riga(["Mario"], ["B-GIVENNAME"])] * 10

    def test_the_missing_tags_are_covered_first(self):
        scelte = fs.stratified_rehearsal(self.pool, 4, self.nuove, TAG_MAP, DROP)
        tipi = set()
        for r in scelte:
            tipi |= fs.tags_of(r, TAG_MAP, DROP)
        self.assertIn("CATASTO", tipi)
        self.assertIn("TARGA", tipi)   # il piu' raro nel pool non viene schiacciato

    def test_the_same_seed_gives_the_same_choice(self):
        a = fs.stratified_rehearsal(self.pool, 20, self.nuove, TAG_MAP, DROP, seed=7)
        b = fs.stratified_rehearsal(self.pool, 20, self.nuove, TAG_MAP, DROP, seed=7)
        self.assertEqual(a, b)

    def test_it_never_returns_more_than_asked(self):
        scelte = fs.stratified_rehearsal(self.pool, 3, self.nuove, TAG_MAP, DROP)
        self.assertEqual(len(scelte), 3)

    def test_it_does_not_repeat_a_row_of_the_pool(self):
        scelte = fs.stratified_rehearsal(self.pool, 57, self.nuove, TAG_MAP, DROP)
        self.assertEqual(len(scelte), 57)
        self.assertEqual(len(scelte), len(self.pool))


class TestRehearsalSaturation(unittest.TestCase):
    """Quando il pool si esaurisce, --rehearsal-ratio smette di fare qualcosa. E'
    successo nella corsa a scala piena mentre la stessa leva veniva tarata sulla
    sonda, dove il pool NON si esaurisce: si crede di aver tarato un rapporto, e nel
    run vero quel rapporto non e' collegato a niente."""

    def test_below_saturation_the_ratio_decides(self):
        quante, richieste = fs.quante_di_ripasso(200, 4, 10000)
        self.assertEqual((quante, richieste), (800, 800))

    def test_above_saturation_the_pool_decides(self):
        # il caso reale: 18.805 righe nuove, ratio 4, pool da 10.000
        quante, richieste = fs.quante_di_ripasso(18805, 4, 10000)
        self.assertEqual(quante, 10000)
        self.assertEqual(richieste, 75220)
        self.assertNotEqual(quante, richieste)      # e' questo che va segnalato

    def test_raising_the_ratio_past_saturation_changes_nothing(self):
        a, _ = fs.quante_di_ripasso(18805, 4, 10000)
        b, _ = fs.quante_di_ripasso(18805, 40, 10000)
        self.assertEqual(a, b)

    def test_the_saturation_point_is_where_the_two_meet(self):
        # pool/nuove = 10000/18805 = 0.5317...: sotto decide il rapporto, sopra il pool
        quante, richieste = fs.quante_di_ripasso(18805, 10000 / 18805, 10000)
        self.assertEqual(quante, richieste)

    def test_a_ratio_below_one_is_honoured(self):
        quante, richieste = fs.quante_di_ripasso(18805, 0.5, 10000)
        self.assertEqual((quante, richieste), (9402, 9402))


class TestRunRecord(unittest.TestCase):
    """finetune.json e' cio' che resta di una corsa quando si confrontano due
    esperimenti a distanza di giorni. Una leva che non compare li rende
    indistinguibili."""

    def args(self, argv=()):
        return fs.build_parser().parse_args(
            ["--train", "t.jsonl", "--out", "o", *argv])

    def test_every_command_line_lever_appears_in_the_record(self):
        args = self.args()
        scheda = fs.scheda_corsa(args, righe=100, esempi=98, ripasso_righe=40)
        mancanti = [k for k in vars(args) if k not in scheda]
        self.assertEqual(mancanti, [])

    def test_the_effective_batch_is_recorded_not_just_the_micro_batch(self):
        # due corse con --batch 8 e accumulo 2 oppure 4 scrivono lo stesso "batch: 8"
        # ma sono due esperimenti diversi: cambia il numero di passi di ottimizzazione
        scheda = fs.scheda_corsa(self.args(["--batch", "8", "--accum", "4"]),
                                 righe=1, esempi=1, ripasso_righe=0)
        self.assertEqual(scheda["batch"], 8)
        self.assertEqual(scheda["accum"], 4)
        self.assertEqual(scheda["batch_efficace"], 32)

    def test_the_freeze_lever_is_recorded(self):
        acceso = fs.scheda_corsa(self.args(["--freeze-encoder"]), 1, 1, 0)
        spento = fs.scheda_corsa(self.args(), 1, 1, 0)
        self.assertTrue(acceso["freeze_encoder"])
        self.assertFalse(spento["freeze_encoder"])

    def test_the_rehearsal_configuration_is_recorded(self):
        scheda = fs.scheda_corsa(
            self.args(["--rehearsal", "r.jsonl", "--rehearsal-strategy", "stratified",
                       "--rehearsal-ratio", "4"]), righe=500, esempi=498,
            ripasso_righe=400)
        self.assertEqual(scheda["rehearsal_strategy"], "stratified")
        self.assertEqual(scheda["rehearsal_ratio"], 4.0)
        self.assertEqual(scheda["ripasso_righe"], 400)

    def test_the_record_survives_the_round_trip_to_json(self):
        scheda = fs.scheda_corsa(self.args(), 1, 1, 0)
        self.assertEqual(json.loads(json.dumps(scheda)), scheda)


if __name__ == "__main__":
    unittest.main()
