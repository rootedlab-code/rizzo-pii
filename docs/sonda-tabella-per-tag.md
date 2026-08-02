# Sonda — regressione sul legale, dettaglio per tag

2.000 righe della validation legale, 4.346 entita'. Modello + rete regex core,
come gira in produzione. Recall entity-level, misure riproducibili.

Configurazioni: `base` = modello rilasciato; le altre due = fine-tuning su 200
righe di sicurezza bilanciate (`--max-tag-repeat 2`) con ripasso 4:1, a due
learning rate diversi.

| tag | gold | base | lr 2e-5 | lr 5e-6 | migliore |
|---|--:|--:|--:|--:|---|
| `FULLNAME` | 1293 | 0.981 | 0.981 | 0.978 | — |
| `CATASTO` | 345 | 0.371 | 0.246 | 0.168 | — |
| `DATE` | 264 | 0.295 | **0.591** | 0.311 | lr2e-5 |
| `TELEPHONENUM` | 260 | 0.977 | 0.965 | 0.965 | — |
| `CITY` | 244 | 0.959 | 0.943 | 0.959 | — |
| `ID_DOC` | 210 | 0.905 | 0.862 | 0.876 | — |
| `EMAIL` | 187 | 1.000 | 1.000 | 1.000 | — |
| `TIME` | 171 | 0.959 | 0.924 | 0.924 | — |
| `STREET` | 163 | 0.988 | 0.982 | 0.982 | — |
| `BUILDINGNUM` | 156 | 0.679 | 0.628 | 0.609 | — |
| `PIVA` | 152 | 0.961 | 0.947 | 0.961 | — |
| `GENDER` | 121 | 1.000 | 1.000 | 1.000 | — |
| `AGE` | 119 | 0.445 | **0.571** | 0.445 | lr2e-5 |
| `PROVINCE` | 112 | 1.000 | 1.000 | 1.000 | — |
| `CF` | 110 | 1.000 | 1.000 | 1.000 | — |
| `DOCID` | 108 | 0.083 | **0.093** | 0.019 | lr2e-5 |
| `ZIPCODE` | 87 | 0.379 | 0.287 | 0.253 | — |
| `IBAN` | 80 | 0.287 | 0.287 | 0.287 | — |
| `CREDITCARDNUMBER` | 78 | 0.090 | **0.115** | 0.090 | lr2e-5 |
| `AMOUNT` | 43 | 0.140 | **0.279** | 0.186 | lr2e-5 |
| `ORG` | 30 | 1.000 | 1.000 | 1.000 | — |
| `TARGA` | 13 | 0.615 | 0.615 | 0.538 | — |
| **MICRO** | 4346 | 0.789 | 0.793 | 0.763 | |
