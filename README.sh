## Uebersicht
ExpChat.ai ist ein KI-Chat-Client mit Fokus auf mittelstaendische Anwendungsfaelle und eine verteilte, peer to peer basierte Zusammenarbeit, bei der Kommunikation, Dateiuebertragung sowie lokale und verteilte Suchfaehigkeiten in einem einheitlichen Client zusammengefuehrt werden. Das System adressiert insbesondere Szenarien, in denen Wissensmanagement, sichere Teamkommunikation und datennahe Recherche ueber heterogene Dokumentbestaende hinweg erforderlich sind, ohne dass zwingend ein zentraler Server als Single Point of Failure betrieben werden muss (Schlieper, 2025).

## Kernfunktionen
### Sichere P2P Kommunikation
- Peer Discovery via mDNS und Messaging via libp2p gossipsub.
- Ende zu Ende Verschluesselung der Nutzdaten mit AES GCM SIV (256 Bit).
- Signierungskonzept auf Basis von BLS Threshold Bausteinen (derzeit als Grundstruktur integriert).

### Dateiuebertragung und DOS aehnliche Befehle
- Interaktive CLI Befehle fuer Verzeichnislisting und Dateioperationen.
- Dateiuebertragung als Chunk Payload (Grundstruktur vorhanden; je nach Branch kann der Transfer vereinfacht oder erweitert sein).

### Lokale und verteilte Suche
- Volltextsuche via Tantivy (BM25) mit periodischem Crawler fuer das Verzeichnis `./Documents`.
- Semantische Vektorsuche via Sentence Transformer Embeddings.
- Hybrid Suche als zweistufiges Verfahren mit Kandidatengenerierung und Re Ranking.

## Architektur in Kurzform
ExpChat.ai kombiniert drei wesentliche Subsysteme, die jeweils auf robuste, in der Praxis bewaehrte Bibliotheken aufsetzen: 
(1) ein Netzwerk Stack auf Basis von libp2p fuer Discovery und PubSub Transport, 
(2) ein lokales Indizierungs und Retrieval Subsystem fuer Volltext (Tantivy) sowie Semantik (Embeddings, brute force Cosine Similarity), und 
(3) eine CLI gesteuerte Interaktionsschicht, welche Chat, Dateioperationen und Suchoperationen vereinheitlicht. Die Index Aktualisierung erfolgt zeitgesteuert, um die Systemlast zu begrenzen und zugleich eine hinreichende Aktualitaet sicherzustellen (Manning et al., 2008).

## Voraussetzungen
### Toolchain
- Rust stable (empfohlen: aktuelle rustup Version)
- cargo

Beispiel:
- `rustup update`

### Plattform Hinweise
Unter Windows kann zusaetzlich ein MSVC Toolchain Target erforderlich sein:
- `rustup target add x86_64-pc-windows-msvc`

## Build und Run
### Build
- `cargo build --release`

### Start eines Nodes
`cargo run --release -- --listen /ip4/0.0.0.0/tcp/4001`

Hinweis: 
Je nach Projektstand kann die Anwendung automatisch auf TCP und QUIC binden oder optional per CLI Argumenten konfiguriert werden. 
In Umgebungen mit restriktiven Firewalls ist eine explizite Konfiguration von Listen Adressen zweckmaessig.

## Nutzung (CLI)
Die Anwendung stellt typischerweise ein interaktives Prompt zur Verfuegung. Relevante Befehle sind unter anderem:

- `help` oder `menu`  
  Zeigt die verfuegbaren Befehle.

- `peers`  
  Listet entdeckte Peers.

- `connect <idx>`  
  Initiiert eine Session mit einem Peer aus der Peerliste.

- `write <text>`  
  Sendet eine Chat Nachricht an den verbundenen Peer.

- `dir`  
  Fordert ein Verzeichnislisting an.

- `type <file>`  
  Fordert Dateiinhalt an (remote).

- `get <file>`  
  Laedt eine Datei vom Partner.

- `put <path>`  
  Sendet eine lokale Datei an den Partner.

- `search <query>`  
  Fuehrt eine BM25 Schlagwortsuche lokal aus und verteilt die Anfrage zusaetzlich im P2P Netz.

- `vec_search <query>`  
  Fuehrt eine semantische Suche lokal aus und verteilt die Anfrage zusaetzlich im P2P Netz.

- `combi_search <query>`  
  Fuehrt eine hybride Suche aus, typischerweise als Vektor Kandidaten plus BM25 Re Ranking oder umgekehrt, abhaengig von der Implementationsvariante.

## Dokumentenindexierung
### Dokumentverzeichnis
- Standardpfad: `./Documents`

### Unterstuetzte Dateitypen (Extraktion)
Die Extraktion ist auf typische Office und Text Formate ausgerichtet, unter anderem:
- txt
- pdf
- docx
- xlsx, xls, csv
- pptx

### Index Aktualisierung
Die Aktualisierung erfolgt periodisch; dabei werden geaenderte Dokumente anhand mtime und optional Hash Tracking erkannt. Dies reduziert Re Index Kosten und erhoeht die Deterministik bei wiederholten Laeufen.

## BM25 Char N Grams (Vektor Re Ranking)
Fuer das BM25 Re Ranking der aus der Vektorsuche selektierten Kandidaten wird eine Char N Gram Tokenisierung eingesetzt, die robust gegen Rechtschreibvarianten, Flexion und gewisse OCR Artefakte ist. Die Groesse der N Grams ist einstellbar ueber eine Umgebungsvariable:

- `BM25_NGRAM` in Range 3..6
- Default: 5

Beispiel (Linux, macOS):
- `export BM25_NGRAM=5`

Beispiel (PowerShell):
- `$env:BM25_NGRAM = "5"`

## Sicherheitshinweise
Das Projekt implementiert kryptographische Bausteine fuer Ende zu Ende Schutz; in produktiven Szenarien sind jedoch insbesondere folgende Punkte zwingend zu beachten:
- Persistente, sicher verwaltete Schluessel statt Hardcoded Defaults.
- Rotationskonzepte fuer Schluesselmaterial.
- Formale Bedrohungsmodellierung und Penetration Tests fuer das konkrete Deployment.

## KI Integration (optional)
In bestimmten Umgebungen wird ein lokaler LLM Server genutzt, beispielsweise via llama.cpp. Ein typischer Ablauf umfasst:
- Installation
- Start eines lokalen Inference Servers
- Nutzung durch Agents oder Research Workflows

Hinweis: Die konkrete Modellwahl, Lizenzierung und die Absicherung des Inference Endpoints sind in Abhaengigkeit von Einsatzgebiet und Compliance Vorgaben zu gestalten.

## Projektstruktur (Beispiel)
- `main.rs`  
  Netzwerklayer, CLI, Payload Handling, Search Dispatch.
- `vector_idx.rs`  
  Embedding Modell, Vektorindex, Sync, Query, BM25 Re Ranking (Char N Grams).

## Roadmap (indikativ)
- Stabilisierung von Schluesselmanagement und Session Handshake.
- Verbesserte Dateiuebertragung mit Sliding Window ACK und Resume.
- Optionaler ANN Index fuer groeessere Korpora jenseits von brute force.
- Erweiterte Observability (Tracing, Metriken, Audit Merkle Root).

## Kontakt
```text
ExpChat.ai
Der KI Chat Client fuer den Mittelstand aus Breckerfeld im Sauerland.
RPA, KI Agents, KI Internet Research, KI Wissensmanagement.
Adresse: Epscheider Str21 58339 Breckerfeld
E-Mail: mschlieper@expchat.ai
