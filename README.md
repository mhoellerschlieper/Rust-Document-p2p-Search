## Overview
ExpChat.ai is an AI chat client focused on mid-sized business use cases and distributed, peer-to-peer collaboration, in which communication, file transfer, and local as well as distributed search capabilities are consolidated into a unified client. The system particularly addresses scenarios in which knowledge management, secure team communication, and data-proximate research across heterogeneous document collections are required, without necessarily having to operate a central server as a single point of failure (Schlieper, 2025).

## Core Features
### Secure P2P Communication
- Peer discovery via mDNS and messaging via libp2p gossipsub.
- End-to-end encryption of user payloads using AES GCM SIV (256-bit).
- A signing concept based on BLS threshold components (currently integrated as a basic structure).

### File Transfer and DOS-like Commands
- Interactive CLI commands for directory listing and file operations.
- File transfer implemented as chunked payloads (basic structure available; depending on the branch, transfer may be simplified or extended).

### Local and Distributed Search
- Full-text search via Tantivy (BM25) with a periodic crawler for the `./Documents` directory.
- Semantic vector search via sentence-transformer embeddings.
- Hybrid search implemented as a two-stage procedure with candidate generation and re-ranking.

## Architecture in Brief
ExpChat.ai combines three essential subsystems, each building on robust, well-established libraries: (1) a networking stack based on libp2p for discovery and PubSub transport, (2) a local indexing and retrieval subsystem for full text (Tantivy) as well as semantics (embeddings, brute-force cosine similarity), and (3) a CLI-driven interaction layer that unifies chat, file operations, and search operations. Index updates are time-scheduled to limit system load while ensuring sufficient freshness (Manning et al., 2008).

## Prerequisites
### Toolchain
- Rust stable (recommended: current rustup version)
- cargo

Example:
- `rustup update`

### Platform Notes
On Windows, an MSVC toolchain target may additionally be required:
- `rustup target add x86_64-pc-windows-msvc`

## Build and Run
### Build
- `cargo build --release`

### Start
- `cargo run --release`

Note: Depending on the project state, the application may bind automatically to TCP and QUIC or be optionally configurable via CLI arguments. In environments with restrictive firewalls, explicitly configuring listen addresses is advisable.

## Usage (CLI)
The application typically provides an interactive prompt. Relevant commands include, among others:

- `help` or `menu`  
  Displays the available commands.

- `peers`  
  Lists discovered peers.

- `connect `  
  Initiates a session with a peer from the peer list.

- `write `  
  Sends a chat message to the connected peer.

- `dir`  
  Requests a directory listing.

- `type `  
  Requests file contents (remote).

- `get `  
  Downloads a file from the peer.

- `put `  
  Sends a local file to the peer.

- `search `  
  Performs a local BM25 keyword search and additionally distributes the query in the P2P network.

- `vec_search `  
  Performs a local semantic search and additionally distributes the query in the P2P network.

- `combi_search `  
  Performs a hybrid search, typically as vector candidates plus BM25 re-ranking or vice versa, depending on the implementation variant.

## Document Indexing
### Document Directory
- Default path: `./Documents`

### Supported File Types (Extraction)
Extraction is oriented toward typical office and text formats, including:
- txt
- pdf
- docx
- xlsx, xls, csv
- pptx

### Index Updates
Updates are performed periodically; modified documents are detected via mtime and optionally hash tracking. This reduces re-indexing costs and increases determinism across repeated runs.

## BM25 Character N-grams (Vector Re-ranking)
For BM25 re-ranking of candidates selected via vector search, a character n-gram tokenization is used that is robust against spelling variations, inflection, and certain OCR artifacts. The n-gram size can be configured via an environment variable:

- `BM25_NGRAM` in range 3..6
- Default: 5

Example (Linux, macOS):
- `export BM25_NGRAM=5`

Example (PowerShell):
- `$env:BM25_NGRAM = &quot;5&quot;`

## Security Notes
The project implements cryptographic components for end-to-end protection; however, in production scenarios the following points in particular must be strictly observed:
- Persistent, securely managed keys instead of hardcoded defaults.
- Rotation concepts for key material.
- Formal threat modeling and penetration tests for the specific deployment.

## AI Integration (Optional)
In certain environments, a local LLM server is used, for example via llama.cpp. A typical workflow includes:
- Installation
- Starting a local inference server
- Use by agents or research workflows

Note: The concrete model selection, licensing, and securing of the inference endpoint must be designed according to the use case and compliance requirements.

## Project Structure (Example)
- `main.rs`  
  Network layer, CLI, payload handling, search dispatch.
- `vector_idx.rs`  
  Embedding model, vector index, sync, query, BM25 re-ranking (character n-grams).

## Roadmap (Indicative)
- Stabilization of key management and session handshake.
- Improved file transfer with sliding-window ACK and resume.
- Optional ANN index for larger corpora beyond brute force.
- Extended observability (tracing, metrics, audit Merkle root).

## Contact
text
ExpChat.ai
The AI chat client for mid-sized businesses from Breckerfeld in the Sauerland region.
RPA, AI agents, AI internet research, AI knowledge management.
Address: Epscheider Str21 58339 Breckerfeld
Email: mschlieper@ylook.de
Phone: 49 2338 8748862
Mobile: 49 15115751864


## References
Manning, C. D., Raghavan, P., &amp; Schuetze, H. (2008). *Introduction to Information Retrieval*. Cambridge University Press.

Schlieper, M. (2025). *ExpChat.ai: Secure p2p client with hybrid search and document intelligence* (Unpublished internal project document). ExpChat.ai.
