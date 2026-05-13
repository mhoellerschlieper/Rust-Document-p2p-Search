/**********************************************************************************************
 *  Modulname : secure_p2p_ext
 *  Datei     : webdav_integration_patch.rs
 *  Autor     : Marcus Schlieper
 *---------------------------------------------------------------------------------------------
 *  Beschreibung
 *  - Beispiel Integration des WebDAV Gateways in das bestehende Hauptprogramm.
 *  - Startet den WebDAV Server parallel zum vorhandenen Webserver.
 *
 *  Historie
 *  13.05.2026  MS  - Initiale Integrationshilfe
 **********************************************************************************************/

/* In main.rs bei den Modulen ergaenzen */
mod webdav_gateway;
use crate::webdav_gateway::{run_webdav_server, WebDavEntry, WebDavGateway};

/* In main() nach init_indices und IAM Init ergaenzen */
let webdav_gateway = Arc::new(WebDavGateway::new(
    iam.clone(),
    idx_tan.clone(),
    idx_vec.clone(),
));

/*
 * Beispiel Daten fuer bekannte Peer Dokumente.
 * In der echten Integration werden diese Daten aus dem P2P Verzeichnis Cache,
 * aus DirResponse oder aus einer eigenen Peer Metadatenstruktur gefuellt.
 */
webdav_gateway.register_peer_entries(
    "peer_demo_01",
    vec![
        WebDavEntry {
            s_name: "angebot_2026.pdf".to_string(),
            s_path: "/peers/peer_demo_01/docs/angebot_2026.pdf".to_string(),
            b_dir: false,
            i_size: 123456,
            i_mtime_unix: now_ms() / 1000,
        },
        WebDavEntry {
            s_name: "projektplan.txt".to_string(),
            s_path: "/peers/peer_demo_01/docs/projektplan.txt".to_string(),
            b_dir: false,
            i_size: 2048,
            i_mtime_unix: now_ms() / 1000,
        },
    ],
);

/*
 * Eigener Bind fuer WebDAV.
 * Beispiel:
 * - Web UI:    127.0.0.1:8080
 * - WebDAV:    127.0.0.1:1900
 */
let s_webdav_bind = "127.0.0.1:1900".to_string();
{
    let gateway_clone = webdav_gateway.clone();
    tokio::spawn(async move {
        let _ = run_webdav_server(&s_webdav_bind, gateway_clone).await;
    });
}
println!("webdav: listening on http://{}", s_webdav_bind);
