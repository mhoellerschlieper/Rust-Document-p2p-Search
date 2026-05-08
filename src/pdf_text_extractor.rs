use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use lopdf::{Document, Object};

#[derive(Debug)]
pub enum ExtractPdfError {
    IoError(std::io::Error),
    PdfError(lopdf::Error),
    Utf8Error(std::string::FromUtf8Error),
    ExternalToolError(String),
}

impl std::fmt::Display for ExtractPdfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtractPdfError::IoError(e) => write!(f, "io error: {}", e),
            ExtractPdfError::PdfError(e) => write!(f, "pdf error: {}", e),
            ExtractPdfError::Utf8Error(e) => write!(f, "utf8 error: {}", e),
            ExtractPdfError::ExternalToolError(s_err) => write!(f, "external tool error: {}", s_err),
        }
    }
}

impl std::error::Error for ExtractPdfError {}

impl From<std::io::Error> for ExtractPdfError {
    fn from(e: std::io::Error) -> Self {
        ExtractPdfError::IoError(e)
    }
}

impl From<lopdf::Error> for ExtractPdfError {
    fn from(e: lopdf::Error) -> Self {
        ExtractPdfError::PdfError(e)
    }
}

impl From<std::string::FromUtf8Error> for ExtractPdfError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        ExtractPdfError::Utf8Error(e)
    }
}

#[derive(Debug, Default)]
pub struct ExtractPdfReport {
    pub s_text: String,
    pub v_warnings: Vec<String>,
    pub i_pages_total: i32,
    pub i_pages_ok_text: i32,
    pub i_pages_ok_ocr: i32,
    pub i_pages_skipped: i32,
    pub b_document_persisted: bool,
    pub p_output_dir: Option<PathBuf>,
}

/* ----------------------------------------------------------------------------
Central function: extract_pdf_text

Policy:
- Never panic from this module.
- Warnings are collected and do not prevent final output.
- If a page fails parsing or yields implausible text, OCR is attempted.
- If OCR fails, the page is skipped, but the document continues.

History (function-level):
    2026-01-14 (Marcus Schlieper):
        - Ensure document is indexable and persistable despite warnings.
---------------------------------------------------------------------------- */
pub fn extract_pdf_text(p_path: &Path) -> Result<ExtractPdfReport, ExtractPdfError> {
    validate_pdf_path(p_path)?;

    let mut doc = Document::load(p_path)?;
    if doc.is_encrypted() {
        if let Err(e) = doc.decrypt("") {
            return Err(ExtractPdfError::PdfError(e));
        }
    }

    let mut report = ExtractPdfReport::default();

    let pages = doc.get_pages();
    report.i_pages_total = pages.len() as i32;

    let mut v_page_nums: Vec<u32> = pages.keys().copied().collect();
    v_page_nums.sort_unstable();

    for u_page_num in v_page_nums {
        let object_id = match pages.get(&u_page_num) {
            Some(id) => *id,
            None => {
                report.i_pages_skipped += 1;
                report.v_warnings.push(format!(
                    "page {} skipped: missing object id",
                    u_page_num
                ));
                continue;
            }
        };

        let s_page_text_raw = match extract_text_single_page_best_effort(&doc, object_id, u_page_num) {
            Ok(s_text) => s_text,
            Err(s_warn) => {
                report.v_warnings.push(s_warn);
                String::new()
            }
        };

        let s_page_text = normalize_and_filter_page_text(&s_page_text_raw);

        if is_plausible_page_text(&s_page_text) {
            report.i_pages_ok_text += 1;
            append_page_text(&mut report.s_text, &s_page_text);
            continue;
        }

        match ocr_page_with_external_tools(p_path, u_page_num) {
            Ok(s_ocr_raw) => {
                let s_ocr = normalize_and_filter_page_text(&s_ocr_raw);
                if is_plausible_page_text(&s_ocr) {
                    report.i_pages_ok_ocr += 1;
                    append_page_text(&mut report.s_text, &s_ocr);
                } else {
                    report.i_pages_skipped += 1;
                    report.v_warnings.push(format!(
                        "page {} skipped: no plausible text from native extraction and OCR returned empty or implausible text",
                        u_page_num
                    ));
                }
            }
            Err(e) => {
                report.i_pages_skipped += 1;
                report.v_warnings.push(format!(
                    "page {} skipped: OCR failed: {}",
                    u_page_num, e
                ));
            }
        }
    }

    Ok(report)
}

fn append_page_text(s_target: &mut String, s_page_text: &str) {
    s_target.push_str(s_page_text);
    if !s_target.ends_with('\n') {
        s_target.push('\n');
    }
}

/* ----------------------------------------------------------------------------
New: persist_index_artifacts

This function guarantees that the pipeline writes output artifacts even if the
PDF parsing produced warnings. The function is intended to be called after
extract_pdf_text().

Artifacts:
- extracted_text.txt: the text used for indexing
- extract_report.json: structured report for audit/troubleshooting

Behavior:
- Always writes both files when a writable output directory is provided.
- Does not fail the indexing pipeline if the text is empty; it still persists
  a report and an empty text file (for traceability).

History (function-level):
    2026-01-14 (Marcus Schlieper):
        - Add persistent output artifacts to ensure indexing despite warnings.
---------------------------------------------------------------------------- */
pub fn persist_index_artifacts(
    p_pdf_path: &Path,
    p_output_base_dir: &Path,
    report: &mut ExtractPdfReport,
) -> Result<(), ExtractPdfError> {
    validate_pdf_path(p_pdf_path)?;
    validate_output_dir(p_output_base_dir)?;

    let s_doc_id = make_stable_doc_id_from_path(p_pdf_path);
    let p_out_dir = p_output_base_dir.join(s_doc_id);

    fs::create_dir_all(&p_out_dir)?;

    let p_text_file = p_out_dir.join("extracted_text.txt");
    let p_report_file = p_out_dir.join("extract_report.json");

    write_text_file(&p_text_file, &report.s_text)?;
    write_text_file(&p_report_file, &report_to_json(report, p_pdf_path))?;

    report.b_document_persisted = true;
    report.p_output_dir = Some(p_out_dir);

    Ok(())
}

fn write_text_file(p_file: &Path, s_content: &str) -> Result<(), ExtractPdfError> {
    let mut f = fs::File::create(p_file)?;
    f.write_all(s_content.as_bytes())?;
    f.flush()?;
    Ok(())
}

fn report_to_json(report: &ExtractPdfReport, p_pdf_path: &Path) -> String {
    let s_pdf = json_escape(&p_pdf_path.display().to_string());
    let s_text_len = report.s_text.len().to_string();

    let mut s_warn = String::new();
    s_warn.push('[');
    for (i_idx, s_w) in report.v_warnings.iter().enumerate() {
        if i_idx > 0 {
            s_warn.push(',');
        }
        s_warn.push('"');
        s_warn.push_str(&json_escape(s_w));
        s_warn.push('"');
    }
    s_warn.push(']');

    format!(
        "{{\
\"pdf_path\":\"{s_pdf}\",\
\"pages_total\":{i_pages_total},\
\"pages_ok_text\":{i_pages_ok_text},\
\"pages_ok_ocr\":{i_pages_ok_ocr},\
\"pages_skipped\":{i_pages_skipped},\
\"text_len\":{s_text_len},\
\"document_persisted\":{b_persisted},\
\"warnings\":{s_warn}\
}}",
        s_pdf = s_pdf,
        i_pages_total = report.i_pages_total,
        i_pages_ok_text = report.i_pages_ok_text,
        i_pages_ok_ocr = report.i_pages_ok_ocr,
        i_pages_skipped = report.i_pages_skipped,
        s_text_len = s_text_len,
        b_persisted = if report.b_document_persisted { "true" } else { "false" },
        s_warn = s_warn
    )
}

fn json_escape(s_in: &str) -> String {
    let mut s_out = String::new();
    for c in s_in.chars() {
        match c {
            '\\' => s_out.push_str("\\\\"),
            '"' => s_out.push_str("\\\""),
            '\n' => s_out.push_str("\\n"),
            '\r' => s_out.push_str("\\r"),
            '\t' => s_out.push_str("\\t"),
            _ => s_out.push(c),
        }
    }
    s_out
}

fn make_stable_doc_id_from_path(p_pdf_path: &Path) -> String {
    /*
    Stable, filesystem-safe id derived from filename.
    For stricter deduplication, this could be replaced by a SHA-256 of file bytes.
    */
    let s_name = p_pdf_path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("document.pdf");

    let mut s_out = String::new();
    for c in s_name.chars() {
        if c.is_ascii_alphanumeric() {
            s_out.push(c.to_ascii_lowercase());
        } else {
            s_out.push('_');
        }
    }

    if s_out.is_empty() {
        "document_pdf".to_string()
    } else {
        s_out
    }
}

/* ----------------------------------------------------------------------------
Per-page extraction (best effort)
- Isolated: returns warning string on failure.
- Conservative: collects literal PDF strings from Tj and TJ only.
---------------------------------------------------------------------------- */
fn extract_text_single_page_best_effort(
    doc: &Document,
    object_id: lopdf::ObjectId,
    u_page_num: u32,
) -> Result<String, String> {
    let v_content = match doc.get_page_content(object_id) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!(
                "page {} content parse failed: {}",
                u_page_num, e
            ));
        }
    };

    let content = match lopdf::content::Content::decode(&v_content) {
        Ok(c) => c,
        Err(_e) => {
            return Err(format!(
                "page {} invalid content stream: InvalidContentStream",
                u_page_num
            ));
        }
    };

    let mut s_out = String::new();

    for op in &content.operations {
        match op.operator.as_ref() {
            "Tj" => {
                if op.operands.len() == 1 {
                    if let Ok(s_piece) = extract_pdf_string_operand_strict(&op.operands[0]) {
                        s_out.push_str(&s_piece);
                    }
                }
            }
            "TJ" => {
                if op.operands.len() == 1 {
                    if let Object::Array(ref v_arr) = op.operands[0] {
                        for o in v_arr {
                            if let Ok(s_piece) = extract_pdf_string_operand_strict(o) {
                                s_out.push_str(&s_piece);
                            }
                        }
                    }
                }
            }
            "Td" | "TD" | "Tm" | "T*" => {
                if !s_out.ends_with('\n') && !s_out.is_empty() {
                    s_out.push('\n');
                }
            }
            _ => {}
        }
    }

    Ok(s_out)
}

/* ----------------------------------------------------------------------------
Strict extraction of a PDF string operand.
Key change:
- No byte-to-char fallback.
- If bytes are not valid UTF-8, the operand is discarded (Err).
---------------------------------------------------------------------------- */
fn extract_pdf_string_operand_strict(o: &Object) -> Result<String, ()> {
    match o {
        Object::String(v_bytes, _fmt) => match String::from_utf8(v_bytes.clone()) {
            Ok(s_ok) => Ok(s_ok),
            Err(_) => Err(()),
        },
        _ => Err(()),
    }
}

/* ----------------------------------------------------------------------------
Normalization and filtering:
- Remove control characters (except newline and tab).
- Collapse excessive whitespace.
- Remove lines likely to be gibberish (symbol-heavy).
---------------------------------------------------------------------------- */
fn normalize_and_filter_page_text(s_in: &str) -> String {
    let mut s_clean = String::new();
    for c in s_in.chars() {
        if c == '\n' || c == '\t' {
            s_clean.push(c);
            continue;
        }
        if c.is_control() {
            continue;
        }
        s_clean.push(c);
    }

    let mut v_lines_out: Vec<String> = Vec::new();
    for s_line in s_clean.lines() {
        let s_line_trim = s_line.trim();
        if s_line_trim.is_empty() {
            continue;
        }
        if is_gibberish_line(s_line_trim) {
            continue;
        }
        v_lines_out.push(collapse_whitespace(s_line_trim));
    }

    v_lines_out.join("\n")
}

fn is_gibberish_line(s_line: &str) -> bool {
    let i_len: i32 = s_line.chars().count() as i32;
    if i_len <= 0 {
        return true;
    }

    let mut i_alpha_num: i32 = 0;
    let mut i_printable: i32 = 0;
    let mut i_symbol: i32 = 0;
    let mut i_max_symbol_run: i32 = 0;
    let mut i_cur_symbol_run: i32 = 0;

    for c in s_line.chars() {
        if c.is_control() {
            continue;
        }
        i_printable += 1;

        if c.is_alphanumeric() {
            i_alpha_num += 1;
            i_cur_symbol_run = 0;
        } else if c.is_ascii_punctuation() || is_common_symbol(c) {
            i_symbol += 1;
            i_cur_symbol_run += 1;
            if i_cur_symbol_run > i_max_symbol_run {
                i_max_symbol_run = i_cur_symbol_run;
            }
        } else {
            i_cur_symbol_run = 0;
        }
    }

    if i_printable <= 0 {
        return true;
    }

    let d_alpha_ratio: f64 = (i_alpha_num as f64) / (i_printable as f64);
    let d_symbol_ratio: f64 = (i_symbol as f64) / (i_printable as f64);

    if d_alpha_ratio < 0.20 && i_printable >= 10 {
        return true;
    }
    if d_symbol_ratio > 0.70 && i_printable >= 10 {
        return true;
    }
    if i_max_symbol_run >= 12 {
        return true;
    }

    false
}

fn is_common_symbol(c: char) -> bool {
    match c {
        '%' | '&' | '*' | '+' | '-' | '/' | '=' | '<' | '>' | '@' | '#' | '$' | '"' | '\''
        | '(' | ')' | '[' | ']' | '{' | '}' | '!' | '?' | ':' | ';' | ',' | '.' => true,
        _ => false,
    }
}

fn collapse_whitespace(s_in: &str) -> String {
    let mut s_out = String::new();
    let mut b_last_space = false;

    for c in s_in.chars() {
        if c.is_whitespace() {
            if !b_last_space {
                s_out.push(' ');
                b_last_space = true;
            }
        } else {
            s_out.push(c);
            b_last_space = false;
        }
    }

    s_out.trim().to_string()
}

fn is_plausible_page_text(s_text: &str) -> bool {
    if s_text.trim().is_empty() {
        return false;
    }

    let i_len: i32 = s_text.chars().count() as i32;
    if i_len < 5 {
        return false;
    }

    let mut i_alpha_num: i32 = 0;
    let mut i_printable: i32 = 0;

    for c in s_text.chars() {
        if c.is_control() && c != '\n' && c != '\t' {
            continue;
        }
        if !c.is_control() {
            i_printable += 1;
        }
        if c.is_alphanumeric() {
            i_alpha_num += 1;
        }
    }

    if i_printable <= 0 {
        return false;
    }

    let d_alpha_ratio: f64 = (i_alpha_num as f64) / (i_printable as f64);
    if d_alpha_ratio < 0.15 && i_printable >= 40 {
        return false;
    }

    true
}

/* ----------------------------------------------------------------------------
OCR: rasterize a single page and run tesseract.
---------------------------------------------------------------------------- */
fn ocr_page_with_external_tools(p_pdf_path: &Path, u_page_num: u32) -> Result<String, ExtractPdfError> {
    let p_tmp_dir = make_temp_dir("pdf_ocr")?;
    let s_prefix = format!("page_{}", u_page_num);
    let p_prefix = p_tmp_dir.join(&s_prefix);

    let mut cmd_ppm = Command::new("pdftoppm");
    cmd_ppm
        .arg("-f").arg(u_page_num.to_string())
        .arg("-l").arg(u_page_num.to_string())
        .arg("-r").arg("300")
        .arg("-png")
        .arg(p_pdf_path)
        .arg(&p_prefix);

    let out_ppm = cmd_ppm.output().map_err(|e| {
        ExtractPdfError::ExternalToolError(format!("pdftoppm failed to start: {}", e))
    })?;

    if !out_ppm.status.success() {
        let s_stderr = String::from_utf8(out_ppm.stderr)?;
        let _ = fs::remove_dir_all(&p_tmp_dir);
        return Err(ExtractPdfError::ExternalToolError(format!(
            "pdftoppm failed for page {}: {}",
            u_page_num,
            sanitize_single_line(&s_stderr)
        )));
    }

    let p_png = p_tmp_dir.join(format!("{}-1.png", s_prefix));
    if !p_png.exists() {
        let _ = fs::remove_dir_all(&p_tmp_dir);
        return Err(ExtractPdfError::ExternalToolError(format!(
            "pdftoppm did not produce expected output file: {}",
            p_png.display()
        )));
    }

    let mut cmd_ocr = Command::new("tesseract");
    cmd_ocr
        .arg(&p_png)
        .arg("stdout")
        .arg("-l")
        .arg("deu+eng");

    let out_ocr = cmd_ocr.output().map_err(|e| {
        ExtractPdfError::ExternalToolError(format!("tesseract failed to start: {}", e))
    })?;

    if !out_ocr.status.success() {
        let s_stderr = String::from_utf8(out_ocr.stderr)?;
        let _ = fs::remove_dir_all(&p_tmp_dir);
        return Err(ExtractPdfError::ExternalToolError(format!(
            "tesseract failed for page {}: {}",
            u_page_num,
            sanitize_single_line(&s_stderr)
        )));
    }

    let s_text = String::from_utf8(out_ocr.stdout)?;

    let _ = fs::remove_dir_all(&p_tmp_dir);
    Ok(s_text)
}

/* ----------------------------------------------------------------------------
Validation helpers
---------------------------------------------------------------------------- */
fn validate_pdf_path(p_path: &Path) -> Result<(), ExtractPdfError> {
    if !p_path.exists() {
        return Err(ExtractPdfError::ExternalToolError(format!(
            "input pdf path does not exist: {}",
            p_path.display()
        )));
    }
    if !p_path.is_file() {
        return Err(ExtractPdfError::ExternalToolError(format!(
            "input pdf path is not a file: {}",
            p_path.display()
        )));
    }
    let ext = p_path.extension().and_then(OsStr::to_str).unwrap_or("");
    if ext.to_ascii_lowercase() != "pdf" {
        return Err(ExtractPdfError::ExternalToolError(format!(
            "input file extension is not pdf: {}",
            p_path.display()
        )));
    }
    Ok(())
}

fn validate_output_dir(p_output_dir: &Path) -> Result<(), ExtractPdfError> {
    if !p_output_dir.exists() {
        return Err(ExtractPdfError::ExternalToolError(format!(
            "output base dir does not exist: {}",
            p_output_dir.display()
        )));
    }
    if !p_output_dir.is_dir() {
        return Err(ExtractPdfError::ExternalToolError(format!(
            "output base dir is not a directory: {}",
            p_output_dir.display()
        )));
    }
    Ok(())
}

fn make_temp_dir(s_prefix: &str) -> Result<PathBuf, ExtractPdfError> {
    let p_base = std::env::temp_dir();
    let s_dir = format!(
        "{}_{}_{}",
        s_prefix,
        std::process::id(),
        current_time_nanos_best_effort()
    );
    let p_dir = p_base.join(s_dir);
    fs::create_dir_all(&p_dir)?;
    Ok(p_dir)
}

fn current_time_nanos_best_effort() -> u128 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_nanos(),
        Err(_) => 0u128,
    }
}

fn sanitize_single_line(s: &str) -> String {
    let mut s_out = String::new();
    for c in s.chars() {
        if c == '\r' || c == '\n' {
            s_out.push(' ');
        } else {
            s_out.push(c);
        }
    }
    s_out.trim().to_string()
}