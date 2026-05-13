/*------------------------------------------------------------------------------
File: pdf_text_extractor.rs
Description:
    Robust PDF text extraction module.

    Scope:
    - Only text extraction from PDF is required
    - All non text artifacts are ignored
    - Native extraction via lopdf is primary
    - OCR fallback via pdftoppm and tesseract is optional
    - Encrypted PDFs are detected
    - Errors are returned safely without panic

    Notes:
    - Some PDFs have broken font encodings
    - Some PDFs are image only and need OCR
    - Some PDFs are encrypted and may not allow text extraction

History:
    2026-05-12 (Marcus Schlieper):
        - Initial robust text only module.
        - Added lopdf native extraction.
        - Added encrypted PDF handling.
        - Added OCR fallback.
        - Added safe validation and error handling.
------------------------------------------------------------------------------*/

use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::process::Command;

use lopdf::Document;

/*------------------------------------------------------------------------------
Type: ExtractPdfError

Description:
    Error type for all extraction related failures.
------------------------------------------------------------------------------*/
#[derive(Debug)]
pub enum ExtractPdfError {
    IoError(std::io::Error),
    ExternalToolError(String),
    ExtractError(String),
}

impl std::fmt::Display for ExtractPdfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtractPdfError::IoError(e_err) => write!(f, "io error: {}", e_err),
            ExtractPdfError::ExternalToolError(s_err) => {
                write!(f, "external tool error: {}", s_err)
            }
            ExtractPdfError::ExtractError(s_err) => write!(f, "extract error: {}", s_err),
        }
    }
}

impl std::error::Error for ExtractPdfError {}

impl From<std::io::Error> for ExtractPdfError {
    fn from(e_err: std::io::Error) -> Self {
        ExtractPdfError::IoError(e_err)
    }
}

/*------------------------------------------------------------------------------
Type: ExtractPdfReport

Description:
    Result report for one PDF extraction run.
------------------------------------------------------------------------------*/
#[derive(Debug, Default, Clone)]
pub struct ExtractPdfReport {
    pub s_text: String,
    pub v_warnings: Vec<String>,
    pub i_pages_total: i32,
    pub i_pages_ok_text: i32,
    pub i_pages_ok_ocr: i32,
    pub i_pages_skipped: i32,
    pub b_is_encrypted: bool,
    pub b_decryption_ok: bool,
    pub b_used_ocr_fallback: bool,
}

/*------------------------------------------------------------------------------
Central function: extract_pdf_text

Description:
    Extract text from a PDF.

Policy:
    - Never panic from this module
    - Native extraction via lopdf is tried first
    - If native extraction is empty or implausible, OCR fallback is tried
    - Only extracted text matters
    - No extra artifacts are written

History:
    2026-05-12 (Marcus Schlieper):
        - Initial robust text only implementation.
        - Added native extraction and OCR fallback.
------------------------------------------------------------------------------*/
pub fn extract_pdf_text(p_path: &Path) -> Result<ExtractPdfReport, ExtractPdfError> {
    validate_pdf_path(p_path)?;

    let mut report = ExtractPdfReport::default();

    match extract_text_with_lopdf(p_path) {
        Ok((s_text_raw, i_pages_total, b_is_encrypted, b_decryption_ok)) => {
            report.i_pages_total = i_pages_total;
            report.b_is_encrypted = b_is_encrypted;
            report.b_decryption_ok = b_decryption_ok;

            let s_text_clean = normalize_text(&s_text_raw);

            if is_plausible_text(&s_text_clean) {
                report.s_text = s_text_clean;
                report.i_pages_ok_text = if i_pages_total > 0 { i_pages_total } else { 1 };
                return Ok(report);
            }

            report.v_warnings.push(
                "native extraction returned empty or implausible text".to_string(),
            );
        }
        Err(e_err) => {
            report
                .v_warnings
                .push(format!("native extraction failed: {}", e_err));
        }
    }

    ensure_tool_exists("pdftoppm")?;
    ensure_tool_exists("tesseract")?;

    if report.i_pages_total <= 0 {
        report.i_pages_total = get_pdf_page_count_with_lopdf(p_path).unwrap_or(0);
    }

    if report.i_pages_total <= 0 {
        report
            .v_warnings
            .push("page count unknown, ocr fallback cannot continue safely".to_string());
        report.i_pages_skipped = 1;
        return Ok(report);
    }

    report.b_used_ocr_fallback = true;

    let mut s_ocr_text = String::new();

    for i_page_num in 1..=report.i_pages_total {
        match ocr_page_with_external_tools(p_path, i_page_num as u32) {
            Ok(s_page_raw) => {
                let s_page_clean = normalize_text(&s_page_raw);

                if is_plausible_text(&s_page_clean) {
                    append_text_block(&mut s_ocr_text, &s_page_clean);
                    report.i_pages_ok_ocr += 1;
                } else {
                    report.i_pages_skipped += 1;
                    report.v_warnings.push(format!(
                        "page {} skipped: ocr returned empty or implausible text",
                        i_page_num
                    ));
                }
            }
            Err(e_err) => {
                report.i_pages_skipped += 1;
                report
                    .v_warnings
                    .push(format!("page {} skipped: ocr failed: {}", i_page_num, e_err));
            }
        }
    }

    report.s_text = s_ocr_text;

    Ok(report)
}

/*------------------------------------------------------------------------------
Function: extract_text_with_lopdf

Description:
    Load a PDF with lopdf and extract text from all pages.

Encrypted PDF handling:
    - Detect encrypted documents
    - Continue only if decryption state is available
------------------------------------------------------------------------------*/
fn extract_text_with_lopdf(
    p_pdf_path: &Path,
) -> Result<(String, i32, bool, bool), ExtractPdfError> {
    let doc = Document::load(p_pdf_path)
        .map_err(|e_err| ExtractPdfError::ExtractError(format!("lopdf load failed: {}", e_err)))?;

    let b_is_encrypted = doc.is_encrypted();
    let b_decryption_ok = if b_is_encrypted {
        doc.encryption_state.is_some()
    } else {
        true
    };

    if b_is_encrypted && !b_decryption_ok {
        return Err(ExtractPdfError::ExtractError(
            "pdf is encrypted and automatic decryption is not available".to_string(),
        ));
    }

    let m_pages = doc.get_pages();
    let i_pages_total = m_pages.len() as i32;

    if m_pages.is_empty() {
        return Ok((String::new(), 0, b_is_encrypted, b_decryption_ok));
    }

    let v_page_nums: Vec<u32> = m_pages.keys().cloned().collect();


    let s_text = doc.extract_text(&v_page_nums).map_err(|e_err| {
        ExtractPdfError::ExtractError(format!("lopdf extract_text failed: {}", e_err))
    })?;

    Ok((s_text, i_pages_total, b_is_encrypted, b_decryption_ok))
}

/*------------------------------------------------------------------------------
Function: get_pdf_page_count_with_lopdf

Description:
    Read page count with lopdf.
------------------------------------------------------------------------------*/
fn get_pdf_page_count_with_lopdf(p_pdf_path: &Path) -> Result<i32, ExtractPdfError> {
    let doc = Document::load(p_pdf_path)
        .map_err(|e_err| ExtractPdfError::ExtractError(format!("lopdf load failed: {}", e_err)))?;

    Ok(doc.get_pages().len() as i32)
}

/*------------------------------------------------------------------------------
Function: ocr_page_with_external_tools

Description:
    OCR one page by rendering it to PNG and sending it to tesseract.
------------------------------------------------------------------------------*/
fn ocr_page_with_external_tools(
    p_pdf_path: &Path,
    u_page_num: u32,
) -> Result<String, ExtractPdfError> {
    let p_tmp_dir = make_temp_dir("pdf_ocr")?;
    let s_prefix = format!("page_{}", u_page_num);
    let p_prefix = p_tmp_dir.join(&s_prefix);

    let out_ppm = Command::new("pdftoppm")
        .arg("-f")
        .arg(u_page_num.to_string())
        .arg("-l")
        .arg(u_page_num.to_string())
        .arg("-r")
        .arg("300")
        .arg("-png")
        .arg(p_pdf_path)
        .arg(&p_prefix)
        .output()
        .map_err(|e_err| {
            ExtractPdfError::ExternalToolError(format!(
                "pdftoppm failed to start: {}",
                e_err
            ))
        })?;

    if !out_ppm.status.success() {
        let s_stderr = String::from_utf8_lossy(&out_ppm.stderr).to_string();
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

    let out_ocr = Command::new("tesseract")
        .arg(&p_png)
        .arg("stdout")
        .arg("-l")
        .arg("deu+eng")
        .output()
        .map_err(|e_err| {
            ExtractPdfError::ExternalToolError(format!(
                "tesseract failed to start: {}",
                e_err
            ))
        })?;

    if !out_ocr.status.success() {
        let s_stderr = String::from_utf8_lossy(&out_ocr.stderr).to_string();
        let _ = fs::remove_dir_all(&p_tmp_dir);

        return Err(ExtractPdfError::ExternalToolError(format!(
            "tesseract failed for page {}: {}",
            u_page_num,
            sanitize_single_line(&s_stderr)
        )));
    }

    let s_text = String::from_utf8_lossy(&out_ocr.stdout).to_string();
    let _ = fs::remove_dir_all(&p_tmp_dir);

    Ok(s_text)
}

/*------------------------------------------------------------------------------
Function: validate_pdf_path

Description:
    Validate the input PDF path.
------------------------------------------------------------------------------*/
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

    let s_ext = p_path.extension().and_then(OsStr::to_str).unwrap_or("");

    if s_ext.to_ascii_lowercase() != "pdf" {
        return Err(ExtractPdfError::ExternalToolError(format!(
            "input file extension is not pdf: {}",
            p_path.display()
        )));
    }

    Ok(())
}

/*------------------------------------------------------------------------------
Function: ensure_tool_exists

Description:
    Check whether an external tool is available.
------------------------------------------------------------------------------*/
fn ensure_tool_exists(s_tool_name: &str) -> Result<(), ExtractPdfError> {
    let out = Command::new(s_tool_name).arg("--version").output();

    match out {
        Ok(_) => Ok(()),
        Err(e_err) => Err(ExtractPdfError::ExternalToolError(format!(
            "required tool is missing or not executable: {}: {}",
            s_tool_name, e_err
        ))),
    }
}

/*------------------------------------------------------------------------------
Function: normalize_text

Description:
    Clean extracted text for downstream use.
------------------------------------------------------------------------------*/
fn normalize_text(s_in: &str) -> String {
    let mut s_clean = String::new();

    for c_char in s_in.chars() {
        if c_char == '\n' || c_char == '\t' {
            s_clean.push(c_char);
            continue;
        }

        if c_char.is_control() {
            continue;
        }

        s_clean.push(c_char);
    }

    let mut v_lines_out: Vec<String> = Vec::new();

    for s_line in s_clean.lines() {
        let s_trim = collapse_whitespace(s_line.trim());

        if s_trim.is_empty() {
            continue;
        }

        if is_gibberish_line(&s_trim) {
            continue;
        }

        v_lines_out.push(s_trim);
    }

    v_lines_out.join("\n")
}

/*------------------------------------------------------------------------------
Function: is_plausible_text

Description:
    Best effort plausibility check for extracted text.
------------------------------------------------------------------------------*/
fn is_plausible_text(s_text: &str) -> bool {
    if s_text.trim().is_empty() {
        return false;
    }

    let i_len: i32 = s_text.chars().count() as i32;
    if i_len < 5 {
        return false;
    }

    let mut i_alpha_num: i32 = 0;
    let mut i_printable: i32 = 0;

    for c_char in s_text.chars() {
        if c_char.is_control() && c_char != '\n' && c_char != '\t' {
            continue;
        }

        if !c_char.is_control() {
            i_printable += 1;
        }

        if c_char.is_alphanumeric() {
            i_alpha_num += 1;
        }
    }

    if i_printable <= 0 {
        return false;
    }

    let d_alpha_ratio = (i_alpha_num as f64) / (i_printable as f64);

    if d_alpha_ratio < 0.15 && i_printable >= 40 {
        return false;
    }

    true
}

/*------------------------------------------------------------------------------
Function: is_gibberish_line

Description:
    Filter lines that look like broken extraction noise.
------------------------------------------------------------------------------*/
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

    for c_char in s_line.chars() {
        if c_char.is_control() {
            continue;
        }

        i_printable += 1;

        if c_char.is_alphanumeric() {
            i_alpha_num += 1;
            i_cur_symbol_run = 0;
        } else if c_char.is_ascii_punctuation() || is_common_symbol(c_char) {
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

    let d_alpha_ratio = (i_alpha_num as f64) / (i_printable as f64);
    let d_symbol_ratio = (i_symbol as f64) / (i_printable as f64);

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

/*------------------------------------------------------------------------------
Function: collapse_whitespace

Description:
    Reduce multiple whitespace characters to single spaces.
------------------------------------------------------------------------------*/
fn collapse_whitespace(s_in: &str) -> String {
    let mut s_out = String::new();
    let mut b_last_space = false;

    for c_char in s_in.chars() {
        if c_char.is_whitespace() {
            if !b_last_space {
                s_out.push(' ');
                b_last_space = true;
            }
        } else {
            s_out.push(c_char);
            b_last_space = false;
        }
    }

    s_out.trim().to_string()
}

/*------------------------------------------------------------------------------
Function: append_text_block

Description:
    Append one text block with normalized newline handling.
------------------------------------------------------------------------------*/
fn append_text_block(s_target: &mut String, s_block: &str) {
    if s_block.trim().is_empty() {
        return;
    }

    if !s_target.is_empty() && !s_target.ends_with('\n') {
        s_target.push('\n');
    }

    s_target.push_str(s_block);

    if !s_target.ends_with('\n') {
        s_target.push('\n');
    }
}

/*------------------------------------------------------------------------------
Function: is_common_symbol

Description:
    Symbol helper used by gibberish detection.
------------------------------------------------------------------------------*/
fn is_common_symbol(c_char: char) -> bool {
    matches!(
        c_char,
        '%'
            | '&'
            | '*'
            | '+'
            | '-'
            | '/'
            | '='
            | '<'
            | '>'
            | '@'
            | '#'
            | '$'
            | '"'
            | '\''
            | '('
            | ')'
            | '['
            | ']'
            | '{'
            | '}'
            | '!'
            | '?'
            | ':'
            | ';'
            | ','
            | '.'
    )
}

/*------------------------------------------------------------------------------
Function: make_temp_dir

Description:
    Create a temporary directory for OCR work files.
------------------------------------------------------------------------------*/
fn make_temp_dir(s_prefix: &str) -> Result<std::path::PathBuf, ExtractPdfError> {
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

/*------------------------------------------------------------------------------
Function: current_time_nanos_best_effort

Description:
    Best effort timestamp helper for temp directory naming.
------------------------------------------------------------------------------*/
fn current_time_nanos_best_effort() -> u128 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d_duration) => d_duration.as_nanos(),
        Err(_) => 0u128,
    }
}

/*------------------------------------------------------------------------------
Function: sanitize_single_line

Description:
    Convert multi line stderr output into a single loggable line.
------------------------------------------------------------------------------*/
fn sanitize_single_line(s_in: &str) -> String {
    let mut s_out = String::new();

    for c_char in s_in.chars() {
        if c_char == '\r' || c_char == '\n' {
            s_out.push(' ');
        } else {
            s_out.push(c_char);
        }
    }

    s_out.trim().to_string()
}
