/* ============================================================================
File: pdf_text_extractor.rs
Description:
    Robust PDF text extraction with per-page error isolation and OCR fallback.
    Output policy: only plausible text is emitted. Garbled output is suppressed.

History:
    2026-01-12:
        - Initial version with per-page isolation and OCR fallback.
    2026-01-12:
        - Enforce "text only" policy:
          * Remove unsafe byte-to-char fallback that produced gibberish.
          * Add gibberish filtering and line sanitization.
          * Trigger OCR when extracted text is empty or implausible.

Author: Marcus Schlieper
============================================================================ */

/* Notes (ASCII only):
- External OCR tooling:
  - pdftoppm (Poppler) for rasterization
  - tesseract for OCR
- This module does not panic on page parse errors.
- Naming:
  - snake_case everywhere
  - i_ prefix for integers
  - d_ prefix for doubles
  - s_ prefix for strings
*/

use std::ffi::OsStr;
use std::fs;
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
}

/* ----------------------------------------------------------------------------
Central function: extract_pdf_text

Policy:
- Never panic.
- Parse errors are isolated per page.
- Only plausible text is appended to output.
- If a page yields empty or implausible text, OCR is attempted.

History (function-level):
    2026-01-12:
        - Adds "text only" output enforcement using gibberish filters.
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
            report.s_text.push_str(&s_page_text);
            if !report.s_text.ends_with('\n') {
                report.s_text.push('\n');
            }
            continue;
        }

        match ocr_page_with_external_tools(p_path, u_page_num) {
            Ok(s_ocr_raw) => {
                let s_ocr = normalize_and_filter_page_text(&s_ocr_raw);
                if is_plausible_page_text(&s_ocr) {
                    report.i_pages_ok_ocr += 1;
                    report.s_text.push_str(&s_ocr);
                    if !report.s_text.ends_with('\n') {
                        report.s_text.push('\n');
                    }
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

/* ----------------------------------------------------------------------------
Per-page extraction (best effort)
- Isolated: returns warning string on failure.
- Conservative: only collects literal PDF strings from Tj and TJ.
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

Rationale:
- Prevents gibberish output like sequences of punctuation or random ASCII.
---------------------------------------------------------------------------- */
fn extract_pdf_string_operand_strict(o: &Object) -> Result<String, ()> {
    match o {
        Object::String(v_bytes, _fmt) => {
            match String::from_utf8(v_bytes.clone()) {
                Ok(s_ok) => Ok(s_ok),
                Err(_) => Err(()),
            }
        }
        _ => Err(()),
    }
}

/* ----------------------------------------------------------------------------
Normalization and filtering:
- Remove control characters (except newline and tab).
- Collapse excessive whitespace.
- Remove lines that are very likely gibberish (symbol-heavy).
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

/* ----------------------------------------------------------------------------
Heuristic gibberish detector for single lines.
The intent is to drop lines like:
!"#$%&'(&)* + ... or similar symbol-only sequences.

Criteria (conservative):
- Require a minimal alphanumeric ratio.
- Reject long runs of punctuation/symbols.
---------------------------------------------------------------------------- */
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
        '%' | '&' | '*' | '+' | '-' | '/' | '=' | '<' | '>' | '@' | '#' | '$' | '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | '!' | '?' | ':' | ';' | ',' | '.' => true,
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

/* ----------------------------------------------------------------------------
Page-level plausibility check.
Used to decide if native extraction should be accepted or OCR should be used.
---------------------------------------------------------------------------- */
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
        return Err(ExtractPdfError::ExternalToolError(format!(
            "pdftoppm failed for page {}: {}",
            u_page_num,
            sanitize_single_line(&s_stderr)
        )));
    }

    let p_png = p_tmp_dir.join(format!("{}-1.png", s_prefix));
    if !p_png.exists() {
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
