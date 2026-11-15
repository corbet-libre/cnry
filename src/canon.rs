//! RFC 8785 (JSON Canonicalization Scheme) for the subset `cnry/1` uses.
//!
//! The format contains only objects, arrays, strings, booleans, null and
//! integers, so number serialisation is the plain decimal integer; a
//! floating-point number is refused instead of risking a different canonical
//! form in another implementation.

use serde_json::Value;
use std::fmt;

/// Why a value cannot be canonicalised.
#[derive(Debug, PartialEq, Eq)]
pub struct CanonError(pub &'static str);

impl fmt::Display for CanonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for CanonError {}

/// Canonical JSON text of `value`: no whitespace, object members sorted by
/// UTF-16 code units of their names, minimal string escapes.
pub fn canonicalize(value: &Value) -> Result<String, CanonError> {
    let mut out = String::new();
    write(value, &mut out)?;
    Ok(out)
}

fn write(value: &Value, out: &mut String) -> Result<(), CanonError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                return Err(CanonError("non-integer number"));
            }
        }
        // serde_json escapes `"`, `\`, the short forms \b \t \n \f \r and the
        // other control characters as lowercase \u00xx, exactly as RFC 8785
        // section 3.2.2.2 requires; everything else is emitted verbatim.
        Value::String(s) => {
            out.push_str(&serde_json::to_string(s).map_err(|_| CanonError("string"))?)
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut members: Vec<(&String, &Value)> = map.iter().collect();
            members.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push('{');
            for (i, (k, v)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).map_err(|_| CanonError("key"))?);
                out.push(':');
                write(v, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}
