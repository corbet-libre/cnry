//! Terminal renderer: two pixels per character cell using half blocks, in
//! 24-bit colour or the 256-colour palette.

use crate::scene::{self, Grid, Rgb};
use std::fmt::Write;

/// How colours are written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorMode {
    /// `ESC[38;2;r;g;bm`.
    TrueColor,
    /// `ESC[38;5;nm`, nearest xterm colour.
    Ansi256,
}

impl ColorMode {
    /// True colour when `COLORTERM` says `truecolor` or `24bit`, else 256.
    pub fn detect() -> Self {
        match std::env::var("COLORTERM") {
            Ok(v) if v == "truecolor" || v == "24bit" => ColorMode::TrueColor,
            _ => ColorMode::Ansi256,
        }
    }
}

/// Nearest xterm-256 index (6x6x6 cube or the grey ramp).
pub fn xterm256((r, g, b): Rgb) -> u8 {
    let level = |v: u8| -> u8 {
        if v < 48 {
            0
        } else if v < 115 {
            1
        } else {
            (v - 35) / 40
        }
    };
    let cube = |l: u8| -> i32 { if l == 0 { 0 } else { 55 + 40 * i32::from(l) } };
    let (lr, lg, lb) = (level(r), level(g), level(b));
    let ci = 16 + 36 * lr + 6 * lg + lb;
    let dist = |c: (i32, i32, i32)| {
        let (dr, dg, db) = (c.0 - i32::from(r), c.1 - i32::from(g), c.2 - i32::from(b));
        dr * dr + dg * dg + db * db
    };
    let cube_d = dist((cube(lr), cube(lg), cube(lb)));
    let avg = (i32::from(r) + i32::from(g) + i32::from(b)) / 3;
    let gi = ((avg - 8 + 5) / 10).clamp(0, 23);
    let gv = 8 + 10 * gi;
    if dist((gv, gv, gv)) < cube_d {
        232 + gi as u8
    } else {
        ci
    }
}

fn color(out: &mut String, mode: ColorMode, fg: bool, c: Rgb) {
    let base = if fg { 38 } else { 48 };
    match mode {
        ColorMode::TrueColor => write!(out, "\x1b[{base};2;{};{};{}m", c.0, c.1, c.2),
        ColorMode::Ansi256 => write!(out, "\x1b[{base};5;{}m", xterm256(c)),
    }
    .expect("writing to a String cannot fail");
}

/// Draw a grid as text lines (no trailing newline), each ending in a reset.
pub fn draw(grid: &Grid, mode: ColorMode) -> String {
    let mut out = String::new();
    for y in (0..grid.h).step_by(2) {
        for x in 0..grid.w {
            match (grid.get(x, y), grid.get(x, y + 1)) {
                (None, None) => out.push_str("\x1b[0m "),
                (Some(t), None) => {
                    out.push_str("\x1b[0m");
                    color(&mut out, mode, true, t);
                    out.push('▀');
                }
                (None, Some(b)) => {
                    out.push_str("\x1b[0m");
                    color(&mut out, mode, true, b);
                    out.push('▄');
                }
                (Some(t), Some(b)) => {
                    color(&mut out, mode, true, t);
                    color(&mut out, mode, false, b);
                    out.push('▀');
                }
            }
        }
        out.push_str("\x1b[0m");
        if y + 2 < grid.h {
            out.push('\n');
        }
    }
    out
}

/// One animation frame, `t` seconds into the state. Present: the bird on a
/// gently swinging seat. Absent: an empty swing coming to rest.
pub fn frame(present: bool, t: f64, mode: ColorMode) -> String {
    draw(&scene::compose(present, t), mode)
}
