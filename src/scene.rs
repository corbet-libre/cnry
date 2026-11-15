//! The canary scene as pixels: one sprite, a branch, a swing. Renderers (the
//! terminal here, the web component in `web/`) draw these same pixels; a test
//! checks that the sprite in `web/cnry-canary.js` is identical.

/// An RGB colour.
pub type Rgb = (u8, u8, u8);

/// Sprite rows: 24 x 18, `.` is transparent, letters index [`palette`].
pub const SPRITE: [&str; 18] = [
    "........................",
    "..............kkkk......",
    ".............kGGggk.....",
    "............kGgggggk....",
    "............kgggweggk...",
    "............kgggeegkooo.",
    "...........kgggggggkoo..",
    "..........kgggggggyk....",
    ".........kdddgggyyyyk...",
    "........kddddddgyyyyyk..",
    ".......kdddddddgyyyyyk..",
    "....kkkdddddddggyyyyyk..",
    "..kkgggkddddddggyyyyk...",
    ".kggk...kddddggggyyk....",
    ".kk......kkggggggkk.....",
    "...........kkkkkk.......",
    "............f..f........",
    "...........fff.fff......",
];

/// Palette letter to colour.
pub fn palette(c: char) -> Option<Rgb> {
    Some(match c {
        'k' => (0x22, 0x30, 0x1c),
        'g' => (0x7f, 0xb0, 0x46),
        'G' => (0xa6, 0xcf, 0x5e),
        'd' => (0x4e, 0x7a, 0x2f),
        'y' => (0xd3, 0xdf, 0x5c),
        'o' => (0xf0, 0xa0, 0x30),
        'e' => (0x0b, 0x0f, 0x0c),
        'w' => (0xff, 0xff, 0xff),
        'f' => (0xd0, 0x8a, 0x40),
        _ => return None,
    })
}

/// Scene width in pixels.
pub const WIDTH: usize = 64;
/// Branch height in pixels.
pub const BRANCH_H: usize = 5;
/// Swing width and height in pixels.
pub const SWING_W: usize = 32;
/// Swing height in pixels.
pub const SWING_H: usize = 36;
/// Scene height in pixels (branch plus swing).
pub const HEIGHT: usize = BRANCH_H + SWING_H;

const ROPE: Rgb = (0xcd, 0xb9, 0x8e);
const SEAT: Rgb = (0xe0, 0xb4, 0x7a);
const SEAT_EDGE: Rgb = (0xa7, 0x7c, 0x4a);
const BARK: Rgb = (0x9a, 0x6a, 0x45);
const BARK_DARK: Rgb = (0x6e, 0x4a, 0x30);
const LEAF: Rgb = (0x6a, 0xa8, 0x4f);

/// A grid of optional pixels.
#[derive(Clone)]
pub struct Grid {
    /// Width in pixels.
    pub w: usize,
    /// Height in pixels.
    pub h: usize,
    /// Row-major pixels; `None` is transparent.
    pub px: Vec<Option<Rgb>>,
}

impl Grid {
    fn new(w: usize, h: usize) -> Self {
        Grid {
            w,
            h,
            px: vec![None; w * h],
        }
    }
    fn set(&mut self, x: usize, y: usize, c: Rgb) {
        if x < self.w && y < self.h {
            self.px[y * self.w + x] = Some(c);
        }
    }
    /// The pixel at `(x, y)`, `None` when transparent or outside.
    pub fn get(&self, x: usize, y: usize) -> Option<Rgb> {
        if x < self.w && y < self.h {
            self.px[y * self.w + x]
        } else {
            None
        }
    }
}

/// The branch, 64 x 5.
pub fn branch() -> Grid {
    let mut g = Grid::new(WIDTH, BRANCH_H);
    for x in 0..WIDTH {
        let y = 2 + usize::from(x % 13 >= 6 && x % 13 < 9);
        g.set(x, y, BARK);
        g.set(x, y + 1, BARK_DARK);
    }
    for (x, y) in [(8, 0), (9, 1), (30, 0), (31, 0), (50, 1), (51, 0), (52, 1)] {
        g.set(x, y, LEAF);
        g.set(x, y + 1, LEAF);
    }
    g
}

/// What the swing carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pose {
    /// The bird sits on the seat.
    pub present: bool,
    /// The bird looks right (else left).
    pub facing_right: bool,
    /// The bird's eye is open.
    pub eye_open: bool,
}

/// The swing (ropes, seat and, if present, the bird), 32 x 36, unrotated.
pub fn swing(pose: Pose) -> Grid {
    let mut g = Grid::new(SWING_W, SWING_H);
    for y in 0..33 {
        g.set(3, y, ROPE);
        g.set(28, y, ROPE);
    }
    for x in 2..30 {
        g.set(x, 33, SEAT);
        g.set(x, 34, SEAT_EDGE);
    }
    if !pose.present {
        return g;
    }
    let (ox, oy) = (4, 15);
    for (r, row) in SPRITE.iter().enumerate() {
        for (cx, mut ch) in row.chars().enumerate() {
            if !pose.eye_open && r == 4 && (cx == 16 || cx == 17) {
                ch = 'g';
            }
            if !pose.eye_open && r == 5 && (cx == 16 || cx == 17) {
                ch = 'k';
            }
            if let Some(c) = palette(ch) {
                let x = if pose.facing_right {
                    ox + cx
                } else {
                    ox + (23 - cx)
                };
                g.set(x, oy + r, c);
            }
        }
    }
    g
}

/// Swing angle in degrees `t` seconds into a state. Present: a steady gentle
/// swing. Absent: the swing the bird left behind settles to rest within 8 s
/// and stays still.
pub fn angle(present: bool, t: f64) -> f64 {
    use std::f64::consts::TAU;
    if present {
        -5.0 * (TAU * t / 4.4).cos()
    } else if t >= 8.0 {
        0.0
    } else {
        -5.0 * (-t / 2.2).exp() * (TAU * t / 3.0).cos()
    }
}

/// The pose at time `t` (blink every 3.8 s for 0.18 s; look the other way
/// every 14 s). Deterministic, so every renderer can reproduce it.
pub fn pose(present: bool, t: f64) -> Pose {
    Pose {
        present,
        facing_right: (t / 14.0).floor() as i64 % 2 == 0,
        eye_open: t.rem_euclid(3.8) >= 0.18,
    }
}

/// The whole scene `t` seconds into a state: branch with the swing hung from
/// it, rotated about its rope attachment line.
pub fn compose(present: bool, t: f64) -> Grid {
    let mut out = Grid::new(WIDTH, HEIGHT);
    let b = branch();
    out.px[..WIDTH * BRANCH_H].copy_from_slice(&b.px);
    let s = swing(pose(present, t));
    let (sin, cos) = angle(present, t).to_radians().sin_cos();
    let (ax, ay) = (SWING_W as f64 / 2.0, 0.0);
    let off = (WIDTH - SWING_W) / 2;
    for y in 0..SWING_H {
        for x in 0..SWING_W {
            // Inverse map: which source pixel lands on (x, y).
            let (dx, dy) = (x as f64 + 0.5 - ax, y as f64 + 0.5 - ay);
            let (sx, sy) = (dx * cos + dy * sin + ax, -dx * sin + dy * cos + ay);
            if sx < 0.0 || sy < 0.0 {
                continue;
            }
            if let Some(c) = s.get(sx as usize, sy as usize) {
                out.set(off + x, BRANCH_H + y, c);
            }
        }
    }
    out
}
