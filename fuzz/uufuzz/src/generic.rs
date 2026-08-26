// This file is part of the uutils coreutils package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore chdir positionals

//! Util-agnostic fuzzing: a target supplies only the util's option table (as
//! scraped from `--help`) and the whole test case — options, values,
//! positionals, stdin, scratch files — is decoded from the libFuzzer input.
//! Values come from one fixed pool shared by every util, so no per-util
//! knowledge is encoded.

use crate::{CommandResult, generate_and_run_uumain_bytes};
use arbitrary::Arbitrary;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::sync::Once;

#[derive(Clone, Copy, Debug)]
pub enum ArgKind {
    Flag,
    Value,
    Optional,
}

#[derive(Clone, Copy, Debug)]
pub struct OptSpec {
    pub long: &'static str,
    pub short: Option<char>,
    pub kind: ArgKind,
}

/// Scratch names created (fresh) before each run and offered as positionals.
pub const SCRATCH_FILES: &[&str] = &["f0", "f1"];
pub const SCRATCH_DIR: &str = "d0";

/// Util-agnostic value pool: numeric edges, size suffixes, format-ish, text
/// shapes (multibyte, RTL, control), path-ish. Absolute paths are limited to
/// the entries here (see `sanitize`).
pub const POOL: &[&str] = &[
    "0", "1", "2", "7", "-1", "-0", "+1", "00", "1.5", "-1.5", ".5", "1e3", "1e18", "1e308", "1e309",
    "-1e309", "inf", "-inf", "nan", "0x10", "010", "1_000", "1,000",
    "255", "256", "32767", "32768", "65535", "65536", "2147483647", "2147483648", "-2147483648",
    "4294967295", "4294967296", "9223372036854775807", "9223372036854775808", "-9223372036854775808",
    "18446744073709551615", "18446744073709551616", "340282366920938463463374607431768211455",
    "99999999999999999999999999999999999999999",
    "1K", "1k", "1Ki", "1KiB", "1M", "1G", "1T", "1P", "1E", "1Z", "1Y", "1R", "1Q", "9E", "9Y", "1EB", "1B", "1KB", "1x", "K", "Ki",
    "%", "%%", "%s", "%d", "%f", "%.f", "%10s", "%-10s", "%'d", "%05d", "%.100f", "%.65535f", "%.65536f", "%.4294967296f",
    "%18446744073709551616f", "%1$s", "%*d", "%b", "%c", "%n", "%Y", "%N", "%z", "%:z", "%::::z", "%E", "%-", "%_", "%^",
    "", " ", "  ", "\t", "\n", "\r", "\r\n", "\0", "\u{1b}[0m", "\u{7f}", "\u{a0}", "\u{3000}", "\u{feff}", "\u{200b}",
    "é", "ü", "ß", "中", "中文", "日本語", "🦀", "🇦🇺", "👨‍👩‍👧", "١٢٣", "١٫٥", "１２３", "Ａ", "ａ", "àé", "e\u{301}",
    "a", "A", "z", "abc", "ABC", "xyz", "yes", "no", "true", "false", "none", "auto", "always", "never", "all", "some",
    "-", "--", "---", "-x", "--x", "-1-", "1-", "-2", "1-2", "2-1", "1,3", "1-", "-", "1:2", "0-0", "1-18446744073709551615",
    "a-b", "a-z", "[:alpha:]", "[a-z]", "[[:digit:]]", "*", "?", "[", "]", "\\", "\\n", "\\t", "\\x41", "\\0", "\\",
    "f0", "f1", "d0", ".", "./f0", "d0/f0", "f0/", "nonexistent", "/dev/null", "/dev/full",
    "-o", "-n", "-c", "-l", "-w", "-b", "-e", "-f", "-r", "-s", "-t", "-v", "-z", "-1", "-0", "-9",
    "C", "POSIX", "en_US.UTF-8", "ar_SA.UTF-8", "long", "iso", "full-iso", "locale", "posix-", "posix-%",
    "utf8", "sha256", "md5", "crc", "1970-01-01", "@0", "@-1", "@99999999999999", "202508260000.00", "0001-01-01", "9999-12-31 23:59:60",
];

const SEPS: &[&[u8]] = &[b" ", b"  ", b"\t", b",", b":", b"\x00", b"", "\u{a0}".as_bytes(), "\u{3000}".as_bytes(), "é".as_bytes()];
const EOLS: &[&[u8]] = &[b"\n", b"\r\n", b"\x00", b"", b"\n\n"];

#[derive(Arbitrary, Debug)]
pub enum Tok {
    Pool(u8),
    Int(i64),
    Big(u128),
    Float(i32, u32),
    Sci(i16, i16),
    Sized(i64, u8),
    Repeat(u8, u16),
    Concat(Box<Tok>, Box<Tok>),
    Raw(String),
    Bytes(Vec<u8>),
}

const SUFFIXES: &[&str] = &["K", "k", "Ki", "KiB", "M", "Mi", "G", "T", "P", "E", "Z", "Y", "R", "Q", "B", "b", "i"];

impl Tok {
    pub fn render(&self, depth: u8) -> Vec<u8> {
        match self {
            Tok::Pool(i) => POOL[*i as usize % POOL.len()].as_bytes().to_vec(),
            Tok::Int(n) => n.to_string().into_bytes(),
            Tok::Big(n) => n.to_string().into_bytes(),
            Tok::Float(i, f) => format!("{i}.{f}").into_bytes(),
            Tok::Sci(m, e) => format!("{m}e{e}").into_bytes(),
            Tok::Sized(n, s) => format!("{n}{}", SUFFIXES[*s as usize % SUFFIXES.len()]).into_bytes(),
            Tok::Repeat(i, n) => POOL[*i as usize % POOL.len()].repeat((*n as usize).min(4096)).into_bytes(),
            Tok::Concat(a, b) if depth < 4 => {
                let mut v = a.render(depth + 1);
                v.extend(b.render(depth + 1));
                v
            }
            Tok::Concat(..) => Vec::new(),
            Tok::Raw(s) => s.as_bytes().to_vec(),
            Tok::Bytes(b) => b.clone(),
        }
    }
}

#[derive(Arbitrary, Debug)]
pub struct OptPick {
    pub idx: u16,
    pub use_short: bool,
    pub joined: bool, // --opt=VAL vs --opt VAL
    pub mangle: u8,   // 0..=15: 0 = drop value for Value opt, 1 = add value to Flag, else none
    pub value: Tok,
}

#[derive(Arbitrary, Debug)]
pub struct Line {
    pub fields: Vec<Tok>,
    pub sep: u8,
}

#[derive(Arbitrary, Debug)]
pub struct Input {
    pub lines: Vec<Line>,
    pub eol: u8,
    pub raw_tail: Option<Vec<u8>>,
}

impl Input {
    fn render(&self) -> Vec<u8> {
        let eol = EOLS[self.eol as usize % EOLS.len()];
        let mut out = Vec::new();
        for l in self.lines.iter().take(24) {
            let sep = SEPS[l.sep as usize % SEPS.len()];
            for (i, t) in l.fields.iter().take(8).enumerate() {
                if i > 0 {
                    out.extend(sep);
                }
                out.extend(t.render(0));
            }
            out.extend(eol);
        }
        if let Some(t) = &self.raw_tail {
            out.extend(t.iter().take(4096));
        }
        out.truncate(1 << 16);
        out
    }
}

#[derive(Arbitrary, Debug)]
pub struct Case {
    pub opts: Vec<OptPick>,
    pub positionals: Vec<Tok>,
    pub stdin: Option<Input>,
    pub file_content: Option<Input>,
    pub dash_dash: bool,
}

/// Keep generated paths inside the scratch dir: no `..`, and absolute paths only
/// from the pool's /dev entries.
pub fn sanitize(mut v: Vec<u8>) -> Vec<u8> {
    v.retain(|&b| b != 0);
    if v.windows(2).any(|w| w == b"..") {
        v = v.iter().map(|&b| if b == b'.' { b'_' } else { b }).collect();
    }
    if v.first() == Some(&b'/') && !POOL.iter().any(|p| p.as_bytes() == v.as_slice()) {
        v.remove(0);
    }
    v
}

static SCRATCH: Once = Once::new();

/// Enter a private scratch directory (under TMPDIR) once, and reset it before each run.
fn reset_scratch(content: &[u8]) {
    SCRATCH.call_once(|| {
        let dir = std::env::temp_dir().join("uufuzz-scratch");
        let _ = std::fs::create_dir_all(&dir);
        std::env::set_current_dir(&dir).expect("chdir to scratch dir");
    });
    unsafe {
        libc::chmod(c".".as_ptr(), 0o700);
    }
    for f in SCRATCH_FILES {
        let _ = std::fs::remove_file(f);
        let _ = std::fs::remove_dir_all(f);
        let _ = std::fs::write(f, content);
    }
    let _ = std::fs::remove_dir_all(SCRATCH_DIR);
    let _ = std::fs::remove_file(SCRATCH_DIR);
    let _ = std::fs::create_dir(SCRATCH_DIR);
    let _ = std::fs::write(Path::new(SCRATCH_DIR).join("f0"), content);
}

pub fn build_args(util: &str, opts: &[OptSpec], case: &Case) -> Vec<OsString> {
    let mut args = vec![OsString::from(util)];
    for p in case.opts.iter().take(8) {
        if opts.is_empty() {
            break;
        }
        let o = opts[p.idx as usize % opts.len()];
        let val = sanitize(p.value.render(0));
        let wants_value = match (o.kind, p.mangle) {
            (ArgKind::Value, 0) => false,
            (ArgKind::Flag, 1) => true,
            (ArgKind::Value, _) => true,
            (ArgKind::Optional, m) => m % 2 == 0,
            (ArgKind::Flag, _) => false,
        };
        let name = match (p.use_short, o.short) {
            (true, Some(c)) => format!("-{c}"),
            _ => format!("--{}", o.long),
        };
        if wants_value && (p.joined || name.len() == 2 && p.use_short) {
            let mut v = name.into_bytes();
            if !p.use_short {
                v.push(b'=');
            }
            v.extend(&val);
            args.push(OsString::from_vec(v));
        } else {
            args.push(OsString::from(name));
            if wants_value {
                args.push(OsString::from_vec(val));
            }
        }
    }
    if case.dash_dash {
        args.push(OsString::from("--"));
    }
    for t in case.positionals.iter().take(6) {
        args.push(OsString::from_vec(sanitize(t.render(0))));
    }
    args
}

/// Run one generic case against `uumain`. No GNU comparison: the only oracle is a crash.
pub fn run<F>(util: &str, opts: &[OptSpec], uumain: F, case: &Case) -> CommandResult
where
    F: FnOnce(std::vec::IntoIter<OsString>) -> i32 + Send + 'static,
{
    let content = case.file_content.as_ref().map(Input::render).unwrap_or_default();
    reset_scratch(&content);
    let args = build_args(util, opts, case);
    let stdin = case.stdin.as_ref().map(Input::render);
    generate_and_run_uumain_bytes(&args, uumain, stdin.as_deref())
}
