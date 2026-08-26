// This file is part of the uutils coreutils package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
// spell-checker:ignore numfmt

//! Structure-aware numfmt fuzzer: the whole test case (options, positional
//! numbers, stdin) is decoded from the libFuzzer input with `arbitrary`, so
//! mutation is coverage-guided and crash artifacts replay exactly.

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::ffi::OsString;
use uu_numfmt::uumain;
use uufuzz::{
    CommandResult, compare_result, generate_and_run_uumain, pretty_print::print_test_begin,
    run_gnu_cmd,
};

static CMD_PATH: &str = "numfmt";

#[derive(Arbitrary, Debug)]
enum Unit {
    Auto,
    Si,
    Iec,
    IecI,
    None,
    Raw(String),
}

impl Unit {
    fn as_str(&self) -> &str {
        match self {
            Unit::Auto => "auto",
            Unit::Si => "si",
            Unit::Iec => "iec",
            Unit::IecI => "iec-i",
            Unit::None => "none",
            Unit::Raw(s) => s,
        }
    }
}

#[derive(Arbitrary, Debug)]
enum Opt {
    From(Unit),
    To(Unit),
    FromUnit(Num),
    ToUnit(Num),
    Padding(Num),
    Header,
    HeaderN(Num),
    Field(Field),
    Format(Fmt),
    Round(u8),
    Suffix(String),
    Invalid(u8),
    Delimiter(String),
    Grouping,
    ZeroTerminated,
    Debug,
    Junk(String),
}

#[derive(Arbitrary, Debug)]
enum Field {
    One(Num),
    Range(Num, Num),
    Open(Num),
    List(Vec<Num>),
    Raw(String),
}

impl Field {
    fn render(&self) -> String {
        match self {
            Field::One(n) => n.render(),
            Field::Range(a, b) => format!("{}-{}", a.render(), b.render()),
            Field::Open(a) => format!("{}-", a.render()),
            Field::List(v) => v.iter().map(Num::render).collect::<Vec<_>>().join(","),
            Field::Raw(s) => s.clone(),
        }
    }
}

/// printf-style format, mostly well-formed with some width/precision abuse.
#[derive(Arbitrary, Debug)]
enum Fmt {
    Structured {
        prefix: String,
        flags: Vec<u8>, // indices into FLAGS
        width: Option<Num>,
        precision: Option<Num>,
        conv: u8,
        suffix: String,
    },
    Raw(String),
}

const FLAGS: &[&str] = &["-", "'", "0", "+", " ", "#"];

impl Fmt {
    fn render(&self) -> String {
        match self {
            Fmt::Raw(s) => s.clone(),
            Fmt::Structured {
                prefix,
                flags,
                width,
                precision,
                conv,
                suffix,
            } => {
                let mut s = prefix.clone();
                s.push('%');
                for f in flags.iter().take(4) {
                    s.push_str(FLAGS[*f as usize % FLAGS.len()]);
                }
                if let Some(w) = width {
                    s.push_str(&w.render());
                }
                if let Some(p) = precision {
                    s.push('.');
                    s.push_str(&p.render());
                }
                s.push(match conv % 8 {
                    0..=4 => 'f',
                    5 => 'd',
                    6 => 's',
                    _ => '%',
                });
                s.push_str(suffix);
                s
            }
        }
    }
}

/// A number-ish token: well-formed ints/floats, suffixed, edge magnitudes, or raw junk.
#[derive(Arbitrary, Debug)]
enum Num {
    Small(i8),
    Int(i64),
    Big(u128),
    Float(i32, u32),
    Sci(i16, i16),
    Suffixed(i64, u8),
    Edge(u8),
    Raw(String),
}

const SUFFIXES: &[&str] = &["K", "Ki", "M", "Mi", "G", "T", "P", "E", "Z", "Y", "R", "Q", "KiB", "k", "B", "i"];
const EDGES: &[&str] = &[
    "0", "-0", "1", "-1", "9223372036854775807", "-9223372036854775808", "18446744073709551615",
    "340282366920938463463374607431768211455", "1e308", "1e309", "-1e309", "inf", "nan", "0x10",
    "1_000", "١٢٣", "１２３", "1٫5", "1.5.5", "1,5", ".", "-", "+", "", " ", "\t", "1e", "e5",
    "000000000000000000000000001", "0.000000000000000000000000001", "99999999999999999999999999999Y",
];

impl Num {
    fn render(&self) -> String {
        match self {
            Num::Small(n) => n.to_string(),
            Num::Int(n) => n.to_string(),
            Num::Big(n) => n.to_string(),
            Num::Float(i, f) => format!("{i}.{f}"),
            Num::Sci(m, e) => format!("{m}e{e}"),
            Num::Suffixed(n, s) => format!("{n}{}", SUFFIXES[*s as usize % SUFFIXES.len()]),
            Num::Edge(i) => EDGES[*i as usize % EDGES.len()].to_string(),
            Num::Raw(s) => s.clone(),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct Line {
    fields: Vec<Num>,
    sep: u8, // index into SEPS
    trailing_ws: bool,
}

const SEPS: &[&str] = &[" ", "  ", "\t", ",", ":", "\u{a0}", "\u{3000}", "é", "中", "🦀", ""];

impl Line {
    fn render(&self) -> String {
        let sep = SEPS[self.sep as usize % SEPS.len()];
        let mut s = self
            .fields
            .iter()
            .take(8)
            .map(Num::render)
            .collect::<Vec<_>>()
            .join(sep);
        if self.trailing_ws {
            s.push_str(sep);
        }
        s
    }
}

#[derive(Arbitrary, Debug)]
struct Case {
    opts: Vec<Opt>,
    positional: Vec<Num>,
    stdin: Vec<Line>,
    use_stdin: bool,
    crlf: bool,
}

fn render_opt(o: &Opt) -> Vec<String> {
    let s = |x: String| vec![x];
    match o {
        Opt::From(u) => s(format!("--from={}", u.as_str())),
        Opt::To(u) => s(format!("--to={}", u.as_str())),
        Opt::FromUnit(n) => s(format!("--from-unit={}", n.render())),
        Opt::ToUnit(n) => s(format!("--to-unit={}", n.render())),
        Opt::Padding(n) => s(format!("--padding={}", n.render())),
        Opt::Header => s("--header".into()),
        Opt::HeaderN(n) => s(format!("--header={}", n.render())),
        Opt::Field(f) => s(format!("--field={}", f.render())),
        Opt::Format(f) => s(format!("--format={}", f.render())),
        Opt::Round(r) => s(format!(
            "--round={}",
            ["up", "down", "from-zero", "towards-zero", "nearest", "u", "bogus"][*r as usize % 7]
        )),
        Opt::Suffix(x) => s(format!("--suffix={x}")),
        Opt::Invalid(i) => s(format!(
            "--invalid={}",
            ["abort", "fail", "warn", "ignore", "x"][*i as usize % 5]
        )),
        Opt::Delimiter(d) => s(format!("--delimiter={d}")),
        Opt::Grouping => s("--grouping".into()),
        Opt::ZeroTerminated => s("-z".into()),
        Opt::Debug => s("--debug".into()),
        Opt::Junk(j) => s(j.clone()),
    }
}

fn sanitize(s: String) -> String {
    // argv cannot carry NUL; keep everything else (newlines, multibyte, ...)
    s.replace('\0', "")
}

fuzz_target!(|case: Case| {
    let mut args = vec![OsString::from("numfmt")];
    for o in case.opts.iter().take(8) {
        args.extend(render_opt(o).into_iter().map(sanitize).map(OsString::from));
    }
    let pipe_input = if case.use_stdin || case.positional.is_empty() {
        let nl = if case.crlf { "\r\n" } else { "\n" };
        let mut s = case
            .stdin
            .iter()
            .take(16)
            .map(Line::render)
            .collect::<Vec<_>>()
            .join(nl);
        s.push_str(nl);
        Some(s)
    } else {
        for n in case.positional.iter().take(8) {
            args.push(OsString::from(sanitize(n.render())));
        }
        None
    };

    print_test_begin(format!("numfmt {args:?} stdin={pipe_input:?}"));
    let rust_result = generate_and_run_uumain(&args, uumain, pipe_input.as_deref());

    let gnu_result = match run_gnu_cmd(CMD_PATH, &args[1..], false, pipe_input.as_deref()) {
        Ok(result) => result,
        Err(error_result) => {
            eprintln!("Failed to run GNU command: {}", error_result.stderr);
            return;
        }
    };
    let _: &CommandResult = &gnu_result;
    compare_result(
        "numfmt",
        &format!("{:?}", &args[1..]),
        pipe_input.as_deref(),
        &rust_result,
        &gnu_result,
        false,
    );
});
