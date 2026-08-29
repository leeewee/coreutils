// This file is part of the uutils coreutils package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.
#![cfg_attr(fuzzing, feature(alloc_error_hook))]

use console::Style;
use libc::STDIN_FILENO;
use libc::{STDERR_FILENO, STDOUT_FILENO, close, dup, dup2, pipe};
use pretty_print::{
    print_diff, print_end_with_status, print_or_empty, print_section, print_with_style,
};
use rand::RngExt;
use rand::prelude::IndexedRandom;
use std::env::temp_dir;
use std::ffi::OsString;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::{Once, OnceLock, atomic::AtomicBool};
use std::{io, thread};

pub mod generic;
pub mod pretty_print;

/// Represents the result of running a command, including its standard output,
/// standard error, and exit code.
#[derive(Debug)]
pub struct CommandResult {
    /// The standard output (stdout) of the command as a string.
    pub stdout: String,

    /// The standard error (stderr) of the command as a string.
    pub stderr: String,

    /// The exit code of the command.
    pub exit_code: i32,
}

static CHECK_GNU: Once = Once::new();
static IS_GNU: AtomicBool = AtomicBool::new(false);

pub fn is_gnu_cmd(cmd_path: &str) -> Result<(), std::io::Error> {
    CHECK_GNU.call_once(|| {
        let version_output = Command::new(cmd_path).arg("--version").output().unwrap();

        println!("version_output {version_output:#?}");

        let version_str = String::from_utf8_lossy(&version_output.stdout).to_string();
        if version_str.contains("GNU coreutils") {
            IS_GNU.store(true, Ordering::Relaxed);
        }
    });

    if IS_GNU.load(Ordering::Relaxed) {
        Ok(())
    } else {
        panic!("Not the GNU implementation");
    }
}

/// Real stdin/stdout/stderr, saved (at fds >= 100, so a util that closes 0/1/2 cannot
/// make a later dup() land there) before any redirection.
static ORIG_STD_FDS: OnceLock<(RawFd, RawFd, RawFd)> = OnceLock::new();
static CRASH_HOOKS: Once = Once::new();
/// argv of the run in progress, for crash records.
static CURRENT_ARGS: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());
/// True while uumain runs: only panics from there are recoverable.
static IN_UUMAIN: AtomicBool = AtomicBool::new(false);

/// UUFUZZ_CATCH_PANICS=1: panics/alloc failures inside uumain are recorded and swallowed
/// instead of killing the process.
fn catch_panics() -> bool {
    static V: OnceLock<bool> = OnceLock::new();
    *V.get_or_init(|| std::env::var_os("UUFUZZ_CATCH_PANICS").is_some())
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn is_first_party(file: &str) -> bool {
    file.contains("/src/uu/") || file.contains("/src/uucore/") || file.contains("fuzz_targets/")
}

/// First first-party `file:line` on the current stack. Used when the panic location is
/// in std (capacity overflow, allocation failure) so the record still names the util
/// site. Symbolisation costs tens of ms, so only called for those cases.
fn first_party_frame() -> Option<(String, u32)> {
    let bt = std::backtrace::Backtrace::force_capture().to_string();
    for l in bt.lines() {
        let l = l.trim();
        // "at /path/file.rs:LINE:COL" (or without :COL)
        if let Some(rest) = l.strip_prefix("at ") {
            let mut parts = rest.rsplitn(3, ':');
            let a = parts.next();
            let b = parts.next();
            let c = parts.next();
            let (file, ln) = match (a.and_then(|x| x.parse::<u32>().ok()), b.and_then(|x| x.parse::<u32>().ok())) {
                (Some(_col), Some(line)) => (c.unwrap_or(""), line),
                (Some(line), None) => (b.unwrap_or(""), line),
                _ => continue,
            };
            if is_first_party(file) {
                return Some((file.to_string(), ln));
            }
        }
    }
    None
}

/// Append one JSON record to $UUFUZZ_CRASH_LOG (if set). This is the durable crash
/// channel: under `-fork -ignore_crashes` libFuzzer discards the child's log.
fn crash_record(kind: &str, file: &str, line: u32, msg: &str) {
    let Some(path) = std::env::var_os("UUFUZZ_CRASH_LOG") else {
        return;
    };
    let argv = CURRENT_ARGS.lock().map(|g| g.clone()).unwrap_or_default();
    let (fp_file, fp_line) = if is_first_party(file) {
        (file.to_string(), line)
    } else {
        first_party_frame().unwrap_or_default()
    };
    let rec = format!(
        "{{\"kind\":\"{kind}\",\"file\":\"{}\",\"line\":{line},\"fp_file\":\"{}\",\"fp_line\":{fp_line},\"msg\":\"{}\",\"argv\":\"{}\"}}\n",
        json_escape(file),
        json_escape(&fp_file),
        json_escape(msg),
        json_escape(&argv)
    );
    if let Ok(mut f) = std::fs::OpenOptions::new().append(true).create(true).open(path) {
        let _ = f.write_all(rec.as_bytes());
    }
}

fn restore_std_fds() {
    if let Some(&(inp, out, err)) = ORIG_STD_FDS.get() {
        unsafe {
            dup2(inp, STDIN_FILENO);
            dup2(out, STDOUT_FILENO);
            dup2(err, STDERR_FILENO);
        }
    }
}

/// While `uumain` runs, fds 1/2 point at capture pipes, so a panic or allocation
/// failure inside it would print into a pipe that dies with the process. These
/// hooks put the real fds back first so the report (and libFuzzer's) is visible.
fn install_crash_hooks() {
    CRASH_HOOKS.call_once(|| {
        // libFuzzer owns main(), so Rust's runtime never ignored SIGPIPE; without this a
        // GNU child that exits before reading its stdin kills the whole fuzzer.
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
        let inp = unsafe { libc::fcntl(STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 100) };
        let out = unsafe { libc::fcntl(STDOUT_FILENO, libc::F_DUPFD_CLOEXEC, 100) };
        let err = unsafe { libc::fcntl(STDERR_FILENO, libc::F_DUPFD_CLOEXEC, 100) };
        if inp == -1 || out == -1 || err == -1 {
            return;
        }
        let _ = ORIG_STD_FDS.set((inp, out, err));
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            restore_std_fds();
            let msg = info
                .payload()
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| info.payload().downcast_ref::<String>().cloned())
                .unwrap_or_default();
            let (file, line) = info.location().map_or(("?", 0), |l| (l.file(), l.line()));
            // An alloc failure in catch mode arrives here as the panic raised by the alloc hook.
            let kind = if msg.starts_with("memory allocation of ") { "alloc-fail" } else { "panic" };
            crash_record(kind, file, line, &msg);
            if catch_panics() && IN_UUMAIN.load(Ordering::Relaxed) {
                // Recoverable: the panic unwinds to the catch_unwind around uumain and the
                // fuzz loop continues (no abort, no restart, no corpus replay).
                eprintln!("uufuzz: caught panic at {file}:{line}: {msg}");
            } else {
                prev(info);
            }
        }));
        #[cfg(fuzzing)]
        std::alloc::set_alloc_error_hook(|layout| {
            restore_std_fds();
            eprintln!("memory allocation of {} bytes failed", layout.size());
            if catch_panics() && IN_UUMAIN.load(Ordering::Relaxed) {
                // Unwind instead of aborting (same mechanism as -Zoom=panic), so a huge
                // allocation inside uumain is recoverable too.
                std::panic::panic_any(format!("memory allocation of {} bytes failed", layout.size()));
            }
            crash_record("alloc-fail", "", 0, &format!("{} bytes", layout.size()));
        });
    });
}

pub fn generate_and_run_uumain<F>(
    args: &[OsString],
    uumain_function: F,
    pipe_input: Option<&str>,
) -> CommandResult
where
    F: FnOnce(std::vec::IntoIter<OsString>) -> i32 + Send + 'static,
{
    generate_and_run_uumain_bytes(args, uumain_function, pipe_input.map(str::as_bytes))
}

/// Like [`generate_and_run_uumain`] but stdin may be arbitrary bytes.
pub fn generate_and_run_uumain_bytes<F>(
    args: &[OsString],
    uumain_function: F,
    pipe_input: Option<&[u8]>,
) -> CommandResult
where
    F: FnOnce(std::vec::IntoIter<OsString>) -> i32 + Send + 'static,
{
    install_crash_hooks();
    // Start every run from the real 0/1/2: the previous util may have closed them (dd wraps
    // them in File::from_raw_fd), which would otherwise derail the dup()/pipe() bookkeeping.
    restore_std_fds();
    if let Ok(mut g) = CURRENT_ARGS.lock() {
        *g = format!("{args:?}");
    }
    // Duplicate the stdout and stderr file descriptors
    let original_stdout_fd = unsafe { libc::fcntl(STDOUT_FILENO, libc::F_DUPFD_CLOEXEC, 100) };
    let original_stderr_fd = unsafe { libc::fcntl(STDERR_FILENO, libc::F_DUPFD_CLOEXEC, 100) };
    if original_stdout_fd == -1 || original_stderr_fd == -1 {
        return CommandResult {
            stdout: "".to_string(),
            stderr: "Failed to duplicate STDOUT_FILENO or STDERR_FILENO".to_string(),
            exit_code: -1,
        };
    }

    println!("Running test {:?}", &args[0..]);
    let mut pipe_stdout_fds = [-1; 2];
    let mut pipe_stderr_fds = [-1; 2];

    // Create pipes for stdout and stderr
    if unsafe { pipe(pipe_stdout_fds.as_mut_ptr()) } == -1
        || unsafe { pipe(pipe_stderr_fds.as_mut_ptr()) } == -1
    {
        return CommandResult {
            stdout: "".to_string(),
            stderr: "Failed to create pipes".to_string(),
            exit_code: -1,
        };
    }

    // Redirect stdout and stderr to their respective pipes
    if unsafe { dup2(pipe_stdout_fds[1], STDOUT_FILENO) } == -1
        || unsafe { dup2(pipe_stderr_fds[1], STDERR_FILENO) } == -1
    {
        unsafe {
            close(pipe_stdout_fds[0]);
            close(pipe_stdout_fds[1]);
            close(pipe_stderr_fds[0]);
            close(pipe_stderr_fds[1]);
        }
        return CommandResult {
            stdout: "".to_string(),
            stderr: "Failed to redirect STDOUT_FILENO or STDERR_FILENO".to_string(),
            exit_code: -1,
        };
    }

    let original_stdin_fd = if let Some(input_str) = pipe_input {
        // we have pipe input
        let mut input_file = tempfile::tempfile().unwrap();
        input_file.write_all(input_str).unwrap();
        input_file.seek(SeekFrom::Start(0)).unwrap();

        // Redirect stdin to read from the in-memory file
        let original_stdin_fd = unsafe { libc::fcntl(STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 100) };
        if original_stdin_fd == -1 || unsafe { dup2(input_file.as_raw_fd(), STDIN_FILENO) } == -1 {
            return CommandResult {
                stdout: "".to_string(),
                stderr: "Failed to set up stdin redirection".to_string(),
                exit_code: -1,
            };
        }
        Some(original_stdin_fd)
    } else {
        None
    };

    let (uumain_exit_status, captured_stdout, captured_stderr) = thread::scope(|s| {
        let out = s.spawn(|| read_from_fd(pipe_stdout_fds[0], true));
        let err = s.spawn(|| read_from_fd(pipe_stderr_fds[0], false));
        #[allow(clippy::unnecessary_to_owned)]
        // TODO: clippy wants us to use args.iter().cloned() ?
        IN_UUMAIN.store(true, Ordering::Relaxed);
        let owned = args.to_owned();
        let status = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            uumain_function(owned.into_iter())
        })) {
            Ok(status) => status,
            Err(_) => 101, // panic recorded by the hook; continue like a `panic=unwind` exit
        };
        IN_UUMAIN.store(false, Ordering::Relaxed);
        // Reset the exit code global variable in case we run another test after this one
        // See https://github.com/uutils/coreutils/issues/5777
        uucore::error::set_exit_code(0);
        // EPIPE here is expected after the reader hit CAPTURE_LIMIT and closed its end.
        let _ = io::stdout().flush();
        let _ = io::stderr().flush();
        unsafe {
            close(pipe_stdout_fds[1]);
            close(pipe_stderr_fds[1]);
            close(STDOUT_FILENO);
            close(STDERR_FILENO);
        }
        (status, out.join().unwrap(), err.join().unwrap())
    });

    // Restore the original stdout and stderr
    if unsafe { dup2(original_stdout_fd, STDOUT_FILENO) } == -1
        || unsafe { dup2(original_stderr_fd, STDERR_FILENO) } == -1
    {
        return CommandResult {
            stdout: "".to_string(),
            stderr: "Failed to restore the original STDOUT_FILENO or STDERR_FILENO".to_string(),
            exit_code: -1,
        };
    }
    unsafe {
        close(original_stdout_fd);
        close(original_stderr_fd);
    }

    // Restore the original stdin if it was modified
    if let Some(fd) = original_stdin_fd {
        if unsafe { dup2(fd, STDIN_FILENO) } == -1 {
            return CommandResult {
                stdout: "".to_string(),
                stderr: "Failed to restore the original STDIN".to_string(),
                exit_code: -1,
            };
        }
        unsafe { close(fd) };
    }

    CommandResult {
        stdout: captured_stdout,
        stderr: captured_stderr
            .split_once(':')
            .map(|x| x.1)
            .unwrap_or("")
            .trim()
            .to_string(),
        exit_code: uumain_exit_status,
    }
}

/// Output budget per run. Past this the pipe is closed so the util gets EPIPE and
/// stops, bounding the cost of huge-output cases (`seq 1e30`). Requires SIGPIPE to be
/// ignored when the fuzzer starts (uucore snapshots the disposition at load time).
const CAPTURE_LIMIT: usize = 16 << 20;

/// `cut_off`: stop reading at CAPTURE_LIMIT and close our end (the writer gets EPIPE).
/// Used for stdout only; stderr is always drained to EOF (past the limit it is dropped),
/// because a program never expects EPIPE on stderr and a dead reader would block it.
/// Never prints: this runs while fds 1/2 are redirected.
fn read_from_fd(fd: RawFd, cut_off: bool) -> String {
    let mut captured_output = Vec::new();
    let mut read_buffer = [0; 65536];
    loop {
        let bytes_read =
            unsafe { libc::read(fd, read_buffer.as_mut_ptr().cast(), read_buffer.len()) };
        if bytes_read <= 0 {
            break;
        }
        if captured_output.len() < CAPTURE_LIMIT {
            captured_output.extend_from_slice(&read_buffer[..bytes_read as usize]);
        } else if cut_off {
            captured_output.extend_from_slice(b"\n[uufuzz: output truncated]\n");
            break;
        }
    }

    unsafe { libc::close(fd) };

    String::from_utf8_lossy(&captured_output).into_owned()
}

pub fn run_gnu_cmd(
    cmd_path: &str,
    args: &[OsString],
    check_gnu: bool,
    pipe_input: Option<&str>,
) -> Result<CommandResult, CommandResult> {
    if check_gnu {
        match is_gnu_cmd(cmd_path) {
            Ok(_) => {} // if the check passes, do nothing
            Err(e) => {
                // Convert the io::Error into the function's error type
                return Err(CommandResult {
                    stdout: String::new(),
                    stderr: e.to_string(),
                    exit_code: -1,
                });
            }
        }
    }

    // #[uucore::main] resets SIGPIPE to SIG_DFL on every uumain call; re-ignore it so a
    // GNU child that exits before reading stdin yields EPIPE instead of killing the fuzzer.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    let mut command = Command::new(cmd_path);
    for arg in args {
        command.arg(arg);
    }

    // See https://github.com/uutils/coreutils/issues/6794
    // uutils' coreutils is not locale-aware, and aims to mirror/be compatible with GNU Core Utilities's LC_ALL=C behavior
    command.env("LC_ALL", "C");

    let output = if let Some(input_str) = pipe_input {
        // We have an pipe input
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = command.spawn().expect("Failed to execute command");
        // Ignore EPIPE: the child may legitimately exit before reading stdin.
        let _ = child.stdin.take().unwrap().write_all(input_str.as_bytes());

        match child.wait_with_output() {
            Ok(output) => output,
            Err(e) => {
                return Err(CommandResult {
                    stdout: String::new(),
                    stderr: e.to_string(),
                    exit_code: -1,
                });
            }
        }
    } else {
        // Just run with args
        match command.output() {
            Ok(output) => output,
            Err(e) => {
                return Err(CommandResult {
                    stdout: String::new(),
                    stderr: e.to_string(),
                    exit_code: -1,
                });
            }
        }
    };
    let exit_code = output.status.code().unwrap_or(-1);
    // Here we get stdout and stderr as Strings
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let stderr = stderr
        .split_once(':')
        .map(|x| x.1)
        .unwrap_or("")
        .trim()
        .to_string();

    if output.status.success() || !check_gnu {
        Ok(CommandResult {
            stdout,
            stderr,
            exit_code,
        })
    } else {
        Err(CommandResult {
            stdout,
            stderr,
            exit_code,
        })
    }
}

/// Compare results from two different implementations of a command.
///
/// # Arguments
/// * `test_type` - The command.
/// * `input` - The input provided to the command.
/// * `rust_result` - The result of running the command with the Rust implementation.
/// * `gnu_result` - The result of running the command with the GNU implementation.
/// * `fail_on_stderr_diff` - Whether to fail the test if there is a difference in stderr output.
pub fn compare_result(
    test_type: &str,
    input: &str,
    pipe_input: Option<&str>,
    rust_result: &CommandResult,
    gnu_result: &CommandResult,
    fail_on_stderr_diff: bool,
) {
    print_section(format!("Compare result for: {test_type} {input}"));

    if let Some(pipe) = pipe_input {
        println!("Pipe: {pipe}");
    }

    let mut discrepancies = Vec::new();
    let mut should_panic = false;

    if rust_result.stdout.trim() != gnu_result.stdout.trim() {
        discrepancies.push("stdout differs");
        println!("Rust stdout:");
        print_or_empty(rust_result.stdout.as_str());
        println!("GNU stdout:");
        print_or_empty(gnu_result.stdout.as_ref());
        print_diff(&rust_result.stdout, &gnu_result.stdout);
        should_panic = true;
    }

    if rust_result.stderr.trim() != gnu_result.stderr.trim() {
        discrepancies.push("stderr differs");
        println!("Rust stderr:");
        print_or_empty(rust_result.stderr.as_str());
        println!("GNU stderr:");
        print_or_empty(gnu_result.stderr.as_str());
        print_diff(&rust_result.stderr, &gnu_result.stderr);
        if fail_on_stderr_diff {
            should_panic = true;
        }
    }

    if rust_result.exit_code != gnu_result.exit_code {
        discrepancies.push("exit code differs");
        println!(
            "Different exit code: (Rust: {}, GNU: {})",
            rust_result.exit_code, gnu_result.exit_code
        );
        should_panic = true;
    }

    if discrepancies.is_empty() {
        print_end_with_status("Same behavior", true);
    } else {
        print_with_style(
            format!("Discrepancies detected: {}", discrepancies.join(", ")),
            Style::new().red(),
        );
        // UUFUZZ_PANIC_ONLY=1: log GNU discrepancies but only crash on real uumain panics.
        if should_panic && std::env::var_os("UUFUZZ_PANIC_ONLY").is_none() {
            print_end_with_status(
                format!("Test failed and will panic for: {test_type} {input}"),
                false,
            );
            panic!("Test failed for: {test_type} {input}");
        } else {
            print_end_with_status(
                format!("Test completed with discrepancies for: {test_type} {input}"),
                false,
            );
        }
    }
    println!();
}

pub fn generate_random_string(max_length: usize) -> String {
    let mut rng = rand::rng();
    let valid_utf8: Vec<char> =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789🔩🪛🪓⚙️🔗🧰"
            .chars()
            .collect();
    let invalid_utf8 = [0xC3, 0x28]; // Invalid UTF-8 sequence
    let mut result = String::new();

    for _ in 0..rng.random_range(0..=max_length) {
        if rng.random_bool(0.9) {
            let ch = valid_utf8.choose(&mut rng).unwrap();
            result.push(*ch);
        } else {
            let ch = invalid_utf8.choose(&mut rng).unwrap();
            if let Some(c) = char::from_u32(*ch as u32) {
                result.push(c);
            }
        }
    }

    result
}

#[allow(dead_code)]
pub fn generate_random_file() -> Result<String, std::io::Error> {
    let mut rng = rand::rng();
    let file_name: String = (0..10)
        .map(|_| rng.random_range(b'a'..=b'z') as char)
        .collect();
    let mut file_path = temp_dir();
    file_path.push(file_name);

    let mut file = File::create(&file_path)?;

    let content_length = rng.random_range(10..1000);
    let content: String = (0..content_length)
        .map(|_| rng.random_range(b' '..=b'~') as char)
        .collect();

    file.write_all(content.as_bytes())?;

    Ok(file_path.to_str().unwrap().to_string())
}

#[allow(dead_code)]
pub fn replace_fuzz_binary_name(cmd: &str, result: &mut CommandResult) {
    let fuzz_bin_name = format!("fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_{cmd}");

    result.stdout = result.stdout.replace(&fuzz_bin_name, cmd);
    result.stderr = result.stderr.replace(&fuzz_bin_name, cmd);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn test_command_result_creation() {
        let result = CommandResult {
            stdout: "Hello, world!".to_string(),
            stderr: "".to_string(),
            exit_code: 0,
        };

        assert_eq!(result.stdout, "Hello, world!");
        assert_eq!(result.stderr, "");
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn test_generate_random_string() {
        let result = generate_random_string(10);
        // Check character count, not byte count (emojis are multi-byte)
        assert!(result.chars().count() <= 10);

        // Test that empty string can be generated (max_length = 0)
        let empty_result = generate_random_string(0);
        assert_eq!(empty_result.chars().count(), 0);
    }

    #[test]
    fn test_replace_fuzz_binary_name() {
        let mut result = CommandResult {
            stdout: "fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_echo: error".to_string(),
            stderr: "fuzz/target/x86_64-unknown-linux-gnu/release/fuzz_echo failed".to_string(),
            exit_code: 1,
        };

        replace_fuzz_binary_name("echo", &mut result);

        assert_eq!(result.stdout, "echo: error");
        assert_eq!(result.stderr, "echo failed");
        assert_eq!(result.exit_code, 1);
    }

    #[test]
    fn test_run_gnu_cmd_nonexistent() {
        let args = vec![OsString::from("--version")];
        let result = run_gnu_cmd("nonexistent_command_12345", &args, false, None);

        // Should return an error since the command doesn't exist
        assert!(result.is_err());
        let error_result = result.unwrap_err();
        assert_ne!(error_result.exit_code, 0);
    }

    #[test]
    fn test_run_gnu_cmd_basic() {
        // Test with a simple command that should exist on most systems
        let args = vec![OsString::from("--version")];
        let result = run_gnu_cmd("echo", &args, false, None);

        // Should succeed (echo --version might not be standard but echo should exist)
        match result {
            Ok(_) => {} // Command succeeded
            Err(err_result) => {
                // Command failed but at least ran
                assert_ne!(err_result.exit_code, -1); // -1 would indicate the command couldn't be found
            }
        }
    }

    #[test]
    fn test_run_gnu_cmd_with_pipe_input() {
        let args: Vec<OsString> = vec![];
        let pipe_input = "hello world";
        let result = run_gnu_cmd("cat", &args, false, Some(pipe_input));

        match result {
            Ok(cmd_result) => {
                assert_eq!(cmd_result.stdout.trim(), "hello world");
            }
            Err(_) => {
                // cat might not be available in test environment, that's ok
            }
        }
    }

    #[test]
    fn test_generate_random_file() {
        let result = generate_random_file();
        match result {
            Ok(file_path) => {
                assert!(!file_path.is_empty());
                // Clean up - try to remove the file
                let _ = std::fs::remove_file(&file_path);
            }
            Err(_) => {
                // File creation might fail due to permissions, that's acceptable for this test
            }
        }
    }
}
