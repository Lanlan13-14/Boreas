//! ELF identity preflight for a candidate executable (master plan §10.1 / §10.3).
//!
//! # What this module is
//!
//! [`inspect_elf`] checks bytes the caller already holds. [`inspect_elf_file`]
//! reads one regular file only after `metadata.len()` is within
//! [`MAX_ELF_BYTES`]. Both accept a normal ELF64 little-endian executable or
//! PIE (`ET_EXEC` / `ET_DYN`) for `EM_X86_64` or `EM_AARCH64`, and only when
//! the program-header table has neither `PT_INTERP` nor `PT_DYNAMIC`.
//!
//! # What this module is not
//!
//! Signature verification, same-filesystem rename, the upgrade journal, and
//! supervisor rollback are separate and are not done here. A passing inspect
//! is not permission to exec. This slice also does not run `self-check`, read
//! a state schema, compare seccomp or capability sets, check free disk, or
//! decide rollback compatibility. `G-SUPPLY` and `G-UPGRADE` are not passed.
//!
//! Absence of `PT_INTERP` and `PT_DYNAMIC` is necessary for the static-release
//! rule and is not a proof that the image cannot `dlopen` through a raw
//! syscall. Section names are not parsed; a stripped static binary has none.
//! The pure function does not touch the filesystem.

#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;

/// Largest candidate image this preflight will parse (64 MiB).
pub const MAX_ELF_BYTES: u64 = 64 * 1024 * 1024;

/// `EI_NIDENT`.
const EI_NIDENT: usize = 16;
/// ELF64 `Elf64_Ehdr` size. `e_ehsize` must match.
const ELF64_EHDR_SIZE: u16 = 64;
/// ELF64 `Elf64_Phdr` size. `e_phentsize` must match.
const ELF64_PHDR_SIZE: u16 = 56;
/// Inclusive upper bound on `e_phnum` for this slice.
const MAX_PHNUM: u16 = 64;

const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;

/// `EM_X86_64`.
const EM_X86_64: u16 = 62;
/// `EM_AARCH64`.
const EM_AARCH64: u16 = 183;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;

const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const EI_VERSION: usize = 6;

/// Machine of an image [`inspect_elf`] accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Machine {
    /// `EM_X86_64` (62).
    X86_64,
    /// `EM_AARCH64` (183).
    Aarch64,
}

/// Object kind of an image [`inspect_elf`] accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfKind {
    /// `ET_EXEC`.
    Exec,
    /// `ET_DYN` (PIE). Still rejected when `PT_DYNAMIC` or `PT_INTERP` is present.
    Dyn,
}

/// Identity of a candidate that passed the static-ELF checks in this module.
///
/// Holding this value is not permission to exec, and it does not mean a
/// signature was checked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfImage {
    /// `ET_EXEC` or `ET_DYN`.
    pub kind: ElfKind,
    /// `EM_X86_64` or `EM_AARCH64`.
    pub machine: Machine,
}

/// Why a candidate was not accepted as a fully static ELF64 release image.
#[derive(Debug)]
pub enum PreflightError {
    /// Zero-length input.
    Empty,
    /// Length is greater than [`MAX_ELF_BYTES`]. The header was not parsed.
    TooLarge {
        /// Rejected length in bytes.
        len: u64,
    },
    /// Filesystem metadata or read failed. Never used by [`inspect_elf`].
    Io(io::Error),
    /// Not an ELF file (bad magic, script, or archive).
    NotElf,
    /// `EI_CLASS` is not `ELFCLASS64`. `ELFCLASS32` is included.
    NotElf64,
    /// `EI_DATA` is not `ELFDATA2LSB`.
    NotLittleEndian,
    /// `EI_VERSION` or `e_version` is not `EV_CURRENT`.
    BadVersion,
    /// `e_type` is not `ET_EXEC` or `ET_DYN`.
    BadType,
    /// `e_machine` is not `EM_X86_64` or `EM_AARCH64`.
    BadMachine,
    /// The ELF header, `e_shoff`, or the program-header table is cut off.
    Truncated,
    /// Program-header geometry is not the fixed ELF64 layout this slice parses.
    BadProgramHeaders,
    /// `PT_INTERP` is present. A musl `ld.so` path is still a failure.
    Interpreter,
    /// `PT_DYNAMIC` is present, including a PIE that still has a dynamic segment.
    DynamicSegment,
}

impl fmt::Display for PreflightError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("ELF image is empty"),
            Self::TooLarge { len } => write!(
                f,
                "ELF image is {len} bytes, above the {MAX_ELF_BYTES}-byte preflight cap"
            ),
            Self::Io(err) => write!(f, "ELF preflight I/O error: {err}"),
            Self::NotElf => f.write_str("input is not an ELF file"),
            Self::NotElf64 => f.write_str("ELF class is not ELFCLASS64"),
            Self::NotLittleEndian => f.write_str("ELF data encoding is not ELFDATA2LSB"),
            Self::BadVersion => f.write_str("ELF version is not EV_CURRENT"),
            Self::BadType => f.write_str("ELF type is not ET_EXEC or ET_DYN"),
            Self::BadMachine => f.write_str("ELF machine is not EM_X86_64 or EM_AARCH64"),
            Self::Truncated => f.write_str("ELF image is truncated"),
            Self::BadProgramHeaders => {
                f.write_str("ELF program-header table is absent or not a bounded ELF64 phdr table")
            }
            Self::Interpreter => f.write_str(
                "ELF has PT_INTERP; a release candidate must be fully static, \
                 including when the interpreter is musl",
            ),
            Self::DynamicSegment => {
                f.write_str("ELF has PT_DYNAMIC; a PIE with a dynamic segment is not static enough")
            }
        }
    }
}

impl Error for PreflightError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        if let Self::Io(err) = self {
            Some(err)
        } else {
            None
        }
    }
}

impl From<io::Error> for PreflightError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// `true` when `len` is above [`MAX_ELF_BYTES`].
///
/// Zero is not too large; empty input is [`PreflightError::Empty`].
#[must_use]
pub const fn image_too_large(len: u64) -> bool {
    len > MAX_ELF_BYTES
}

/// Parse a normal ELF image from memory.
///
/// Rejects an empty slice and any slice longer than [`MAX_ELF_BYTES`] before
/// reading a header. Does not read the filesystem.
///
/// A passing result is not permission to exec the bytes. Signature
/// verification, same-filesystem rename, the upgrade journal, and supervisor
/// rollback are separate and are not done here. `G-SUPPLY` and `G-UPGRADE`
/// are not passed.
///
/// # Errors
///
/// Returns [`PreflightError`] when the bytes are not a fully static ELF64 LSB
/// executable or PIE for x86-64 or AArch64. `PT_INTERP` and `PT_DYNAMIC` are
/// hard failures. Missing both is not a proof against `dlopen` via a raw
/// syscall.
pub fn inspect_elf(bytes: &[u8]) -> Result<ElfImage, PreflightError> {
    let len = bytes.len() as u64;
    if bytes.is_empty() {
        return Err(PreflightError::Empty);
    }
    if image_too_large(len) {
        return Err(PreflightError::TooLarge { len });
    }
    parse_ident(bytes)?;
    let header = parse_ehdr(bytes)?;
    check_shoff(bytes, header.shoff)?;
    check_program_headers(bytes, &header)?;
    Ok(ElfImage {
        kind: header.kind,
        machine: header.machine,
    })
}

/// Read `path` and pass the bytes to [`inspect_elf`].
///
/// `metadata.len()` is checked against [`MAX_ELF_BYTES`] before the file is
/// allocated or parsed. I/O failures become [`PreflightError::Io`]. This is
/// not an install path and does not verify a signature.
///
/// # Errors
///
/// Returns [`PreflightError::TooLarge`] when the metadata length is over the
/// cap, [`PreflightError::Empty`] for a zero-length file, [`PreflightError::Io`]
/// when the file cannot be read, and the same parse errors as [`inspect_elf`].
pub fn inspect_elf_file(path: &Path) -> Result<ElfImage, PreflightError> {
    let len = fs::metadata(path)?.len();
    if len == 0 {
        return Err(PreflightError::Empty);
    }
    if image_too_large(len) {
        return Err(PreflightError::TooLarge { len });
    }
    let file = File::open(path)?;
    let cap = usize::try_from(len).map_err(|_| PreflightError::TooLarge { len })?;
    let mut buf = Vec::new();
    buf.try_reserve_exact(cap)
        .map_err(|err| PreflightError::Io(io::Error::new(io::ErrorKind::OutOfMemory, err)))?;
    file.take(len).read_to_end(&mut buf)?;
    inspect_elf(&buf)
}

struct Header {
    kind: ElfKind,
    machine: Machine,
    shoff: u64,
    phoff: u64,
    phentsize: u16,
    phnum: u16,
}

fn parse_ident(bytes: &[u8]) -> Result<(), PreflightError> {
    let mag = bytes.get(..ELFMAG.len()).ok_or(PreflightError::NotElf)?;
    if mag != ELFMAG {
        return Err(PreflightError::NotElf);
    }
    if bytes.len() < EI_NIDENT {
        return Err(PreflightError::Truncated);
    }
    // ELFCLASS32 (1) and every other class are not release targets.
    if bytes[EI_CLASS] != ELFCLASS64 {
        return Err(PreflightError::NotElf64);
    }
    if bytes[EI_DATA] != ELFDATA2LSB {
        return Err(PreflightError::NotLittleEndian);
    }
    if bytes[EI_VERSION] != EV_CURRENT {
        return Err(PreflightError::BadVersion);
    }
    Ok(())
}

fn parse_ehdr(bytes: &[u8]) -> Result<Header, PreflightError> {
    if bytes.len() < usize::from(ELF64_EHDR_SIZE) {
        return Err(PreflightError::Truncated);
    }
    let kind = read_u16(bytes, 16)?;
    let machine = read_u16(bytes, 18)?;
    let version = read_u32(bytes, 20)?;
    let phoff = read_u64(bytes, 32)?;
    let shoff = read_u64(bytes, 40)?;
    let ehsize = read_u16(bytes, 52)?;
    let phentsize = read_u16(bytes, 54)?;
    let phnum = read_u16(bytes, 56)?;
    if version != u32::from(EV_CURRENT) {
        return Err(PreflightError::BadVersion);
    }
    if ehsize != ELF64_EHDR_SIZE {
        return Err(PreflightError::BadProgramHeaders);
    }
    let kind = match kind {
        ET_EXEC => ElfKind::Exec,
        ET_DYN => ElfKind::Dyn,
        _ => return Err(PreflightError::BadType),
    };
    let machine = match machine {
        EM_X86_64 => Machine::X86_64,
        EM_AARCH64 => Machine::Aarch64,
        _ => return Err(PreflightError::BadMachine),
    };
    Ok(Header {
        kind,
        machine,
        shoff,
        phoff,
        phentsize,
        phnum,
    })
}

/// `e_shoff` must be zero or a byte offset inside the image.
///
/// The section-header table is not parsed. A static release binary may be
/// stripped, so section names are not evidence.
fn check_shoff(bytes: &[u8], shoff: u64) -> Result<(), PreflightError> {
    if shoff == 0 {
        return Ok(());
    }
    let off = usize::try_from(shoff).map_err(|_| PreflightError::Truncated)?;
    if off >= bytes.len() {
        return Err(PreflightError::Truncated);
    }
    Ok(())
}

fn check_program_headers(bytes: &[u8], header: &Header) -> Result<(), PreflightError> {
    if header.phentsize != ELF64_PHDR_SIZE {
        return Err(PreflightError::BadProgramHeaders);
    }
    if header.phnum == 0 || header.phnum > MAX_PHNUM {
        return Err(PreflightError::BadProgramHeaders);
    }
    let phnum = usize::from(header.phnum);
    let phoff = usize::try_from(header.phoff).map_err(|_| PreflightError::Truncated)?;
    if phoff < usize::from(ELF64_EHDR_SIZE) {
        return Err(PreflightError::BadProgramHeaders);
    }
    let table = phnum
        .checked_mul(usize::from(ELF64_PHDR_SIZE))
        .ok_or(PreflightError::BadProgramHeaders)?;
    let end = phoff.checked_add(table).ok_or(PreflightError::Truncated)?;
    if end > bytes.len() {
        return Err(PreflightError::Truncated);
    }
    scan_phdrs(bytes, phoff, phnum)
}

/// `PT_INTERP` wins over `PT_DYNAMIC` when both are present.
///
/// Other program-header types (`PT_NOTE`, `PT_GNU_STACK`, `PT_PHDR`, …) are
/// ignored. That is not a claim that every remaining segment is harmless.
fn scan_phdrs(bytes: &[u8], phoff: usize, phnum: usize) -> Result<(), PreflightError> {
    let mut saw_interp = false;
    let mut saw_dynamic = false;
    let mut saw_load = false;
    let mut off = phoff;
    for _ in 0..phnum {
        let p_type = read_u32(bytes, off)?;
        match p_type {
            PT_INTERP => saw_interp = true,
            PT_DYNAMIC => saw_dynamic = true,
            PT_LOAD => saw_load = true,
            _ => {}
        }
        off = off
            .checked_add(usize::from(ELF64_PHDR_SIZE))
            .ok_or(PreflightError::Truncated)?;
    }
    if saw_interp {
        return Err(PreflightError::Interpreter);
    }
    if saw_dynamic {
        return Err(PreflightError::DynamicSegment);
    }
    if !saw_load {
        return Err(PreflightError::BadProgramHeaders);
    }
    Ok(())
}

fn read_u16(bytes: &[u8], off: usize) -> Result<u16, PreflightError> {
    Ok(u16::from_le_bytes(read_array(bytes, off)?))
}

fn read_u32(bytes: &[u8], off: usize) -> Result<u32, PreflightError> {
    Ok(u32::from_le_bytes(read_array(bytes, off)?))
}

fn read_u64(bytes: &[u8], off: usize) -> Result<u64, PreflightError> {
    Ok(u64::from_le_bytes(read_array(bytes, off)?))
}

fn read_array<const N: usize>(bytes: &[u8], off: usize) -> Result<[u8; N], PreflightError> {
    let end = off.checked_add(N).ok_or(PreflightError::Truncated)?;
    let slice = bytes.get(off..end).ok_or(PreflightError::Truncated)?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct PhdrSpec {
        p_type: u32,
        p_offset: u64,
        p_filesz: u64,
    }

    fn write_u16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn elf_image(machine: u16, kind: u16, phdrs: &[PhdrSpec]) -> Vec<u8> {
        let phnum = u16::try_from(phdrs.len()).expect("phdr count fits u16");
        let ehdr = usize::from(ELF64_EHDR_SIZE);
        let phdr = usize::from(ELF64_PHDR_SIZE);
        let total = ehdr
            .checked_add(phdrs.len().checked_mul(phdr).expect("phdr table size"))
            .expect("image size");
        let mut buf = vec![0u8; total];
        buf[..4].copy_from_slice(&ELFMAG);
        buf[EI_CLASS] = ELFCLASS64;
        buf[EI_DATA] = ELFDATA2LSB;
        buf[EI_VERSION] = EV_CURRENT;
        write_u16(&mut buf, 16, kind);
        write_u16(&mut buf, 18, machine);
        write_u32(&mut buf, 20, u32::from(EV_CURRENT));
        write_u64(&mut buf, 32, u64::from(ELF64_EHDR_SIZE));
        write_u16(&mut buf, 52, ELF64_EHDR_SIZE);
        write_u16(&mut buf, 54, ELF64_PHDR_SIZE);
        write_u16(&mut buf, 56, phnum);
        for (i, phdr) in phdrs.iter().enumerate() {
            let at = ehdr + i * usize::from(ELF64_PHDR_SIZE);
            write_u32(&mut buf, at, phdr.p_type);
            write_u32(&mut buf, at + 4, 5);
            write_u64(&mut buf, at + 8, phdr.p_offset);
            write_u64(&mut buf, at + 32, phdr.p_filesz);
            write_u64(&mut buf, at + 40, phdr.p_filesz);
            write_u64(&mut buf, at + 48, 8);
        }
        buf
    }

    fn one_load(machine: u16, kind: u16) -> Vec<u8> {
        let load = PhdrSpec {
            p_type: PT_LOAD,
            p_offset: 0,
            p_filesz: u64::from(ELF64_EHDR_SIZE),
        };
        elf_image(machine, kind, &[load])
    }

    #[test]
    fn x86_64_pie_with_only_load_is_accepted() {
        let image = inspect_elf(&one_load(EM_X86_64, ET_DYN)).expect("static pie");
        assert_eq!(image.machine, Machine::X86_64);
        assert_eq!(image.kind, ElfKind::Dyn);
    }

    #[test]
    fn aarch64_exec_with_only_load_is_accepted() {
        let image = inspect_elf(&one_load(EM_AARCH64, ET_EXEC)).expect("static exec");
        assert_eq!(image.machine, Machine::Aarch64);
        assert_eq!(image.kind, ElfKind::Exec);
    }

    #[test]
    fn note_and_gnu_stack_do_not_reject_a_static_image() {
        let note = PhdrSpec {
            p_type: 4,
            p_offset: 0,
            p_filesz: 0,
        };
        let stack = PhdrSpec {
            p_type: 0x6474_e551,
            p_offset: 0,
            p_filesz: 0,
        };
        let load = PhdrSpec {
            p_type: PT_LOAD,
            p_offset: 0,
            p_filesz: 64,
        };
        let buf = elf_image(EM_X86_64, ET_EXEC, &[note, load, stack]);
        let image = inspect_elf(&buf).expect("note and stack are not dynamic");
        assert_eq!(image.machine, Machine::X86_64);
        assert_eq!(image.kind, ElfKind::Exec);
    }

    #[test]
    fn pt_interp_is_rejected_even_for_a_musl_loader_path() {
        let path = b"/lib/ld-musl-aarch64.so.1\0";
        let interp_off = u64::from(ELF64_EHDR_SIZE) + 2 * u64::from(ELF64_PHDR_SIZE);
        let mut buf = elf_image(
            EM_AARCH64,
            ET_DYN,
            &[
                PhdrSpec {
                    p_type: PT_LOAD,
                    p_offset: 0,
                    p_filesz: 64,
                },
                PhdrSpec {
                    p_type: PT_INTERP,
                    p_offset: interp_off,
                    p_filesz: u64::try_from(path.len()).expect("path"),
                },
            ],
        );
        buf.extend_from_slice(path);
        assert!(matches!(
            inspect_elf(&buf),
            Err(PreflightError::Interpreter)
        ));
    }

    #[test]
    fn pt_dynamic_without_interp_is_rejected() {
        let buf = elf_image(
            EM_X86_64,
            ET_DYN,
            &[
                PhdrSpec {
                    p_type: PT_LOAD,
                    p_offset: 0,
                    p_filesz: 64,
                },
                PhdrSpec {
                    p_type: PT_DYNAMIC,
                    p_offset: 0,
                    p_filesz: 0,
                },
            ],
        );
        assert!(matches!(
            inspect_elf(&buf),
            Err(PreflightError::DynamicSegment)
        ));
    }

    #[test]
    fn interp_is_reported_when_dynamic_precedes_it() {
        let buf = elf_image(
            EM_X86_64,
            ET_DYN,
            &[
                PhdrSpec {
                    p_type: PT_DYNAMIC,
                    p_offset: 0,
                    p_filesz: 0,
                },
                PhdrSpec {
                    p_type: PT_INTERP,
                    p_offset: 0,
                    p_filesz: 0,
                },
            ],
        );
        assert!(matches!(
            inspect_elf(&buf),
            Err(PreflightError::Interpreter)
        ));
    }

    #[test]
    fn class32_wrong_magic_and_em386_are_rejected() {
        let mut class32 = one_load(EM_X86_64, ET_DYN);
        class32[EI_CLASS] = 1;
        assert!(matches!(
            inspect_elf(&class32),
            Err(PreflightError::NotElf64)
        ));

        let mut magic = one_load(EM_X86_64, ET_EXEC);
        magic[0] = 0;
        assert!(matches!(inspect_elf(&magic), Err(PreflightError::NotElf)));
        assert!(matches!(
            inspect_elf(b"#!/bin/sh\n"),
            Err(PreflightError::NotElf)
        ));
        assert!(matches!(
            inspect_elf(b"!<arch>\n"),
            Err(PreflightError::NotElf)
        ));

        let em386 = one_load(3, ET_DYN);
        assert!(matches!(
            inspect_elf(&em386),
            Err(PreflightError::BadMachine)
        ));
    }

    #[test]
    fn truncated_phdr_table_is_rejected() {
        let mut buf = one_load(EM_X86_64, ET_DYN);
        buf.truncate(usize::from(ELF64_EHDR_SIZE) + 20);
        assert!(matches!(inspect_elf(&buf), Err(PreflightError::Truncated)));
    }

    #[test]
    fn phoff_past_the_buffer_is_rejected_without_a_huge_allocation() {
        let mut buf = one_load(EM_AARCH64, ET_EXEC);
        write_u64(&mut buf, 32, 10_000);
        assert!(matches!(inspect_elf(&buf), Err(PreflightError::Truncated)));
    }

    #[test]
    fn phnum_zero_and_sixty_five_are_rejected() {
        let mut zero = one_load(EM_X86_64, ET_DYN);
        write_u16(&mut zero, 56, 0);
        assert!(matches!(
            inspect_elf(&zero),
            Err(PreflightError::BadProgramHeaders)
        ));

        let loads = vec![
            PhdrSpec {
                p_type: PT_LOAD,
                p_offset: 0,
                p_filesz: 64,
            };
            65
        ];
        let sixty_five = elf_image(EM_X86_64, ET_EXEC, &loads);
        assert!(matches!(
            inspect_elf(&sixty_five),
            Err(PreflightError::BadProgramHeaders)
        ));
    }

    #[test]
    fn phentsize_and_ehsize_must_be_the_elf64_constants() {
        let mut phentsize = one_load(EM_X86_64, ET_DYN);
        write_u16(&mut phentsize, 54, 64);
        assert!(matches!(
            inspect_elf(&phentsize),
            Err(PreflightError::BadProgramHeaders)
        ));

        let mut ehsize = one_load(EM_X86_64, ET_DYN);
        write_u16(&mut ehsize, 52, 52);
        assert!(matches!(
            inspect_elf(&ehsize),
            Err(PreflightError::BadProgramHeaders)
        ));
    }

    #[test]
    fn relocatable_and_core_images_are_rejected() {
        assert!(matches!(
            inspect_elf(&one_load(EM_X86_64, 1)),
            Err(PreflightError::BadType)
        ));
        assert!(matches!(
            inspect_elf(&one_load(EM_AARCH64, 4)),
            Err(PreflightError::BadType)
        ));
    }

    #[test]
    fn big_endian_and_bad_version_are_rejected() {
        let mut data = one_load(EM_X86_64, ET_DYN);
        data[EI_DATA] = 2;
        assert!(matches!(
            inspect_elf(&data),
            Err(PreflightError::NotLittleEndian)
        ));

        let mut ident_version = one_load(EM_X86_64, ET_DYN);
        ident_version[EI_VERSION] = 0;
        assert!(matches!(
            inspect_elf(&ident_version),
            Err(PreflightError::BadVersion)
        ));

        let mut e_version = one_load(EM_X86_64, ET_DYN);
        write_u32(&mut e_version, 20, 0);
        assert!(matches!(
            inspect_elf(&e_version),
            Err(PreflightError::BadVersion)
        ));
    }

    #[test]
    fn shoff_zero_is_ignored_and_shoff_past_eof_is_truncated() {
        let mut inside = one_load(EM_X86_64, ET_DYN);
        let inside_end = u64::try_from(inside.len() - 1).expect("shoff");
        write_u64(&mut inside, 40, inside_end);
        assert!(inspect_elf(&inside).is_ok());

        let mut past = one_load(EM_X86_64, ET_DYN);
        let past_end = u64::try_from(past.len()).expect("shoff");
        write_u64(&mut past, 40, past_end);
        assert!(matches!(inspect_elf(&past), Err(PreflightError::Truncated)));
    }

    #[test]
    fn image_without_pt_load_is_rejected() {
        let buf = elf_image(
            EM_X86_64,
            ET_EXEC,
            &[PhdrSpec {
                p_type: 0,
                p_offset: 0,
                p_filesz: 0,
            }],
        );
        assert!(matches!(
            inspect_elf(&buf),
            Err(PreflightError::BadProgramHeaders)
        ));
    }

    #[test]
    fn empty_input_is_not_reported_as_too_large() {
        assert!(matches!(inspect_elf(&[]), Err(PreflightError::Empty)));
        assert!(!image_too_large(0));
    }

    #[test]
    fn size_predicate_caps_at_sixty_four_mebibytes() {
        assert_eq!(MAX_ELF_BYTES, 64 * 1024 * 1024);
        assert!(!image_too_large(MAX_ELF_BYTES));
        assert!(image_too_large(MAX_ELF_BYTES + 1));
        assert!(image_too_large(u64::MAX));
    }

    #[test]
    fn file_reader_uses_hand_built_bytes_and_maps_io() {
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let ok_path = dir.join(format!("boreas-preflight-{pid}-ok.elf"));
        let empty_path = dir.join(format!("boreas-preflight-{pid}-empty.elf"));
        let missing = dir.join(format!("boreas-preflight-{pid}-missing.elf"));
        let bytes = one_load(EM_AARCH64, ET_EXEC);
        std::fs::write(&ok_path, &bytes).expect("write candidate");
        std::fs::write(&empty_path, []).expect("write empty");
        let image = inspect_elf_file(&ok_path).expect("file inspect");
        assert_eq!(image, inspect_elf(&bytes).expect("slice inspect"));
        assert!(matches!(
            inspect_elf_file(&empty_path),
            Err(PreflightError::Empty)
        ));
        assert!(matches!(
            inspect_elf_file(&missing),
            Err(PreflightError::Io(_))
        ));
        let _ = std::fs::remove_file(&ok_path);
        let _ = std::fs::remove_file(&empty_path);
    }
}
