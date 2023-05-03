// Ref: https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#:~:text=header%5B4%5D-,File%20header,-%5Bedit%5D

// NOTE: only suppoort 64-bit ELF
#[derive(Debug, PartialEq, PartialOrd)]
pub struct Header {
    pub ident: Ident,
    pub ty: Type,
    pub machine: Machine,
    pub version: u32,
    // memory address of the entry point
    pub entry: u64,
    // points to the start of the program header table
    pub ph_off: u64,
    // points to the start of the section header table
    pub sh_off: u64,
    // depends on the target architecture.
    pub flags: u32,
    // size of this header
    pub eh_size: u16,
    // size of a program header table entry
    pub ph_ent_size: u16,
    // number of entries in the program header table
    pub ph_num: u16,
    // size of a section header table entry
    pub sh_ent_size: u16,
    // number of entries in the section header table
    pub sh_num: u16,
    // section header table index of the entry associated with the section name string table
    pub sh_str_ndx: u16,
}

#[derive(Debug, PartialEq, PartialOrd)]
pub struct Ident {
    pub class: Class,
    pub data: Data,
    pub version: Version,
    pub os_abi: OsAbi,
    pub abi_version: u8,
}

pub static ELF_MAGIC: &[u8; 4] = b"\x7fELF";

#[derive(Debug, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Class {
    None = 0x0,  // invalid class
    Bit32 = 0x1, // 32-bit objects
    Bit64 = 0x2, // 64-bit objects
    Unknown,
}

impl From<u8> for Class {
    fn from(value: u8) -> Self {
        match value {
            0x0 => Class::None,
            0x1 => Class::Bit32,
            0x2 => Class::Bit64,
            _ => Class::Unknown,
        }
    }
}

#[derive(Debug, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Data {
    None = 0x0, // invalid data encoding
    Lsb = 0x1,  // little endian
    Msb = 0x2,  // big endian
    Unknown,
}

impl From<u8> for Data {
    fn from(value: u8) -> Self {
        match value {
            0x0 => Data::None,
            0x1 => Data::Lsb,
            0x2 => Data::Msb,
            _ => Data::Unknown,
        }
    }
}

#[derive(Debug, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Version {
    Current = 0x1,
    Unknown,
}

impl From<u8> for Version {
    fn from(value: u8) -> Self {
        match value {
            0x1 => Version::Current,
            _ => Version::Unknown,
        }
    }
}

#[derive(Debug, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum OsAbi {
    SystemV = 0x0,
    HpUx = 0x1,
    NetBsd = 0x2,
    Linux = 0x3,
    GnuHurd = 0x4,
    Solaris = 0x6,
    Aix = 0x7,
    Irix = 0x8,
    FreeBsd = 0x9,
    Tru64 = 0x10,
    NovellModesto = 0x11,
    OpenBsd = 0x12,
    OpenVms = 0x13,
    NonStopKernel = 0x14,
    Aros = 0x15,
    FenixOs = 0x16,
    CloudAbi = 0x17,
    OpenVos = 0x18,
    Unknown,
}

impl From<u8> for OsAbi {
    fn from(value: u8) -> Self {
        match value {
            0x0 => OsAbi::SystemV,
            0x1 => OsAbi::HpUx,
            0x2 => OsAbi::NetBsd,
            0x3 => OsAbi::Linux,
            0x4 => OsAbi::GnuHurd,
            0x6 => OsAbi::Solaris,
            0x7 => OsAbi::Aix,
            0x8 => OsAbi::Irix,
            0x9 => OsAbi::FreeBsd,
            0xA => OsAbi::Tru64,
            0xB => OsAbi::NovellModesto,
            0xC => OsAbi::OpenBsd,
            0xD => OsAbi::OpenVms,
            0xE => OsAbi::NonStopKernel,
            0xF => OsAbi::Aros,
            0x10 => OsAbi::FenixOs,
            0x11 => OsAbi::CloudAbi,
            0x12 => OsAbi::OpenVos,
            _ => OsAbi::Unknown,
        }
    }
}

// ELF's file type
#[derive(Debug, PartialEq, PartialOrd)]
pub enum Type {
    None = 0x0,
    Rel = 0x1,
    Exec = 0x2,
    Dyn = 0x3,
    Core = 0x4,
    Loos = 0xfe00,
    Hios = 0xfeff,
    Loproc = 0xff00,
    Hiproc = 0xffff,
    Unknown,
}

impl From<u16> for Type {
    fn from(value: u16) -> Self {
        match value {
            0x0 => Type::None,
            0x1 => Type::Rel,
            0x2 => Type::Exec,
            0x3 => Type::Dyn,
            0x4 => Type::Core,
            0xfe00 => Type::Loos,
            0xfeff => Type::Hios,
            0xff00 => Type::Loproc,
            0xffff => Type::Hiproc,
            _ => Type::Unknown,
        }
    }
}

#[derive(Debug, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum Machine {
    None = 0x0,
    AtTWe32100 = 0x1,
    Sparc = 0x2,
    X86 = 0x3,
    M68k = 0x4,
    M88k = 0x5,
    Iamcu = 0x6,
    IbmSystem370 = 0x7,
    Mips = 0x8,
    S370 = 0x9,
    MipsRs3Le = 0xA,
    Parisc = 0xE,
    I80960 = 0x13,
    PowerPc = 0x14,
    PowerPc64 = 0x15,
    S390 = 0x16,
    Spu = 0x17,
    NecV800 = 0x24,
    FujitsuFr20 = 0x25,
    TrWRh32 = 0x26,
    MotorolaRce = 0x27,
    Arm = 0x28,
    Alpha = 0x29,
    SuperH = 0x2A,
    SparcV9 = 0x2B,
    Tricore = 0x2C,
    Arc = 0x2D,
    H8_300 = 0x2E,
    H8_300H = 0x2F,
    H8S = 0x30,
    H8_500 = 0x31,
    Ia64 = 0x32,
    MipsX = 0x33,
    Coldfire = 0x34,
    M68HC12 = 0x35,
    Mma = 0x36,
    Pcp = 0x37,
    Ncpu = 0x38,
    Ndr1 = 0x39,
    Starcore = 0x3A,
    Me16 = 0x3B,
    St100 = 0x3C,
    Tinyj = 0x3D,
    X86_64 = 0x3E,
    Pdsp = 0x3F,
    Pdp10 = 0x40,
    Pdp11 = 0x41,
    Fx66 = 0x42,
    St9plus = 0x43,
    St7 = 0x44,
    Mc68HC16 = 0x45,
    Mc68HC11 = 0x46,
    Mc68HC08 = 0x47,
    Mc68HC05 = 0x48,
    Svx = 0x49,
    St19 = 0x4A,
    Vax = 0x4B,
    Axis = 0x4C,
    Infineon = 0x4D,
    Element14 = 0x4E,
    Latticemico32 = 0x4F,
    TMS320C6000 = 0x8C,
    McstElbrus = 0xAF,
    Arm64 = 0xB7,
    Z80 = 0xDC,
    RiscV = 0xF3,
    Bpf = 0xF7,
    Wdc65816 = 0x101,
    Unknown,
}

impl From<u16> for Machine {
    fn from(value: u16) -> Self {
        match value {
            0x0 => Machine::None,
            0x1 => Machine::AtTWe32100,
            0x2 => Machine::Sparc,
            0x3 => Machine::X86,
            0x4 => Machine::M68k,
            0x5 => Machine::M88k,
            0x6 => Machine::Iamcu,
            0x7 => Machine::IbmSystem370,
            0x8 => Machine::Mips,
            0x9 => Machine::S370,
            0xA => Machine::MipsRs3Le,
            0xE => Machine::Parisc,
            0x13 => Machine::I80960,
            0x14 => Machine::PowerPc,
            0x15 => Machine::PowerPc64,
            0x16 => Machine::S390,
            0x17 => Machine::Spu,
            0x24 => Machine::NecV800,
            0x25 => Machine::FujitsuFr20,
            0x26 => Machine::TrWRh32,
            0x27 => Machine::MotorolaRce,
            0x28 => Machine::Arm,
            0x29 => Machine::Alpha,
            0x2A => Machine::SuperH,
            0x2B => Machine::SparcV9,
            0x2C => Machine::Tricore,
            0x2D => Machine::Arc,
            0x2E => Machine::H8_300,
            0x2F => Machine::H8_300H,
            0x30 => Machine::H8S,
            0x31 => Machine::H8_500,
            0x32 => Machine::Ia64,
            0x33 => Machine::MipsX,
            0x34 => Machine::Coldfire,
            0x35 => Machine::M68HC12,
            0x36 => Machine::Mma,
            0x37 => Machine::Pcp,
            0x38 => Machine::Ncpu,
            0x39 => Machine::Ndr1,
            0x3A => Machine::Starcore,
            0x3B => Machine::Me16,
            0x3C => Machine::St100,
            0x3D => Machine::Tinyj,
            0x3E => Machine::X86_64,
            0x3F => Machine::Pdsp,
            0x40 => Machine::Pdp10,
            0x41 => Machine::Pdp11,
            0x42 => Machine::Fx66,
            0x43 => Machine::St9plus,
            0x44 => Machine::St7,
            0x45 => Machine::Mc68HC16,
            0x46 => Machine::Mc68HC11,
            0x47 => Machine::Mc68HC08,
            0x48 => Machine::Mc68HC05,
            0x49 => Machine::Svx,
            0x4A => Machine::St19,
            0x4B => Machine::Vax,
            0x4C => Machine::Axis,
            0x4D => Machine::Infineon,
            0x4E => Machine::Element14,
            0x4F => Machine::Latticemico32,
            0x8C => Machine::TMS320C6000,
            0xAF => Machine::McstElbrus,
            0xB7 => Machine::Arm64,
            0xDC => Machine::Z80,
            0xF3 => Machine::RiscV,
            0xF7 => Machine::Bpf,
            0x101 => Machine::Wdc65816,
            _ => Machine::Unknown,
        }
    }
}
