use crate::elf::header::{Class, Data, Header, Ident, Machine, OsAbi, Type, Version, ELF_MAGIC};
use nom::{
    bytes::streaming::tag,
    combinator::map,
    multi::count,
    number::complete::{le_u16, le_u32, le_u64, u8 as read_u8},
    IResult,
};

pub fn parse_magic_number(raw: &[u8]) -> IResult<&[u8], &[u8]> {
    tag(ELF_MAGIC)(raw)
}

pub fn parse_class(raw: &[u8]) -> IResult<&[u8], Class> {
    map(read_u8, Class::from)(raw)
}

pub fn parse_data(raw: &[u8]) -> IResult<&[u8], Data> {
    map(read_u8, Data::from)(raw)
}

pub fn parse_version(raw: &[u8]) -> IResult<&[u8], Version> {
    map(read_u8, Version::from)(raw)
}

pub fn parse_os_api(raw: &[u8]) -> IResult<&[u8], OsAbi> {
    map(read_u8, OsAbi::from)(raw)
}

pub fn parse_abi_version(raw: &[u8]) -> IResult<&[u8], u8> {
    read_u8(raw)
}

pub fn parse_machine(raw: &[u8]) -> IResult<&[u8], Machine> {
    map(le_u16, Machine::from)(raw)
}

pub fn parse_ident(raw: &[u8]) -> IResult<&[u8], Ident> {
    let (r, _) = parse_magic_number(raw)?;
    let (r, class) = parse_class(r)?;
    let (r, data) = parse_data(r)?;
    let (r, version) = parse_version(r)?;
    let (r, osabi) = parse_os_api(r)?;
    let (r, abi_version) = parse_abi_version(r)?;
    let (r, _) = count(read_u8, 7)(r)?;
    Ok((
        r,
        Ident {
            class,
            data,
            version,
            os_abi: osabi,
            abi_version,
        },
    ))
}

pub fn parse_type(raw: &[u8]) -> IResult<&[u8], Type> {
    map(le_u16, Type::from)(raw)
}

pub fn parse_elf_header(raw: &[u8]) -> IResult<&[u8], Header> {
    let (r, ident) = parse_ident(raw)?;
    let (r, ty) = parse_type(r)?;
    let (r, machine) = parse_machine(r)?;
    let (r, version) = le_u32(r)?;
    let (r, entry) = le_u64(r)?;
    let (r, ph_off) = le_u64(r)?;
    let (r, sh_off) = le_u64(r)?;
    let (r, flags) = le_u32(r)?;
    let (r, eh_size) = le_u16(r)?;
    let (r, ph_ent_size) = le_u16(r)?;
    let (r, ph_num) = le_u16(r)?;
    let (r, sh_ent_size) = le_u16(r)?;
    let (r, sh_num) = le_u16(r)?;
    let (r, sh_str_ndx) = le_u16(r)?;
    Ok((
        r,
        Header {
            ident,
            ty,
            machine,
            version,
            entry,
            ph_off,
            sh_off,
            flags,
            eh_size,
            ph_ent_size,
            ph_num,
            sh_ent_size,
            sh_num,
            sh_str_ndx,
        },
    ))
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use super::*;

    fn helper<'a, T, P>(parser: P, input: &'a [u8], expected: T)
    where
        T: Debug + PartialEq + PartialOrd,
        P: Fn(&'a [u8]) -> IResult<&'a [u8], T>,
    {
        let result = parser(input);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().1, expected);
    }

    fn helper_fail<'a, T, P>(parser: P, input: &'a [u8])
    where
        T: Debug + PartialEq + PartialOrd,
        P: Fn(&'a [u8]) -> IResult<&'a [u8], T>,
    {
        let result = parser(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_magic_number() {
        helper(parse_magic_number, ELF_MAGIC, ELF_MAGIC);
    }

    #[test]
    fn test_parse_magic_number_fail() {
        helper_fail(parse_magic_number, b"\x7fFLF");
    }

    #[test]
    fn test_parse_class() {
        for (input, expected) in [
            (b"\x01", Class::ELF32),
            (b"\x02", Class::ELF64),
            (b"\x00", Class::None),
            (b"\x03", Class::Unknown),
        ] {
            helper(parse_class, input, expected);
        }
    }

    #[test]
    fn test_parse_data() {
        for (input, expected) in [
            (b"\x00", Data::None),
            (b"\x01", Data::Lsb),
            (b"\x02", Data::Msb),
            (b"\x03", Data::Unknown),
        ] {
            helper(parse_data, input, expected);
        }
    }

    #[test]
    fn test_parse_version() {
        for (input, expected) in [(b"\x01", Version::Current), (b"\x02", Version::Unknown)] {
            helper(parse_version, input, expected);
        }
    }

    #[test]
    fn test_parse_osabi() {
        for (input, expected) in [
            (b"\x00", OsAbi::SystemV),
            (b"\x01", OsAbi::HpUx),
            (b"\x02", OsAbi::NetBsd),
            (b"\x03", OsAbi::Linux),
            (b"\x04", OsAbi::GnuHurd),
            (b"\x06", OsAbi::Solaris),
            (b"\x07", OsAbi::Aix),
            (b"\x08", OsAbi::Irix),
            (b"\x09", OsAbi::FreeBsd),
            (b"\x0a", OsAbi::Tru64),
            (b"\x0b", OsAbi::NovellModesto),
            (b"\x0c", OsAbi::OpenBsd),
            (b"\x0d", OsAbi::OpenVms),
            (b"\x0e", OsAbi::NonStopKernel),
            (b"\x0f", OsAbi::Aros),
            (b"\x10", OsAbi::FenixOs),
            (b"\x11", OsAbi::CloudAbi),
            (b"\x12", OsAbi::OpenVos),
            (b"\x13", OsAbi::Unknown),
        ] {
            helper(parse_os_api, input, expected);
        }
    }

    #[test]
    fn test_abi_version() {
        for (input, expected) in [(b"\x00", 0), (b"\x01", 1)] {
            helper(parse_abi_version, input, expected);
        }
    }

    #[test]
    fn test_parse_identification() {
        helper(
            parse_ident,
            &[
                0x7f, 0x45, 0x4c, 0x46, // magic number
                0x02, // data
                0x01, // version
                0x01, // os abi
                0x00, // abi version
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding
            ],
            Ident {
                class: Class::ELF64,
                data: Data::Lsb,
                version: Version::Current,
                os_abi: OsAbi::SystemV,
                abi_version: 0x00,
            },
        );
    }

    #[test]
    fn elf_header64_test() {
        helper(
            parse_elf_header,
            &[
                0x7f, 0x45, 0x4c, 0x46, // magic number
                0x02, // data
                0x01, // version
                0x01, // os abi
                0x00, // abi version
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding
                0x00, 0x03, // type
                0x00, 0x3e, // machine
                0x00, 0x01, 0x00, 0x00, // version
                0x00, 0x60, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, // entry
                0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ph_off
                0x00, 0x88, 0x1c, 0x42, 0x00, 0x00, 0x00, 0x00, // sh_off
                0x00, 0x00, 0x00, 0x00, // flags
                0x00, 0x40, // eh_size
                0x00, 0x38, // ph_ent_size
                0x00, 0x0c, // ph_num
                0x00, 0x40, // sh_ent_size
                0x00, 0x2b, // sh_num
                0x00, 0x2a, // sh_str_ndx
                0x00,
            ],
            Header {
                ident: Ident {
                    class: Class::ELF64,
                    data: Data::Lsb,
                    version: Version::Current,
                    os_abi: OsAbi::SystemV,
                    abi_version: 0x00,
                },
                ty: Type::Dyn,
                machine: Machine::X86_64,
                version: 0x01,
                entry: 0x9560,
                ph_off: 64,
                sh_off: 4332680,
                flags: 0x0,
                eh_size: 64,
                ph_ent_size: 56,
                ph_num: 12,
                sh_ent_size: 64,
                sh_num: 43,
                sh_str_ndx: 42,
            },
        );
    }
}
