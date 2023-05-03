pub mod header;

use self::header::Header;

#[derive(Debug, PartialEq, PartialOrd)]
pub struct ELF {
    pub header: Header,
}
