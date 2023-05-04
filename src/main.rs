use std::fs;
use std::{env, process};

use elf_parser::parse_elf_header;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args();
    let file_path = args.nth(1);
    let Some(file_path) =file_path else {
        eprintln!("usage: {} <file>", args.next().expect("not found argument 0"));
        process::exit(1);
    };

    let raw = fs::read(file_path)?;
    let result = parse_elf_header(&raw);

    match result {
        Ok(out) => {
            let header = out.1;
            println!("ELF Header:");
            println!("  Class: {:?}", header.ident.class);
            println!("  Data: {:?}", header.ident.data);
            println!("  Version: {}", header.version);
            println!("  OS/ABI: {:?}", header.ident.os_abi);
            println!("  Type: {:?}", header.ty);
            println!("  Machine: {:?}", header.machine);
            println!("  Version: {:?}", header.version);
            println!("  Entry point address: 0x{:x}", header.entry);
            println!("  Start of program headers: {:?}", header.ph_off);
            println!("  Start of section headers: {:?}", header.sh_off);
            println!("  Flags: 0x{:x}", header.flags);
            println!("  Size of this header: {} (bytes)", header.eh_size);
            println!("  Size of program headers: {} (bytes)", header.ph_ent_size);
            println!("  Number of program headers: {}", header.ph_num);
            println!("  Size of section headers: {}", header.sh_ent_size);
            println!("  Number of section headers: {}", header.sh_num);
            println!("  Section header string table index: {}", header.sh_str_ndx);
        }
        Err(e) => eprintln!("failed to parse, error: {:#?}", e),
    }
    Ok(())
}
