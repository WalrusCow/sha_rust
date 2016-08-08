use std::env;
use std::fs::File;
use std::io::Read;
use std::io::Write;

mod sha;

fn main() {
    let args: Vec<String> = env::args().collect();
    let file_path = &args[1];
    let mut file_handle = match File::open(file_path) {
        Ok(fh) => fh,
        Err(_) => {
            println!("Could not open file {}", file_path);
            return;
        },
    };

    let mut write_handle = match File::create("./awtpoot") {
        Ok(f) => f,
        Err(e) => {
            println!("Fuck {}", e);
            return;
        },
    };

    let mut buf: [u8; 4096] = [0; 4096];
    let mut sha_thing = sha::Sha256Digestion::new();

    loop {
        let bytes_read = match file_handle.read(&mut buf) {
            Ok(count) => count,
            Err(_) => {
                println!("Error reading file.");
                return;
            },
        };

        if bytes_read == 0 {
            println!("Doooone");
            break;
        } else {
            for b in buf.iter_mut().take(bytes_read) {
                sha_thing.add_byte(*b);
            }
        }
    }
    let m = sha_thing.digest();
    write_handle.write_all(&m).unwrap();
}
