use std::env;
use std::fs::File;

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

    let sha_sum = sha::sha256sum_read(&mut file_handle);
    for b in sha_sum.iter() {
        print!("{:0>2x} ", b);
    }
    println!("");
}
