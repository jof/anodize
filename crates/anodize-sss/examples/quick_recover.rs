use anodize_sss::{reconstruct, Share};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: quick_recover SHARE1 SHARE2");
        std::process::exit(1);
    }
    let s1 = Share::from_words(&args[1], 32).expect("share1 decode");
    let s2 = Share::from_words(&args[2], 32).expect("share2 decode");
    eprintln!("share1: index={}", s1.index);
    eprintln!("share2: index={}", s2.index);

    let pin = reconstruct(&[s1, s2], 2).expect("reconstruct");
    let pin_hex = hex::encode(&pin);
    let pin_hash = hex::encode(anodize_sss::pin_verify_hash(&pin));
    eprintln!("pin_verify_hash: {pin_hash}");
    println!("{pin_hex}");
}
