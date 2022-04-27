use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about=None)]
struct Args {
    #[clap(short, long)]
    message: String,
}

fn choice(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn majority(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

fn sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

fn phi0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

fn phi1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

fn pad_message(message: &str) -> Vec<u8> {
    // Convert string message to bytes
    let mut message_bytes = message.as_bytes().to_vec();

    // Calculate length of message in bits
    let message_len = message_bytes.len() * 8;

    // Add 1000_0000
    message_bytes.push(0x80);

    // Fill message with 0s until length is 448 mod 512
    while (message_bytes.len() % 64) != 56 {
        message_bytes.push(0);
    }

    // Fill last 8 bytes with the length of the message
    message_bytes.extend(message_len.to_be_bytes());

    message_bytes
}

fn prepare_message_schedule(block: &[u8]) -> [u32; 64] {
    let mut w = [0; 64];

    for t in 0..16 {
        let from = t * 4;
        let to = from + 4;
        // block[from..to] is a [u8; 4] array
        // try_into() coerces [u8; 4] to [u8]
        w[t] = u32::from_be_bytes(block[from..to].try_into().unwrap());
    }

    for t in 16..64 {
        w[t] = phi1(w[t - 2])
            .wrapping_add(w[t - 7])
            .wrapping_add(phi0(w[t - 15]))
            .wrapping_add(w[t - 16]);
    }

    w
}

// Thanks, github copilot <3
const CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn run_sha256_algorithm(args: &Args) -> String {
    // Pad message, making sure it is a multiple of 64 bytes
    let message_bytes = pad_message(&args.message);

    // Set initial hash values
    let mut h0: u32 = 0x6a09e667;
    let mut h1: u32 = 0xbb67ae85;
    let mut h2: u32 = 0x3c6ef372;
    let mut h3: u32 = 0xa54ff53a;
    let mut h4: u32 = 0x510e527f;
    let mut h5: u32 = 0x9b05688c;
    let mut h6: u32 = 0x1f83d9ab;
    let mut h7: u32 = 0x5be0cd19;

    // Loop through the message in 64-byte blocks
    for block in message_bytes.chunks(64) {
        let message_schedule = prepare_message_schedule(block);

        // Set working variables
        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        let mut f = h5;
        let mut g = h6;
        let mut h = h7;

        // Do some algorithmic magic for every byte in the block
        for t in 0..64 {
            let t1 = h
                .wrapping_add(sigma1(e))
                .wrapping_add(choice(e, f, g))
                .wrapping_add(CONSTANTS[t])
                .wrapping_add(message_schedule[t]);
            let t2 = sigma0(a).wrapping_add(majority(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        // Update hash values
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
        h5 = h5.wrapping_add(f);
        h6 = h6.wrapping_add(g);
        h7 = h7.wrapping_add(h);
    }

    // Returns the formatted hash values
    format!(
        "{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
        h0, h1, h2, h3, h4, h5, h6, h7,
    )
}

fn main() {
    // Parse input arguments
    let args = Args::parse();
    let result = run_sha256_algorithm(&args);
    println!("{}", result);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_test() {
        let args = Args {
            message: "".to_string(),
        };
        let result = run_sha256_algorithm(&args);
        assert_eq!(
            result,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn nist_1_test() {
        let args = Args {
            message: "abc".to_string(),
        };
        let result = run_sha256_algorithm(&args);
        assert_eq!(
            result,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn nist_3_test() {
        let args = Args {
            message: "a".repeat(1_000_000).to_string(),
        };
        let result = run_sha256_algorithm(&args);
        assert_eq!(
            result,
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }
}
