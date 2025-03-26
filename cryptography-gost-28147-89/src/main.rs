use hex;
use rand::Rng;


const SBOX:[[u8; 16]; 8] = [
    [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
    [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
    [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
    [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
    [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
    [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
    [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
    [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12]
];

fn rot_left(num: u32, bits: u32)-> u32 {
    if bits > 32 {
        (num << bits) | (num >> (32- (bits % 32)))
    } else if bits == 0 {
        (num << bits) | (num >> (32 - 1 - bits))
    } else {
        (num << bits) | (num >> (32 - bits))
    }
}

// fn key_gen256() -> String {
//     (0..32)
//     .map(|_| format!("{:02x}", rand::thread_rng().gen_range(48..57)))
//     .collect::<String>()
// }

fn word_addition(mut message: String) -> String {
    while message.len() % 8 != 0 {
        message.push('a');
    }
    message
}

fn round_keys(key: &str, op: char) -> Vec<u32> {
    let mut result: Vec<u32> = Vec::new();
    let mut split_key:Vec<u32> = Vec::new();
    for i in 0..8 {
        split_key.push(u32::from_str_radix(&key[0+i*8..8+i*8], 16).unwrap());
    }
    if op == 'e' {
        for _i in 0..3 {
            result = [&result[..], &split_key[..]].concat();
        }   
        result.reverse();
        result = [&result[..], &split_key[..]].concat();
    } else {
        result = [&result[..], &split_key[..]].concat();
        result.reverse();
        for _i in 0..3 {
            result = [&result[..], &split_key[..]].concat();
        }   
    }
    result
}


fn encrypt_block(block: &str, r_keys: Vec<u32>, op: char) -> String{
    let mut left = u32::from_str_radix(&block[0..block.len()/2], 16).unwrap();
    let mut right = u32::from_str_radix(&block[block.len()/2..], 16).unwrap();
    let mut s: u32;
    for i in 0..32 {
        s = ((left as u64 + r_keys[i] as u64) % u32::MAX as u64) as u32;
        // println!("{}", &s);
        let mut s_arr: Vec<u8> = format!("{:02x}", s)
            .chars()
            .map(|x| u8::from_str_radix(x.to_string().as_str(), 16).unwrap())
            .collect::<Vec<u8>>();
        // println!("{:?}", &s_arr);
        for (s_elem, value) in s_arr.clone().iter_mut().enumerate() {
            s_arr[s_elem] = SBOX[s_elem][*value as usize];
        }
        // println!("{:?}", &s_arr);
        s =  u32::from_str_radix(s_arr.iter().map(|x| format!("{:x}", x)).collect::<String>().as_str(), 16).unwrap();
        s = rot_left(s, 11);
        s = s ^ right;
        right = left;
        left = s;
    }

    let res = format!("{:02x}", right) + format!("{:02x}", left).as_str();
    res
}


fn  crypt_message(message: &str, key: &str, op: char) -> String{
    let mut message = word_addition(message.to_string());
    if op == 'e' {message = hex::encode(message)}
    
    let r_keys: Vec<u32> = round_keys(key, op);
    let step: usize = message.len() / 16;

    let mut enc_message: String = String::new();
    
    for i in 0..step{
        let block: &str = &message[0+i*16..16+i*16];
        let val = encrypt_block(block, r_keys.clone(), op);
        enc_message.push_str(&val);
    }
    enc_message
} 

fn main() {
    let message = &word_addition("lenya voronin was an opportunist and we killed him".to_string())[..];
    let key = "a55275ad61a2c973fe3727b26b9001d353bc0e51e12b2db0c55bfa9a87cfd32d";
    let result = crypt_message(message, key, 'e');
    let res = crypt_message(&result[..], key, 'd');
    println!("{:?}", hex::encode(message));
    println!("{:?}", key);
    println!("{:?}", res);
    println!("{:?}", hex::decode(res).unwrap().iter().map(|x| *x as char).collect::<String>());
}
