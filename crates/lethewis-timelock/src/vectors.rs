// SPDX-FileCopyrightText: 2026 Alan Wisper <https://alanwisper.com>
// SPDX-License-Identifier: AGPL-3.0-only

//! Values from outside this library that the tests check against.

extern crate std;

use std::vec::Vec;

use crate::network::{Network, SIGNATURE_LEN};

/// Beacons of quicknet, as `https://api.drand.sh/<chain hash>/public/<round>` gives them.
pub(crate) const BEACONS: [(u64, &str); 6] = [
    (
        1,
        concat!(
            "b55e7cb2d5c613ee0b2e28d6750aabbb78c39dcc96bd9d38",
            "c2c2e12198df95571de8e8e402a0cc48871c7089a2b3af4b",
        ),
    ),
    (
        2,
        concat!(
            "b6b6a585449b66eb12e875b64fcbab3799861a00e4dbf092",
            "d99e969a5eac57dd3f798acf61e705fe4f093db926626807",
        ),
    ),
    (
        1000,
        concat!(
            "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b1957",
            "6350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39",
        ),
    ),
    (
        1_000_000,
        concat!(
            "83ad29e4c409f9470fc2ef02f90214df49e02b441a1a241a",
            "82d622d9f608ef98fd8b11a029f1bee9d9e83b45088abe72",
        ),
    ),
    (
        10_000_000,
        concat!(
            "a187c9f5800521e986b5658924696682071ce7ae965486e8",
            "fd08bc2c4758bdbb9ed9ecb7beee392a38214e321ecd434f",
        ),
    ),
    (
        33_512_211,
        concat!(
            "b5e488939196e9e4ab7de45e1d0b6e6a8e26ce2f8b0a30f9",
            "6a0c795ac8d48f54a8de0065cf6cca64ae305973e403e5d1",
        ),
    ),
];

pub(crate) fn unhex<const N: usize>(text: &str) -> [u8; N] {
    let mut bytes = [0; N];
    assert_eq!(text.len(), 2 * N);
    for (byte, &[high, low]) in bytes.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        let digit = |c: u8| char::from(c).to_digit(16).unwrap();
        *byte = u8::try_from(digit(high) * 16 + digit(low)).unwrap();
    }
    bytes
}

pub(crate) fn signature_of(round: u64) -> [u8; SIGNATURE_LEN] {
    let (_, signature) = BEACONS.iter().find(|(at, _)| *at == round).unwrap();
    unhex(signature)
}

/// The pairing of the generators of G1 and G2, as the reference implementation of tlock hashes it:
/// twelve coefficients, most significant first.
pub(crate) const PAIRING_OF_GENERATORS: [&str; 12] = [
    "0f41e58663bf08cf068672cbd01a7ec73baca4d72ca93544deff686bfd6df543d48eaa24afe47e1efde449383b676631",
    "04c581234d086a9902249b64728ffd21a189e87935a954051c7cdba7b3872629a4fafc05066245cb9108f0242d0fe3ef",
    "03350f55a7aefcd3c31b4fcb6ce5771cc6a0e9786ab5973320c806ad360829107ba810c5a09ffdd9be2291a0c25a99a2",
    "11b8b424cd48bf38fcef68083b0b0ec5c81a93b330ee1a677d0d15ff7b984e8978ef48881e32fac91b93b47333e2ba57",
    "06fba23eb7c5af0d9f80940ca771b6ffd5857baaf222eb95a7d2809d61bfe02e1bfd1b68ff02f0b8102ae1c2d5d5ab1a",
    "19f26337d205fb469cd6bd15c3d5a04dc88784fbb3d0b2dbdea54d43b2b73f2cbb12d58386a8703e0f948226e47ee89d",
    "018107154f25a764bd3c79937a45b84546da634b8f6be14a8061e55cceba478b23f7dacaa35c8ca78beae9624045b4b6",
    "01b2f522473d171391125ba84dc4007cfbf2f8da752f7c74185203fcca589ac719c34dffbbaad8431dad1c1fb597aaa5",
    "193502b86edb8857c273fa075a50512937e0794e1e65a7617c90d8bd66065b1fffe51d7a579973b1315021ec3c19934f",
    "1368bb445c7c2d209703f239689ce34c0378a68e72a6b3b216da0e22a5031b54ddff57309396b38c881c4c849ec23e87",
    "089a1c5b46e5110b86750ec6a532348868a84045483c92b7af5af689452eafabf1a8943e50439f1d59882a98eaa0170f",
    "1250ebd871fc0a92a7b2d83168d0d727272d441befa15c503dd8e90ce98db3e7b6d194f60839c508a84305aaca1789b6",
];

/// A lock the reference tool wrote on quicknet for round 746511, holding "hello world" and a new
/// line, in its armor.
pub(crate) const REFERENCE_LOCK: [&str; 8] = [
    "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDc0NjUxMSA1MmRiOWJhNzBl",
    "MGNjMGY2ZWFmNzgwM2RkMDc0NDdhMWY1NDc3NzM1ZmQzZjY2MTc5MmJhOTQ2MDBj",
    "ODRlOTcxCmtEWkJHdnVveWVDeGI5MVBYVWgvY2pOWUdrcElRQU95dFhvUk9WbUNh",
    "dkVaeUN3OUVMR1ZBWE4zcTZKMlBrYmkKQURyQWVNdWJuMyswODJOVDNSR1ZCMDBv",
    "Nzg2MHhVMnl3N0pCbVV4eFY0UGJHZTREaWh2NWJrKzVibzVHRkRJUwpGaGFoS21R",
    "UVFrSDJyOEF6VkNHRXc5ekxPaGRQMktlbmxUSFhEREplc3JnCi0tLSBpMndTSkZI",
    "MnFveWFqSnhTOXhEazJSN2E2dWRKNWZReDBiUlRnZnFYak1zCnw2ccNps+whQe+p",
    "qVlJAYqlmEB4qFMRif9Z518uFEfAX5e5AyeQtVJcdfU3",
];

/// The signature of round 746511 of quicknet.
pub(crate) const REFERENCE_SIGNATURE: &str = concat!(
    "a9080432fbe9dd72d25a78c092f6d507a418fd9f985f8b5e",
    "99ac380dc63d6d203198f4160e353055e9fbd8fccdfdbd37",
);

/// The test network of the same scheme as quicknet, quicknet-t.
pub(crate) const TESTNET: Network = Network {
    chain_hash: unhex_const(concat!(
        "cc9c398442737cbd141526600919edd6",
        "9f1d6f9b4adb67e4d912fbc64341a9a5",
    )),
    public_key: unhex_const(concat!(
        "b15b65b46fb29104f6a4b5d1e11a8da6344463973d423661",
        "bb0804846a0ecd1ef93c25057f1c0baab2ac53e56c662b66",
        "072f6d84ee791a3382bfb055afab1e6a375538d8ffc45110",
        "4ac971d2dc9b168e2d3246b0be2015969cbaac298f6502da",
    )),
    genesis: 1_689_232_296,
    period: 3,
};

/// A lock the reference tool wrote on quicknet-t for round 5423142, holding 1063 bytes of text.
pub(crate) const TESTNET_LOCK: [&str; 30] = [
    "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHRsb2NrIDU0MjMxNDIgY2M5YzM5ODQ0",
    "MjczN2NiZDE0MTUyNjYwMDkxOWVkZDY5ZjFkNmY5YjRhZGI2N2U0ZDkxMmZiYzY0",
    "MzQxYTlhNQpoek0rRzZyMFgvcjdxc0tlUnlyZ2wwbUc2ZFlDajdTeFhNUncvY2ZV",
    "RWhNWE0vYklaOGU4VnUxU3RxNkZHV3RMCkRSVnVaYm9BT0xQR1VoQVhzNjdReEY4",
    "eEFSMjBveWJNZGZUMHFOZU43U1J4V0ZQU1hYck80dTZZcUtBZGl3MGcKaG9tU3BK",
    "dTdqZnAzVnZpb0JKTVA1WXlaYzVqM0wrakhMYU9xdHBoUExKdwotLS0gdEJwcFZR",
    "VUdabkVMVTF6TWFMb040VHp4Wmp2RFMxM29zTjVvQ0ppN1d0bwr0aKdwOuhX9epf",
    "ewK2KOYCOM6p+cEzMFxYGUGjjui/NiDG4h8ih0fdr+N3Ig81+GH3h9KcfdkbZHV6",
    "L+hEGVZvAwWcOXi45iSCfUQO6ID4YA9/4AuxjnlSnwXFKcdwc4lMyhQdKE2Fe9j2",
    "SHG++eFe7fQi9M64ic3FOcNcrBXDNCmv7qUhSBxW8fFZjoJER5+oZd61yArLldMh",
    "KWByL5iyg83cSfB79e9mHnAk/Y4fznlJzkgVc8eh9CWvY2rtVufwmUYZoBKnFd80",
    "M0FwnrvLDZmujUpiikZopEql4x8OUxhkrWfqoFfInUWnekP/rNbYhgs2ySS33/5C",
    "4K1ppS070rMysVoFMzpyiGFmQymx0JPh+vQ+kPGjtTrN2KplQ7XRMNehNeDjc++i",
    "fukz/ILwOvoWZBlHdS/IWR6TS4lK6PEQaRBq8jOX5zNOIdTCNfjy2i9JVuQwLA3l",
    "dz6+JWEiq9k25MPciF6zKvsxkmDvlamacmu2SXoo11lkW7o1QlWG8602+Uk4FYi8",
    "HukJ8PHWAxC3fJf1Tb0EeUIcKG2hbXkzCOb/KlmsYZpPeDgoYS1WGiOlvXorjqHI",
    "Cv0y2K+LakpgFM17whY47rpf+gwPbbf5i+wOCSQ31rlgECjJbrEctVaGIohCEDhF",
    "xh+MQcPzAkKgTPWkd7xEFJyAch87V4/crCVYGBWRkB+oG+g3l5RHcANKtDmdGMCK",
    "nLZ98aAXr4UIl/dLloctp+akmjUN0lYbbHWeYN+Qp1WwpD4j3xPgO9k7kHLR9gR1",
    "9eYX/Esk9AaAjcLWT041WH3CsrfMBh1Hm5zA0HEa0mcKjNPfPA+7U6yix8JSiDj3",
    "bG4Sb+jtHdQfISpGM+Bo9VatM1kFTMSVTPDsuSTRxuOdfUdk4sum4AxWuug5u+AN",
    "ffHVI7+RCHguatWuxYNlgEcgQ2EX2+RsBjbTjmUD+nNGRzMEh9MdFwdImhlgwUin",
    "zLZXP6MAsri7YOTWiD21zJ5shxaPhWi2ERDrnjYTs9P95BPiT025gMn/MMHcqqpz",
    "hNVN7hY8TpaKxXm9DErYD5h+qs87zVX24isfxw1Ix0eX42+tU1CbSRoG/NbxMdQV",
    "fq/Aeim86Fq7Q3BsrlJ6YfB8bMILSB2VfgfbWwIkg2972LZttgTLk1Q4eeZGODUL",
    "RgqTJ7w6GTdHDphbjckAo5JmRlHTt7Bl2vnRZIrsD09I+hmkT8NfRc9R3Gy4q6jD",
    "jroKDtZJzOahH9pGQAZoR2714upgZK5541KgA4bbeMnPb84+1g+FxEj6q/t1uCgv",
    "3WhuJtmwHAbRw5abwJz+HkiXBWYfp2oyVG2ZJ+XjQFcnYiYx2HSm73ly1ICS36Qq",
    "rw4ve/c4w5gUoOZJ+YTmoWJHdmKo6GbD+OV3yBOUbhMu/mUyKWwDyFZE/TYNBV1y",
    "yFtROCURe6axDDcOUgR+QEsl8oKXA6rppMwIeMg=",
];

/// The signature of round 5423142 of quicknet-t.
pub(crate) const TESTNET_SIGNATURE: &str = concat!(
    "96fce8e2f70e2784577c8f2d8bd36af7a4b0dfd73dd91469",
    "d8556b36d2973a4f84681a45b1af2ce0511e5a32dd72508f",
);

/// SHA-256 of the text the lock on quicknet-t holds.
pub(crate) const TESTNET_TEXT_SHA256: &str =
    "d5e9d3881b3058556aac1b41b6261d8c34dec2fdd13a9e4cb3acd3a2e05af1cb";

const fn unhex_const<const N: usize>(text: &str) -> [u8; N] {
    const fn digit(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not a hex digit"),
        }
    }
    let text = text.as_bytes();
    assert!(text.len() == 2 * N);
    let mut bytes = [0; N];
    let mut at = 0;
    while at < N {
        bytes[at] = digit(text[2 * at]) * 16 + digit(text[2 * at + 1]);
        at += 1;
    }
    bytes
}

/// The file inside the armor of `lines`.
pub(crate) fn dearmor(lines: &[&str]) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits = 0_u32;
    let mut held = 0;
    let mut bytes = Vec::new();
    for char in lines.concat().bytes().filter(|&char| char != b'=') {
        let six = ALPHABET.iter().position(|&known| known == char).unwrap();
        bits = bits << 6 | u32::try_from(six).unwrap();
        held += 6;
        if held >= 8 {
            held -= 8;
            bytes.push(u8::try_from(bits >> held & 0xff).unwrap());
        }
    }
    bytes
}

/// The parts of an age file of one stanza.
pub(crate) struct AgeParts {
    /// Through the three dashes.
    pub(crate) header: Vec<u8>,
    /// Of the stanza.
    pub(crate) body: Vec<u8>,
    pub(crate) mac: Vec<u8>,
    /// Of the payload.
    pub(crate) nonce: [u8; 16],
    pub(crate) payload: Vec<u8>,
}

pub(crate) fn age_parts(file: &[u8]) -> AgeParts {
    let dashes = file
        .windows(5)
        .position(|window| window == b"\n--- ")
        .unwrap()
        + 4;
    let header = &file[..dashes];
    let lines: Vec<&[u8]> = header.split(|&byte| byte == b'\n').collect();
    let body: Vec<&str> = lines[2..lines.len() - 1]
        .iter()
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect();
    let end = dashes
        + file[dashes..]
            .iter()
            .position(|&byte| byte == b'\n')
            .unwrap();
    let mac = std::str::from_utf8(&file[dashes + 1..end]).unwrap();
    let nonce = file[end + 1..end + 17].try_into().unwrap();
    AgeParts {
        header: header.to_vec(),
        body: dearmor(&body),
        mac: dearmor(&[mac]),
        nonce,
        payload: file[end + 17..].to_vec(),
    }
}
