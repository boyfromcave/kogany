//! The Ycash Development Fund (YDF) and the pre-fork founders' reward on Ycash (kogany W1-Y3).
//!
//! From the Ycash upgrade until the mandate ends, every coinbase must pay exactly 5 % of the block
//! subsidy (`GetBlockSubsidy(nHeight) / 20`) to the YDF address for its height, P2PKH or P2SH; after
//! the mandate the payment is optional and unchecked (`ycash6 src/main.cpp:6267-6286`). Before the
//! Ycash upgrade the inherited Zcash founders' reward applies (`src/main.cpp:6248-6265`). Ycash has
//! no ZIP 207/214 funding streams and no lockbox (survey B trap T4).

use crate::{
    amount::{Amount, NonNegative},
    block::Height,
    parameters::{subsidy::halving_block_subsidy, Network, NetworkUpgrade},
    transparent,
};

/// The number of blocks each YDF address is used for, about a month
/// (`ycash6 src/chainparams.cpp:1030`, `addressChangeInterval`).
pub const YDF_ADDRESS_CHANGE_INTERVAL: u32 = 17_917;

/// The YDF share divisor: the YDF is paid `subsidy / 20`, 5 % (`ycash6 src/main.cpp:6272`).
pub const YDF_DIVISOR: u64 = 20;

/// The first height at which the YDF payment is no longer mandatory, `nYdfMandateEndHeight`.
pub mod mandate_end {
    use crate::block::Height;

    /// Ycash mainnet (`ycash6 src/chainparams.cpp:167`).
    pub const MAINNET: Height = Height(2_275_000);
    /// The Ycash testnet profiles (`ycash6 src/chainparams.cpp:474`).
    pub const TESTNET: Height = Height(900_000);
    /// Ycash regtest (`ycash6 src/chainparams.cpp:777`).
    pub const REGTEST: Height = Height(5);
}

/// Ycash mainnet YDF addresses (`vYcashFoundersRewardAddress`, `ycash6 src/chainparams.cpp:358-371`).
pub const MAINNET_YDF_ADDRESSES: [&str; 48] = [
    "s1hfWJ4ej1H3s8XCUb7YnrU68K64AsGVUHE",
    "s1iZaRoYtafWspcieQxg6hhaU4DfZyAdGQf",
    "s1RSr6xec6Cc98emM4cdq45rkVekHMjRWbw",
    "s1RsqYeweoKVepivLPLsiajE8c6khu5UKhS",
    "s1MNmqMWyV4nMWE4oDb1nqJs7haJrv9QTKp",
    "s1RP95ESdcu33gMtU7deLW9TP6yDZncjRQ7",
    "s1h8W7xQbiU8Zxu21Zcg82NByjkWMcEbNtX",
    "s1PVcdfcrJrDCmXxgSTGuKGSNhwSYZ51XKJ",
    "s1PkV5nFkgQN4EGuTtEcmm4CxeBVx2L5HHv",
    "s1jiVSTfMaFUrWnf17BGc416oomHbut58Ue",
    "s1Zr2KdHtnK2zNSMQDrAVv3KU51mgDbqgwe",
    "s1QkY6tmBHPZacXPMPmsjP37Kxgs5mcgcAn",
    "s1Xu76ZmGDENdLFAiuj5iMdp1RA4hWSNieq",
    "s1bdiEnfBYaEgrt2TmnY3ZHmdhg5AEw9tjN",
    "s1asM9Ui4U13GjmLoAhvfK6J5QihemQR9Pk",
    "s1QhTSXYu4K1cTNomN27wiep9WC9HBZjrxJ",
    "s1j3Ef2qCNjwRAM18BgwsPAZFzZ475BWM5S",
    "s1QZibiN7iqVCfVBES9Gn7e3o5psxRKtpwE",
    "s1fdiDZHkzp8K8UajpVwYUdyFeb6jNVyoKv",
    "s1iMShbVRH1eCGxK2ZoLMDn5o9NcwXkNPVF",
    "s1YtUXAMt8m31gGeP5m3Y53B1wrMk3FFigJ",
    "s1gy9aqWUihGRjZa3vqc7136vqTGNAWyefF",
    "s1NNozrex18HZqcHCGpGoSRkj8hqHLEPaVC",
    "s1NYNDdqthMf7D7sZbnLGuecDtXb48Ne2bf",
    "s1P7UJ9Wp7jstJPUbvMSRVFjN8tfQueQSK3",
    "s1RDeyH7xg8y9veb9XfAmtKzrMTjFS14c4T",
    "s1NmH6MNXU19xoHjUfpQpb4dEMSy1Wbs9tC",
    "s1UnFL2yrZapMKmB5EqaBKpogZmnXLUgELB",
    "s1XT3W1sLFdgmGoecQbPdJbjUDMurW8CFA2",
    "s1gyVwgangQxLCAcm8VS4SWqXDqeohNg7hd",
    "s1k3eWbqnbVM1xtZEDc81UbFdwXgXNnbtdH",
    "s1Wr6eAh3gZWwBVRZcND9YCzdNfR9cARkD4",
    "s1dtjp2KHWZ6qF2LvgNiEwjJV2dA2c6y75V",
    "s1cjQf9kmjQdTmnn6mbBaesHMNLt2JqjyEV",
    "s1URQeusSoi7fkgyAwCshFzobUzmLGH4U3b",
    "s1Z9YqM2h48HUf8kcSHS89q4Z6Bg9xua3kA",
    "s1TLmZzMDsDhYfh4vpY7NpRB4kao2UEEqKu",
    "s1QEWvfC1uifDfi78NY7cArw9xLEja7QAZR",
    "s1b4kfW9WMUtd2H7X4C64KLzqPWdMPXRMtS",
    "s1cHTXzCXhKYAX7sY7D8YGcmopjN8Yngoju",
    "s1QKjMQDeF9FLVo2sL8m11VC4ZA18s61s2K",
    "s1gV8D561ZpmaZVxG176cQM1bMFMnHLvujE",
    "s1caQmLCYVDZegcMoBckHD2RXjBh7ikpj2j",
    "s1Y63AsWsJTk5t5nSZfaFcFWmtfnFUUAu2V",
    "s1Y2U4GsfZdP9LAbC97GAmSdihBX5FU9gQn",
    "s1bPYWZMXzyN2ML2vswDiCckmas775QFs2Q",
    "s1erG25RcWYCiBPbT7khTU4ULhzm8jJZ7pv",
    "s1kYEiPdFZ3oV389q2MmSYY932qPF1ygVtx",
];

/// Ycash testnet and regtest YDF addresses (`ycash6 src/chainparams.cpp:613-626,856-869`).
pub const TESTNET_YDF_ADDRESSES: [&str; 48] = [
    "smDw2LWkeuJ1NGBDDZvdNbzY8A9D1mkkDZm",
    "smDxM6WPpz3HcK6m9cCnhQkBXMLnUf3cryA",
    "smEKdQPcZHYTmcTbVkqfWryRbEZWMrapjMo",
    "smEVfJmuGErW6ZM3XSNwbJR6cPU3iPABAqY",
    "smEkWMsbV1CBZosu9wtq69f2vNXBT1owNKe",
    "smFd3Dh5MjEttRHd9S8kx153Vzesefzjc2d",
    "smGBXB9SrjnEDf7ASQxvnujBRc1qBb58o5q",
    "smGLTYjSriA3n8EMf4JTiHLGUCzUYjau3WV",
    "smGVF2kDywxhjfzBqoFDE1AyXZEafTLSjbH",
    "smGVrxUHUzd2gaURPw2ASoE3L5WMFcxJcp1",
    "smHTCd59Q9pFzrzA73f6het1ozDzeQaA8E3",
    "smHy6JaGM9gkaGBJ4DF4p5FbFvoUbpAusWd",
    "smJ1fpQdKNuchkxuVUMBkcCWoBcWFmyDAyZ",
    "smJ2j3Gea5XH7ERpyYzvo6YQKaoYfzkMUS3",
    "smJ8gtE5EX5oFSp4c5cCDpxoajXTQu73VSC",
    "smJyGxvwpCxPaFJM6TwZ6cwT1qz5PMPPBeL",
    "smKEt1iVgCDY9V4915HnGpFK3zyTPyQixMa",
    "smKXxXsNLUVE8Qro6R9EyaEZmvgxqjbsFX9",
    "smLTH7FEiXUVpWjhoL91ToMoSZPU8xAvEh9",
    "smLo65rNyiEYiVHxWZHNNP9QU1HsQu3QX7b",
    "smMDUN36MqFE4thY54CQnWBpU4ePuayF9TV",
    "smMWmoipQ7YVuRAJaQHKqhHbbTg28mS6ET5",
    "smMtCCZsR3s7ZiEYskFietNPfSb1eVHNoZi",
    "smMuh9QVkpQg93Gb54ucaVykbk9FgjZBN3D",
    "smNM44GrsbMWHQRhhayqieCadzURNDLkxkW",
    "smNhJLQs3LmHWtVscrnJmrLhhjPcDD3unJZ",
    "smPHxC1438rANivn1omntbRF5Nf2wSZfFhs",
    "smSAidYKoFY2fmi2efcoJPSeBpdVC2vyHvj",
    "smShCYXefsx8RcnW2b7duPKBcD5TXWY5K2A",
    "smTRxVMtveLrdzVb1B9rLKfDZ3Qp8kAna7r",
    "smTnar3ernxTG5voae2bUC185EicBdSKVux",
    "smUmPeP8VwuPsNTcJcB7YZY1b1HJJsJfkYp",
    "smVSGTzPP4dbj3HXRR84WoBFWw4EVuuyVi2",
    "smW8AA9LAKGMj4EXxNtfJQFLFaiuzTyGwYa",
    "smWAgHkGiQ1fZHF9ZBjYzKS7ZX8JtjvWbaU",
    "smX1HT3n9mtPGeK7qMBETCEGL5UG8eC8nmy",
    "smX3udkLyb3qZ2z2muEinbvNuSi5M2JiiE5",
    "smXEcB2QZaZgevkB7CS1Tz2BZNQ9cnNwXBj",
    "smXddMXWZvpRDq4FjuTGxLWYTtwbNwc36g5",
    "smXfPS6G7aiVECG8qFvZc9oFe1bzEvCKECG",
    "smXxQi63m9x2WfhdBYogWdKzavVpbnnGyJq",
    "smZ53EtRafyjGZyjiNDb1FiGbwXbtE3aqTB",
    "smZJPM9KsKAdfotD6Woh2nb8wLedvhf4Nw5",
    "smZyciv3CGZLAFU8d2yKff33FU8f2nek5yx",
    "smZzRpCLENnxN5JgMHaKtMruTCi7jsa7Tak",
    "smaWKSqvUJvajRquGbaHBdNbL78fDf6hdwE",
    "smazMQ9G7NLJXAzX4ZMKc8x6DigyeoEucgk",
    "smbTaZmsKNEVstoQVyZcJAMJExiytfnwaMU",
];

/// Zcash's mainnet founders' P2SH list re-encoded under the Ycash `s3` prefix (`KeyIO::ZecToYec`), the same scripts.
pub const MAINNET_FOUNDER_ADDRESSES: [&str; 48] = [
    "s39yZGB6K2s9ZjPR7TGFhk4niP5yEsdN47P",
    "s3GKgQAPRdaZzhg193FRyU7qxfSTik2htHH",
    "s3KqTzFe5RRAZzvXqp6skyFGaxUzFtGRsXk",
    "s37g6NpEFFJFGUCxDvZQtXTuW2Rfs87sMgg",
    "s36pHqeBcikEVi2AXP9kBbwdKRBSJdgqV6c",
    "s3Bsc2f8eSRVu1yCHCqsHQEDpBJhihzn4q5",
    "s3ExiyorA9b8VPwjEjixG8GDTABY2aVLjuj",
    "s3EcqQfgocrprXXk2sJF9gdagVu6pMnz8JZ",
    "s2y47ZoMuVGzvrne6cRySAScCtqidpySEmX",
    "s35YL6rs1k5jH95MV1ZQT7GH3PqLE5RZ5r2",
    "s38sbYjcFcHAQoX1XZytFmANTwZg42KRt2d",
    "s3DmjbRhuww1QPSYTNgbeds7e6zmrLBrg5E",
    "s3KAgqRpsVPXiWCxsc8Nir6wQ4CKdMcT97G",
    "s3Gw6ta9bmsjUmK4crpMjSvMTSAtraEvTGx",
    "s3CcM8zJtvfKvY1Now2y7e4mSJh26nTpTXd",
    "s3FLTRbVuewfYo1FttF5jSWWRbRFnjGXFyU",
    "s39upjpu56en3XhfuWWG6x23Vm9jsF6Lz7E",
    "s3JEgkMJFgHc4mMhuBqG2gm3nErV8ua9bEB",
    "s3JrjcCizfpR68Jcr89APEWzmWQAn7qC9Bp",
    "s314GbNUmGsSyY88KMa6BRj2aUyejQcf1ts",
    "s3LG4BsyKA3MLDLNqBYdeYKs6Fp34UQR9WJ",
    "s2zT3t4jsZEQj3uFeVYCyXjGzFcEDfPvEDN",
    "s334rYmvLjNMCrjEAkZRebDmSrvcU13nBpQ",
    "s3K2zH2yjv5dxBMpWwUnozVwazaKKzHM63u",
    "s35qM2AnDARUhfFnWYirrcXbeTd4f7SE7T5",
    "s3KJ6JzL72o2rLXdwdpW9HjqW94NHCssbq8",
    "s33n8uNJxRx4DoLGMSGn4mu7YjgLWa2QvUz",
    "s3AdrdUjRma92wGeNhpTo3Gs5Jo8XdVKXHj",
    "s3C8nbxoKLxHqacyWDyH29A8HXyxerj5m9x",
    "s3EMxZbeZ5owv2tB96jGiwnaKMmkRkpKuiR",
    "s3LPkTqhy8Lo7aS6Zv27gi1395oswB46Khu",
    "s35bWyxjEWK4p6geCdiYwzTZNCp4YAKoDUV",
    "s3Ea3HqErRxP63AGtgAtbJrWdLWKuBRP1UH",
    "s3CEFPpt8HaLtfUpMYAbFhVJyiBLDGBJaVK",
    "s3L1Whjj75EQie58f769z5L1YL5E7FwM75e",
    "s3HP41ubKbg5MKgne6nPPLPPTta8AAcHY8N",
    "s34R6kXzcjsWttCt9s2itnvHMem9tw6H7mA",
    "s3JnEPTDBkrNAXnv5qyUGx9K3gfkb7MxFAF",
    "s33jsuhtEWd3xRBZtPMAbDgk2rq1prMmjRX",
    "s2zQRWj12gxNf85R4t5miUQLHuYr4xcUXNp",
    "s3KN9rSFq2TjYd3eeUwrcjASszyNiGYJC3d",
    "s3HKLxjFFHCYpSHZiwHmFca2AD5YEKF5Gzh",
    "s3EJpKdVjQrccgmv3TKZMQfDUZbwGgx1AoM",
    "s31E4SVvjvYtzk6bqMaKznRVxmDaFUKgBA1",
    "s3ADEcvVy5trvnvAuJ4TLrcwVPgoLuxbbGY",
    "s33SKJiNaQ13tXPgUYPFQa5BvArTjwNfAFN",
    "s3535KBZQPh3jYUtNhu6WsAKtBL46Dmqs6w",
    "s33cJLHtTvLZDskVKMC5SS9REP7nFd1j87h",
];

/// Zcash's testnet founders' P2SH list re-encoded under the Ycash testnet script prefix, the same scripts.
pub const TESTNET_FOUNDER_ADDRESSES: [&str; 48] = [
    "s2Xi8gr2eXXT2f8Jx8axGD2qwutsQPwjNYG",
    "s2RUXVWbFuz1fnG5FCN3ajzPN7fjpr6njrA",
    "s2RbYwuRvTH4TSscSQ4yB7WS61En2mRGLd8",
    "s2HhpL4N1bs8yYXPc6Gn2cYmVpPUKAxxpbb",
    "s2F5gqrGokwj8Y4PUYZbHJnTN3a2aTGbpvB",
    "s2MTyEKMWzvzWXewt8q169gMbjQPrcfTCxo",
    "s2GByN949DnJwz9jGfgAQAPuh2Lx3hoqmPd",
    "s2HuVbqnumnAY5CJbwpnMDxzscgD1BHYQTR",
    "s2JUn6mgboKV4DSdK9R32fVG1zCyH34CSRK",
    "s2Pis58sBJTqSHhvoA9DgGuGyzAi6JkgjcT",
    "s2AHpBAXSnVkydE1KWnAbEVnJmZxbrZZREb",
    "s2GNtH2T8zstvL8tRQ7GjqpxgGhhUqY4FVu",
    "s2GqgQ82q8kCU1THFCWQRArhHmdjwQZ6aWE",
    "s2FNtTcEEATEVqe6gUGdcy1S7hhkARcU29V",
    "s2R7bJG5QuJi9rQjxT4R3yQcqiqopXgBaQf",
    "s2DkP5siKG2WxTzUPvCuqvdeWy8b2Qjzqxb",
    "s2YzD9ggooaXiaJzG8aWaVhkFnVvLuPoFyG",
    "s2NNoqrnnrSMifVSsJHN5yVLgw4sfsT5nr9",
    "s2YZvFgnqjJi7DaYaFoyCQPKbwZJTYLKiKt",
    "s2JTg2Gv98P6wEaATRzZPexGTJvKTXAPFv3",
    "s2EmFaDg6QgKVPetPFLxKtp4CtrkapD1nWN",
    "s2KEbAAQiPCmEBDVS2PKxQwksxWk8dBHKLG",
    "s2VrBgVTQcUNXDf97UkvWNP5TEBj4STS5bf",
    "s2YQ9tvSxZKMaev2b5FBedqQHHH2RCufZRU",
    "s2KJc5hpFPnLZt5sFKf16u43t7qcoCjRV8U",
    "s2HsjUhjGXr78DN3zeq8s1mPRDufGrnwzcY",
    "s2Rjc4oy53ua4RxAyXDWHWUxrXbm7xACSpi",
    "s2KmemvPWZg9PCFJyz7nMx2HJL6ciUKa451",
    "s2V9ot85V6SvkVvyTdAYk1JKoxz35Vjfw4P",
    "s2NKt1mvJfZAHW2HeDi1rFhTBnYB6DovVu3",
    "s2DZnsyBYUfjd77FJ9u4hjKRU6JpjFX39eK",
    "s2Ri1FvM51teZGXrHyDAHctFPHbMrLEWHPX",
    "s2HXLcka8iVUGfzjM6xt1rr36bMxTVUkoE1",
    "s2MujRqpmtUrfiuUCJoLA2nZCzeDyjJ4mZP",
    "s2Jc8iSe9N9UoNiUrF21o3S5RUADnLF1HJ9",
    "s2GoMLw6X1uW61dxKxvrBYDQX3tuDUAVYkJ",
    "s2Y4dez8WTfZDukgRziYWfy1RZWrT5bsXxR",
    "s2WWcP4JrjJkcNJ1y18ueA29VLUePYDLCpe",
    "s2XKC7a4D97vZE4Rk5ddNT4LBZWAaVCFFLu",
    "s2SK1WoeQ6xdAjpDcps5J3uEQU3vHLie2Nj",
    "s2NrShs4VckmoC2a7UBaFvp5h3Ey1YiiZGd",
    "s2MUgmFMYmeCUwvVXDAGALZies4hGQtYCWX",
    "s2U24iRwtv1r73yGoUrU794RYLzg53jvRpD",
    "s2RYbWkDsZtbfCqJonMhqn2cyaH4dfnAGWz",
    "s2D9RRYbLsrdtUKrxhsiF7BeG1WivNMgML9",
    "s2JKHXiD14NB16CtRiLQXLhW6J5XVQ9YZdh",
    "s2GR7KfABaYrZaBCNpmSrRcqUcj2qQfwkaU",
    "s2XpBAD5uDbkZDBkGxdHjca5fqfYjEA6cAN",
];

/// Returns true if the Ycash upgrade's rules apply at `height`: in the `ycash` profile every
/// later upgrade carries them, so this is the ordinal `current >= Ycash` (kogany plan §2.2).
pub fn is_ycash_active(network: &Network, height: Height) -> bool {
    NetworkUpgrade::current(network, height) >= NetworkUpgrade::Ycash
}

/// The first height without a mandatory YDF payment on `network`.
pub fn ydf_mandate_end_height(network: &Network) -> Height {
    match network {
        Network::Mainnet => mandate_end::MAINNET,
        Network::Testnet(params) if params.is_regtest() => mandate_end::REGTEST,
        Network::Testnet(_) => mandate_end::TESTNET,
    }
}

/// The YDF address list of `network`. Regtest uses the testnet list, as ycashd does.
pub fn ydf_address_list(network: &Network) -> &'static [&'static str] {
    match network {
        Network::Mainnet => &MAINNET_YDF_ADDRESSES,
        Network::Testnet(_) => &TESTNET_YDF_ADDRESSES,
    }
}

/// The YDF address for `height`, or `None` below the Ycash upgrade.
///
/// The index advances every [`YDF_ADDRESS_CHANGE_INTERVAL`] blocks from the Ycash activation
/// height and wraps modulo the list length (`CChainParams::GetFoundersRewardAddressAtHeight`,
/// `ycash6 src/chainparams.cpp:1026-1033`). It is defined after the mandate ends too, for miners
/// that pay the optional YDF.
pub fn ydf_address(network: &Network, height: Height) -> Option<transparent::Address> {
    if !is_ycash_active(network, height) {
        return None;
    }
    let activation = NetworkUpgrade::Ycash.activation_height(network)?;
    let list = ydf_address_list(network);
    let period = height.0.checked_sub(activation.0)? / YDF_ADDRESS_CHANGE_INTERVAL;
    let index = usize::try_from(period).ok()? % list.len();
    list[index].parse().ok()
}

/// The mandatory YDF payment at `height`: `subsidy / 20` from the Ycash upgrade until the mandate
/// ends, zero otherwise.
pub fn ydf_reward(network: &Network, height: Height) -> Amount<NonNegative> {
    if !is_ycash_active(network, height) || height >= ydf_mandate_end_height(network) {
        return Amount::zero();
    }

    // The YDF ends long before ZIP 234 could start on Ycash (NU7 has no height), so the halving
    // schedule is the whole subsidy. Integer division matches ycashd's `GetBlockSubsidy / 20`.
    halving_block_subsidy(height, network)
        .ok()
        .and_then(|subsidy| (subsidy / YDF_DIVISOR).ok())
        .expect("a block subsidy divided by a positive constant is a valid amount")
}
