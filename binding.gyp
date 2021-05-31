{
    "targets": [
        {
            "target_name": "multihashing",
            "sources": [
                "multihashing.cc",
                "algorithms/allium.c",
                "algorithms/bcrypt.c",
                "algorithms/blake.c",
                "algorithms/blake2s.c",
                "algorithms/c11.c",
                "algorithms/fresh.c",
                "algorithms/fugue.c",
                "algorithms/gost.c",
                "algorithms/groestl.c",
                "algorithms/hefty1.c",
                "algorithms/keccak.c",
                "algorithms/lbry.c",
                "algorithms/lyra2.c",
                "algorithms/lyra2RE.c",
                "algorithms/lyra2REV2.c",
                "algorithms/lyra2REV3.c",
                "algorithms/lyra2Z.c",
                "algorithms/lyra2z16m330.c",
                "algorithms/lyra2z330.c",
                "algorithms/minotaur.c",
                "algorithms/neoscrypt.c",
                "algorithms/nist5.c",
                "algorithms/phi1612.c",
                "algorithms/quark.c",
                "algorithms/qubit.c",
                "algorithms/scryptn.c",
                "algorithms/sha256d.c",
                "algorithms/shavite3.c",
                "algorithms/skein.c",
                "algorithms/sm3.c",
                "algorithms/sponge.c",
                "algorithms/tribus.c",
                "algorithms/whirlpoolx.c",
                "algorithms/x11.c",
                "algorithms/x13.c",
                "algorithms/x15.c",
                "algorithms/x16r.c",
                "algorithms/x17.c",
                "algorithms/sha3/aes_helper.c",
                "algorithms/sha3/hamsi.c",
                "algorithms/sha3/KeccakP-800-reference.c",
                "algorithms/sha3/sph_haval.c",
                "algorithms/sha3/sph_hefty1.c",
                "algorithms/sha3/sph_fugue.c",
                "algorithms/sha3/sph_blake.c",
                "algorithms/sha3/sph_blake2s.c",
                "algorithms/sha3/sph_bmw.c",
                "algorithms/sha3/sph_cubehash.c",
                "algorithms/sha3/sph_echo.c",
                "algorithms/sha3/sph_gost.c",
                "algorithms/sha3/sph_groestl.c",
                "algorithms/sha3/sph_jh.c",
                "algorithms/sha3/sph_keccak.c",
                "algorithms/sha3/sph_luffa.c",
                "algorithms/sha3/sph_shavite.c",
                "algorithms/sha3/sph_simd.c",
                "algorithms/sha3/sph_skein.c",
                "algorithms/sha3/sph_whirlpool.c",
                "algorithms/sha3/sph_shabal.c",
                "algorithms/sha3/sph_ripemd.c",
                "algorithms/sha3/sph_sha2.c",
                "algorithms/sha3/sph_sha2big.c",
                "algorithms/sha3/sph_tiger.c",
                "algorithms/sph/sph_cubehash.h",
                "algorithms/sph/sph_echo.h",
                "algorithms/sph/sph_fungue.h",
                "algorithms/sph/sph_gost.h",
                "algorithms/sph/sph_jh.h",
                "algorithms/sph/sph_skein.h"
            ],
            'conditions': [
                ['OS=="linux"',
                  {
                    'link_settings': {
                      'libraries': [
                        '-lgmp'
                      ]
                    }
                  }
                ],
                ['OS=="mac"',
                  {
                    'link_settings': {
                      'libraries': [
                        '-lgmp'
                      ]
                    }
                  }
                ],
                ['OS=="win"',
                  {
                    'link_settings': {
                      'libraries': [
                        '-lgmp.lib'
                      ],
                    }
                  }
                ]
              ],
            "include_dirs": [
                "crypto"
            ],
            "cflags_cc": [
                "-std=c++0x"
            ],
        }
    ]
}
