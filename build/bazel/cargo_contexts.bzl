"""Native target/build-tool features and dependency edges from locked manifests.

These are source model inputs, separately checked against actual configured
compiler actions. They are not compilation, runtime or cache qualification.
Only the three declared native host architectures are supported.
"""

CARGO_CONTEXTS = {
    "linux_aarch64": {
        "cookie@0.18.2": {
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [
                    "@crates__version_check-0.9.5//:version_check"
                ],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__percent-encoding-2.3.2//:percent_encoding",
                    "@crates__time-0.3.55//:time"
                ],
                "features": [
                    "percent-encode",
                    "percent-encoding"
                ],
                "proc_macro_deps": []
            }
        },
        "errno@0.3.14": {
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__libc-0.2.189//:libc"
                ],
                "features": [
                    "default",
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "getrandom@0.3.4": {
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__cfg-if-1.0.4//:cfg_if",
                    "@crates__libc-0.2.189//:libc"
                ],
                "features": [
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "getrandom@0.4.3": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__cfg-if-1.0.4//:cfg_if",
                    "@crates__libc-0.2.189//:libc"
                ],
                "features": [],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__cfg-if-1.0.4//:cfg_if",
                    "@crates__libc-0.2.189//:libc",
                    "@crates__rand_core-0.10.1//:rand_core"
                ],
                "features": [
                    "std",
                    "sys_rng"
                ],
                "proc_macro_deps": []
            }
        },
        "hashbrown@0.17.1": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__foldhash-0.2.0//:foldhash"
                ],
                "features": [
                    "default-hasher"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__allocator-api2-0.2.21//:allocator_api2",
                    "@crates__equivalent-1.0.2//:equivalent",
                    "@crates__foldhash-0.2.0//:foldhash"
                ],
                "features": [
                    "allocator-api2",
                    "default",
                    "default-hasher",
                    "equivalent",
                    "inline-more",
                    "raw-entry"
                ],
                "proc_macro_deps": []
            }
        },
        "idna@1.1.0": {
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__idna_adapter-1.2.2//:idna_adapter",
                    "@crates__smallvec-1.16.0//:smallvec",
                    "@crates__utf8_iter-1.0.4//:utf8_iter"
                ],
                "features": [
                    "alloc",
                    "compiled_data",
                    "default",
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "indexmap@2.14.2": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__equivalent-1.0.2//:equivalent",
                    "@crates__hashbrown-0.17.1//:hashbrown",
                    "@crates__serde_core-1.0.229//:serde_core"
                ],
                "features": [
                    "default",
                    "serde",
                    "std"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__equivalent-1.0.2//:equivalent",
                    "@crates__hashbrown-0.17.1//:hashbrown"
                ],
                "features": [
                    "default",
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "libc@0.2.189": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build"
                ],
                "features": [],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build"
                ],
                "features": [
                    "default",
                    "extra_traits",
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "linux_raw_sys@0.12.1": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [],
                "features": [
                    "auxvec",
                    "elf",
                    "errno",
                    "general",
                    "ioctl",
                    "no_std"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [],
                "features": [
                    "auxvec",
                    "elf",
                    "errno",
                    "general",
                    "if_ether",
                    "ioctl",
                    "net",
                    "netlink",
                    "no_std",
                    "prctl",
                    "system",
                    "xdp"
                ],
                "proc_macro_deps": []
            }
        },
        "log@0.4.34": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [],
                "features": [],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [],
                "features": [
                    "alloc",
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "phf@0.14.0": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__phf_shared-0.14.0//:phf_shared"
                ],
                "features": [
                    "default",
                    "std"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__phf_shared-0.14.0//:phf_shared"
                ],
                "features": [
                    "default",
                    "macros",
                    "phf_macros",
                    "std"
                ],
                "proc_macro_deps": [
                    "@crates__phf_macros-0.14.0//:phf_macros"
                ]
            }
        },
        "regex_automata@0.4.18": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__aho-corasick-1.1.5//:aho_corasick",
                    "@crates__memchr-2.8.3//:memchr",
                    "@crates__regex-syntax-0.8.11//:regex_syntax"
                ],
                "features": [
                    "alloc",
                    "default",
                    "dfa",
                    "dfa-build",
                    "dfa-onepass",
                    "dfa-search",
                    "hybrid",
                    "meta",
                    "nfa",
                    "nfa-backtrack",
                    "nfa-pikevm",
                    "nfa-thompson",
                    "perf",
                    "perf-inline",
                    "perf-literal",
                    "perf-literal-multisubstring",
                    "perf-literal-substring",
                    "std",
                    "syntax",
                    "unicode",
                    "unicode-age",
                    "unicode-bool",
                    "unicode-case",
                    "unicode-gencat",
                    "unicode-perl",
                    "unicode-script",
                    "unicode-segment",
                    "unicode-word-boundary"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__regex-syntax-0.8.11//:regex_syntax"
                ],
                "features": [
                    "alloc",
                    "dfa-build",
                    "dfa-search",
                    "nfa-thompson",
                    "std",
                    "syntax"
                ],
                "proc_macro_deps": []
            }
        },
        "regex_syntax@0.8.11": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [],
                "features": [
                    "default",
                    "std",
                    "unicode",
                    "unicode-age",
                    "unicode-bool",
                    "unicode-case",
                    "unicode-gencat",
                    "unicode-perl",
                    "unicode-script",
                    "unicode-segment"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [],
                "features": [
                    "default",
                    "std",
                    "unicode",
                    "unicode-age",
                    "unicode-bool",
                    "unicode-case",
                    "unicode-gencat",
                    "unicode-perl",
                    "unicode-script",
                    "unicode-segment"
                ],
                "proc_macro_deps": []
            }
        },
        "reqwest@0.12.28": {
            "target": {
                "aliases": {
                    "@crates__cookie-0.18.2//:cookie": "cookie_crate"
                },
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__base64-0.22.1//:base64",
                    "@crates__bytes-1.12.1//:bytes",
                    "@crates__cookie-0.18.2//:cookie",
                    "@crates__cookie_store-0.22.1//:cookie_store",
                    "@crates__futures-channel-0.3.34//:futures_channel",
                    "@crates__futures-core-0.3.34//:futures_core",
                    "@crates__futures-util-0.3.34//:futures_util",
                    "@crates__http-1.5.0//:http",
                    "@crates__http-body-1.1.0//:http_body",
                    "@crates__http-body-util-0.1.5//:http_body_util",
                    "@crates__hyper-1.11.1//:hyper",
                    "@crates__hyper-rustls-0.27.9//:hyper_rustls",
                    "@crates__hyper-util-0.1.20//:hyper_util",
                    "@crates__log-0.4.34//:log",
                    "@crates__percent-encoding-2.3.2//:percent_encoding",
                    "@crates__pin-project-lite-0.2.17//:pin_project_lite",
                    "@crates__rustls-0.23.46//:rustls",
                    "@crates__rustls-pki-types-1.15.1//:rustls_pki_types",
                    "@crates__serde-1.0.229//:serde",
                    "@crates__serde_json-1.0.151//:serde_json",
                    "@crates__serde_urlencoded-0.7.1//:serde_urlencoded",
                    "@crates__sync_wrapper-1.0.2//:sync_wrapper",
                    "@crates__tokio-1.53.1//:tokio",
                    "@crates__tokio-rustls-0.26.5//:tokio_rustls",
                    "@crates__tower-0.5.3//:tower",
                    "@crates__tower-http-0.6.11//:tower_http",
                    "@crates__tower-service-0.3.3//:tower_service",
                    "@crates__url-2.5.8//:url",
                    "@crates__webpki-roots-1.0.10//:webpki_roots"
                ],
                "features": [
                    "__rustls",
                    "__rustls-ring",
                    "__tls",
                    "blocking",
                    "cookies",
                    "json",
                    "rustls-tls",
                    "rustls-tls-webpki-roots",
                    "rustls-tls-webpki-roots-no-provider"
                ],
                "proc_macro_deps": []
            }
        },
        "rustix@1.1.5": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__bitflags-2.13.1//:bitflags",
                    "@crates__linux-raw-sys-0.12.1//:linux_raw_sys"
                ],
                "features": [
                    "alloc",
                    "default",
                    "fs",
                    "std"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__bitflags-2.13.1//:bitflags",
                    "@crates__linux-raw-sys-0.12.1//:linux_raw_sys"
                ],
                "features": [
                    "alloc",
                    "default",
                    "event",
                    "fs",
                    "net",
                    "process",
                    "std",
                    "stdio",
                    "system",
                    "time"
                ],
                "proc_macro_deps": []
            }
        },
        "serde@1.0.229": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__serde_core-1.0.229//:serde_core"
                ],
                "features": [
                    "alloc"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__serde_core-1.0.229//:serde_core"
                ],
                "features": [
                    "alloc",
                    "default",
                    "derive",
                    "serde_derive",
                    "std"
                ],
                "proc_macro_deps": [
                    "@crates__serde_derive-1.0.229//:serde_derive"
                ]
            }
        },
        "serde_core@1.0.229": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build"
                ],
                "features": [
                    "alloc",
                    "result",
                    "std"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build"
                ],
                "features": [
                    "alloc",
                    "default",
                    "result",
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "serde_json@1.0.151": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__itoa-1.0.18//:itoa",
                    "@crates__memchr-2.8.3//:memchr",
                    "@crates__serde_core-1.0.229//:serde_core",
                    "@crates__zmij-1.0.23//:zmij"
                ],
                "features": [
                    "default",
                    "std"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__itoa-1.0.18//:itoa",
                    "@crates__memchr-2.8.3//:memchr",
                    "@crates__serde_core-1.0.229//:serde_core",
                    "@crates__zmij-1.0.23//:zmij"
                ],
                "features": [
                    "alloc",
                    "default",
                    "raw_value",
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "syn@2.0.119": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__proc-macro2-1.0.107//:proc_macro2",
                    "@crates__quote-1.0.47//:quote",
                    "@crates__unicode-ident-1.0.24//:unicode_ident"
                ],
                "features": [
                    "clone-impls",
                    "default",
                    "derive",
                    "extra-traits",
                    "fold",
                    "full",
                    "parsing",
                    "printing",
                    "proc-macro",
                    "visit",
                    "visit-mut"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__proc-macro2-1.0.107//:proc_macro2",
                    "@crates__quote-1.0.47//:quote",
                    "@crates__unicode-ident-1.0.24//:unicode_ident"
                ],
                "features": [
                    "clone-impls",
                    "default",
                    "derive",
                    "full",
                    "parsing",
                    "printing",
                    "proc-macro",
                    "visit"
                ],
                "proc_macro_deps": []
            }
        },
        "tokio@1.53.1": {
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__bytes-1.12.1//:bytes",
                    "@crates__libc-0.2.189//:libc",
                    "@crates__mio-1.2.3//:mio",
                    "@crates__parking_lot-0.12.5//:parking_lot",
                    "@crates__pin-project-lite-0.2.17//:pin_project_lite",
                    "@crates__signal-hook-registry-1.4.8//:signal_hook_registry",
                    "@crates__socket2-0.6.5//:socket2"
                ],
                "features": [
                    "bytes",
                    "default",
                    "fs",
                    "io-util",
                    "libc",
                    "macros",
                    "mio",
                    "net",
                    "parking_lot",
                    "process",
                    "rt",
                    "rt-multi-thread",
                    "signal",
                    "signal-hook-registry",
                    "socket2",
                    "sync",
                    "test-util",
                    "time",
                    "tokio-macros"
                ],
                "proc_macro_deps": [
                    "@crates__tokio-macros-2.7.2//:tokio_macros"
                ]
            }
        }
    },
    "linux_x86_64": {
        "cookie@0.18.2": {
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [
                    "@crates__version_check-0.9.5//:version_check"
                ],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__percent-encoding-2.3.2//:percent_encoding",
                    "@crates__time-0.3.55//:time"
                ],
                "features": [
                    "percent-encode",
                    "percent-encoding"
                ],
                "proc_macro_deps": []
            }
        },
        "errno@0.3.14": {
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__libc-0.2.189//:libc"
                ],
                "features": [
                    "default",
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "getrandom@0.3.4": {
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__cfg-if-1.0.4//:cfg_if",
                    "@crates__libc-0.2.189//:libc"
                ],
                "features": [
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "getrandom@0.4.3": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__cfg-if-1.0.4//:cfg_if",
                    "@crates__libc-0.2.189//:libc"
                ],
                "features": [],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__cfg-if-1.0.4//:cfg_if",
                    "@crates__libc-0.2.189//:libc",
                    "@crates__rand_core-0.10.1//:rand_core"
                ],
                "features": [
                    "std",
                    "sys_rng"
                ],
                "proc_macro_deps": []
            }
        },
        "hashbrown@0.17.1": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__foldhash-0.2.0//:foldhash"
                ],
                "features": [
                    "default-hasher"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__allocator-api2-0.2.21//:allocator_api2",
                    "@crates__equivalent-1.0.2//:equivalent",
                    "@crates__foldhash-0.2.0//:foldhash"
                ],
                "features": [
                    "allocator-api2",
                    "default",
                    "default-hasher",
                    "equivalent",
                    "inline-more",
                    "raw-entry"
                ],
                "proc_macro_deps": []
            }
        },
        "idna@1.1.0": {
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__idna_adapter-1.2.2//:idna_adapter",
                    "@crates__smallvec-1.16.0//:smallvec",
                    "@crates__utf8_iter-1.0.4//:utf8_iter"
                ],
                "features": [
                    "alloc",
                    "compiled_data",
                    "default",
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "indexmap@2.14.2": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__equivalent-1.0.2//:equivalent",
                    "@crates__hashbrown-0.17.1//:hashbrown",
                    "@crates__serde_core-1.0.229//:serde_core"
                ],
                "features": [
                    "default",
                    "serde",
                    "std"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__equivalent-1.0.2//:equivalent",
                    "@crates__hashbrown-0.17.1//:hashbrown"
                ],
                "features": [
                    "default",
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "libc@0.2.189": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build"
                ],
                "features": [],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build"
                ],
                "features": [
                    "default",
                    "extra_traits",
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "linux_raw_sys@0.12.1": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [],
                "features": [
                    "auxvec",
                    "elf",
                    "errno",
                    "general",
                    "ioctl",
                    "no_std"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [],
                "features": [
                    "auxvec",
                    "elf",
                    "errno",
                    "general",
                    "if_ether",
                    "ioctl",
                    "net",
                    "netlink",
                    "no_std",
                    "prctl",
                    "system",
                    "xdp"
                ],
                "proc_macro_deps": []
            }
        },
        "log@0.4.34": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [],
                "features": [],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [],
                "features": [
                    "alloc",
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "phf@0.14.0": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__phf_shared-0.14.0//:phf_shared"
                ],
                "features": [
                    "default",
                    "std"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__phf_shared-0.14.0//:phf_shared"
                ],
                "features": [
                    "default",
                    "macros",
                    "phf_macros",
                    "std"
                ],
                "proc_macro_deps": [
                    "@crates__phf_macros-0.14.0//:phf_macros"
                ]
            }
        },
        "regex_automata@0.4.18": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__aho-corasick-1.1.5//:aho_corasick",
                    "@crates__memchr-2.8.3//:memchr",
                    "@crates__regex-syntax-0.8.11//:regex_syntax"
                ],
                "features": [
                    "alloc",
                    "default",
                    "dfa",
                    "dfa-build",
                    "dfa-onepass",
                    "dfa-search",
                    "hybrid",
                    "meta",
                    "nfa",
                    "nfa-backtrack",
                    "nfa-pikevm",
                    "nfa-thompson",
                    "perf",
                    "perf-inline",
                    "perf-literal",
                    "perf-literal-multisubstring",
                    "perf-literal-substring",
                    "std",
                    "syntax",
                    "unicode",
                    "unicode-age",
                    "unicode-bool",
                    "unicode-case",
                    "unicode-gencat",
                    "unicode-perl",
                    "unicode-script",
                    "unicode-segment",
                    "unicode-word-boundary"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__regex-syntax-0.8.11//:regex_syntax"
                ],
                "features": [
                    "alloc",
                    "dfa-build",
                    "dfa-search",
                    "nfa-thompson",
                    "std",
                    "syntax"
                ],
                "proc_macro_deps": []
            }
        },
        "regex_syntax@0.8.11": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [],
                "features": [
                    "default",
                    "std",
                    "unicode",
                    "unicode-age",
                    "unicode-bool",
                    "unicode-case",
                    "unicode-gencat",
                    "unicode-perl",
                    "unicode-script",
                    "unicode-segment"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [],
                "features": [
                    "default",
                    "std",
                    "unicode",
                    "unicode-age",
                    "unicode-bool",
                    "unicode-case",
                    "unicode-gencat",
                    "unicode-perl",
                    "unicode-script",
                    "unicode-segment"
                ],
                "proc_macro_deps": []
            }
        },
        "reqwest@0.12.28": {
            "target": {
                "aliases": {
                    "@crates__cookie-0.18.2//:cookie": "cookie_crate"
                },
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__base64-0.22.1//:base64",
                    "@crates__bytes-1.12.1//:bytes",
                    "@crates__cookie-0.18.2//:cookie",
                    "@crates__cookie_store-0.22.1//:cookie_store",
                    "@crates__futures-channel-0.3.34//:futures_channel",
                    "@crates__futures-core-0.3.34//:futures_core",
                    "@crates__futures-util-0.3.34//:futures_util",
                    "@crates__http-1.5.0//:http",
                    "@crates__http-body-1.1.0//:http_body",
                    "@crates__http-body-util-0.1.5//:http_body_util",
                    "@crates__hyper-1.11.1//:hyper",
                    "@crates__hyper-rustls-0.27.9//:hyper_rustls",
                    "@crates__hyper-util-0.1.20//:hyper_util",
                    "@crates__log-0.4.34//:log",
                    "@crates__percent-encoding-2.3.2//:percent_encoding",
                    "@crates__pin-project-lite-0.2.17//:pin_project_lite",
                    "@crates__rustls-0.23.46//:rustls",
                    "@crates__rustls-pki-types-1.15.1//:rustls_pki_types",
                    "@crates__serde-1.0.229//:serde",
                    "@crates__serde_json-1.0.151//:serde_json",
                    "@crates__serde_urlencoded-0.7.1//:serde_urlencoded",
                    "@crates__sync_wrapper-1.0.2//:sync_wrapper",
                    "@crates__tokio-1.53.1//:tokio",
                    "@crates__tokio-rustls-0.26.5//:tokio_rustls",
                    "@crates__tower-0.5.3//:tower",
                    "@crates__tower-http-0.6.11//:tower_http",
                    "@crates__tower-service-0.3.3//:tower_service",
                    "@crates__url-2.5.8//:url",
                    "@crates__webpki-roots-1.0.10//:webpki_roots"
                ],
                "features": [
                    "__rustls",
                    "__rustls-ring",
                    "__tls",
                    "blocking",
                    "cookies",
                    "json",
                    "rustls-tls",
                    "rustls-tls-webpki-roots",
                    "rustls-tls-webpki-roots-no-provider"
                ],
                "proc_macro_deps": []
            }
        },
        "rustix@1.1.5": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__bitflags-2.13.1//:bitflags",
                    "@crates__linux-raw-sys-0.12.1//:linux_raw_sys"
                ],
                "features": [
                    "alloc",
                    "default",
                    "fs",
                    "std"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__bitflags-2.13.1//:bitflags",
                    "@crates__linux-raw-sys-0.12.1//:linux_raw_sys"
                ],
                "features": [
                    "alloc",
                    "default",
                    "event",
                    "fs",
                    "net",
                    "process",
                    "std",
                    "stdio",
                    "system",
                    "time"
                ],
                "proc_macro_deps": []
            }
        },
        "serde@1.0.229": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__serde_core-1.0.229//:serde_core"
                ],
                "features": [
                    "alloc"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__serde_core-1.0.229//:serde_core"
                ],
                "features": [
                    "alloc",
                    "default",
                    "derive",
                    "serde_derive",
                    "std"
                ],
                "proc_macro_deps": [
                    "@crates__serde_derive-1.0.229//:serde_derive"
                ]
            }
        },
        "serde_core@1.0.229": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build"
                ],
                "features": [
                    "alloc",
                    "result",
                    "std"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build"
                ],
                "features": [
                    "alloc",
                    "default",
                    "result",
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "serde_json@1.0.151": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__itoa-1.0.18//:itoa",
                    "@crates__memchr-2.8.3//:memchr",
                    "@crates__serde_core-1.0.229//:serde_core",
                    "@crates__zmij-1.0.23//:zmij"
                ],
                "features": [
                    "default",
                    "std"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__itoa-1.0.18//:itoa",
                    "@crates__memchr-2.8.3//:memchr",
                    "@crates__serde_core-1.0.229//:serde_core",
                    "@crates__zmij-1.0.23//:zmij"
                ],
                "features": [
                    "alloc",
                    "default",
                    "raw_value",
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "syn@2.0.119": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__proc-macro2-1.0.107//:proc_macro2",
                    "@crates__quote-1.0.47//:quote",
                    "@crates__unicode-ident-1.0.24//:unicode_ident"
                ],
                "features": [
                    "clone-impls",
                    "default",
                    "derive",
                    "extra-traits",
                    "fold",
                    "full",
                    "parsing",
                    "printing",
                    "proc-macro",
                    "visit",
                    "visit-mut"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__proc-macro2-1.0.107//:proc_macro2",
                    "@crates__quote-1.0.47//:quote",
                    "@crates__unicode-ident-1.0.24//:unicode_ident"
                ],
                "features": [
                    "clone-impls",
                    "default",
                    "derive",
                    "full",
                    "parsing",
                    "printing",
                    "proc-macro",
                    "visit"
                ],
                "proc_macro_deps": []
            }
        },
        "tokio@1.53.1": {
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__bytes-1.12.1//:bytes",
                    "@crates__libc-0.2.189//:libc",
                    "@crates__mio-1.2.3//:mio",
                    "@crates__parking_lot-0.12.5//:parking_lot",
                    "@crates__pin-project-lite-0.2.17//:pin_project_lite",
                    "@crates__signal-hook-registry-1.4.8//:signal_hook_registry",
                    "@crates__socket2-0.6.5//:socket2"
                ],
                "features": [
                    "bytes",
                    "default",
                    "fs",
                    "io-util",
                    "libc",
                    "macros",
                    "mio",
                    "net",
                    "parking_lot",
                    "process",
                    "rt",
                    "rt-multi-thread",
                    "signal",
                    "signal-hook-registry",
                    "socket2",
                    "sync",
                    "test-util",
                    "time",
                    "tokio-macros"
                ],
                "proc_macro_deps": [
                    "@crates__tokio-macros-2.7.2//:tokio_macros"
                ]
            }
        }
    },
    "macos_aarch64": {
        "cookie@0.18.2": {
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [
                    "@crates__version_check-0.9.5//:version_check"
                ],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__percent-encoding-2.3.2//:percent_encoding",
                    "@crates__time-0.3.55//:time"
                ],
                "features": [
                    "percent-encode",
                    "percent-encoding"
                ],
                "proc_macro_deps": []
            }
        },
        "errno@0.3.14": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__libc-0.2.189//:libc"
                ],
                "features": [
                    "std"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__libc-0.2.189//:libc"
                ],
                "features": [
                    "default",
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "getrandom@0.3.4": {
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__cfg-if-1.0.4//:cfg_if",
                    "@crates__libc-0.2.189//:libc"
                ],
                "features": [
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "getrandom@0.4.3": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__cfg-if-1.0.4//:cfg_if",
                    "@crates__libc-0.2.189//:libc"
                ],
                "features": [],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__cfg-if-1.0.4//:cfg_if",
                    "@crates__libc-0.2.189//:libc",
                    "@crates__rand_core-0.10.1//:rand_core"
                ],
                "features": [
                    "std",
                    "sys_rng"
                ],
                "proc_macro_deps": []
            }
        },
        "hashbrown@0.17.1": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__foldhash-0.2.0//:foldhash"
                ],
                "features": [
                    "default-hasher"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__allocator-api2-0.2.21//:allocator_api2",
                    "@crates__equivalent-1.0.2//:equivalent",
                    "@crates__foldhash-0.2.0//:foldhash"
                ],
                "features": [
                    "allocator-api2",
                    "default",
                    "default-hasher",
                    "equivalent",
                    "inline-more",
                    "raw-entry"
                ],
                "proc_macro_deps": []
            }
        },
        "idna@1.1.0": {
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__idna_adapter-1.2.2//:idna_adapter",
                    "@crates__smallvec-1.16.0//:smallvec",
                    "@crates__utf8_iter-1.0.4//:utf8_iter"
                ],
                "features": [
                    "alloc",
                    "compiled_data",
                    "default",
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "indexmap@2.14.2": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__equivalent-1.0.2//:equivalent",
                    "@crates__hashbrown-0.17.1//:hashbrown",
                    "@crates__serde_core-1.0.229//:serde_core"
                ],
                "features": [
                    "default",
                    "serde",
                    "std"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__equivalent-1.0.2//:equivalent",
                    "@crates__hashbrown-0.17.1//:hashbrown"
                ],
                "features": [
                    "default",
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "libc@0.2.189": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build"
                ],
                "features": [
                    "std"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build"
                ],
                "features": [
                    "default",
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "log@0.4.34": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [],
                "features": [],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [],
                "features": [
                    "alloc",
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "phf@0.14.0": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__phf_shared-0.14.0//:phf_shared"
                ],
                "features": [
                    "default",
                    "std"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__phf_shared-0.14.0//:phf_shared"
                ],
                "features": [
                    "default",
                    "macros",
                    "phf_macros",
                    "std"
                ],
                "proc_macro_deps": [
                    "@crates__phf_macros-0.14.0//:phf_macros"
                ]
            }
        },
        "regex_automata@0.4.18": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__aho-corasick-1.1.5//:aho_corasick",
                    "@crates__memchr-2.8.3//:memchr",
                    "@crates__regex-syntax-0.8.11//:regex_syntax"
                ],
                "features": [
                    "alloc",
                    "default",
                    "dfa",
                    "dfa-build",
                    "dfa-onepass",
                    "dfa-search",
                    "hybrid",
                    "meta",
                    "nfa",
                    "nfa-backtrack",
                    "nfa-pikevm",
                    "nfa-thompson",
                    "perf",
                    "perf-inline",
                    "perf-literal",
                    "perf-literal-multisubstring",
                    "perf-literal-substring",
                    "std",
                    "syntax",
                    "unicode",
                    "unicode-age",
                    "unicode-bool",
                    "unicode-case",
                    "unicode-gencat",
                    "unicode-perl",
                    "unicode-script",
                    "unicode-segment",
                    "unicode-word-boundary"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__regex-syntax-0.8.11//:regex_syntax"
                ],
                "features": [
                    "alloc",
                    "dfa-build",
                    "dfa-search",
                    "nfa-thompson",
                    "std",
                    "syntax"
                ],
                "proc_macro_deps": []
            }
        },
        "regex_syntax@0.8.11": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [],
                "features": [
                    "default",
                    "std",
                    "unicode",
                    "unicode-age",
                    "unicode-bool",
                    "unicode-case",
                    "unicode-gencat",
                    "unicode-perl",
                    "unicode-script",
                    "unicode-segment"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [],
                "features": [
                    "default",
                    "std",
                    "unicode",
                    "unicode-age",
                    "unicode-bool",
                    "unicode-case",
                    "unicode-gencat",
                    "unicode-perl",
                    "unicode-script",
                    "unicode-segment"
                ],
                "proc_macro_deps": []
            }
        },
        "reqwest@0.12.28": {
            "target": {
                "aliases": {
                    "@crates__cookie-0.18.2//:cookie": "cookie_crate"
                },
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__base64-0.22.1//:base64",
                    "@crates__bytes-1.12.1//:bytes",
                    "@crates__cookie-0.18.2//:cookie",
                    "@crates__cookie_store-0.22.1//:cookie_store",
                    "@crates__futures-channel-0.3.34//:futures_channel",
                    "@crates__futures-core-0.3.34//:futures_core",
                    "@crates__futures-util-0.3.34//:futures_util",
                    "@crates__http-1.5.0//:http",
                    "@crates__http-body-1.1.0//:http_body",
                    "@crates__http-body-util-0.1.5//:http_body_util",
                    "@crates__hyper-1.11.1//:hyper",
                    "@crates__hyper-rustls-0.27.9//:hyper_rustls",
                    "@crates__hyper-util-0.1.20//:hyper_util",
                    "@crates__log-0.4.34//:log",
                    "@crates__percent-encoding-2.3.2//:percent_encoding",
                    "@crates__pin-project-lite-0.2.17//:pin_project_lite",
                    "@crates__rustls-0.23.46//:rustls",
                    "@crates__rustls-pki-types-1.15.1//:rustls_pki_types",
                    "@crates__serde-1.0.229//:serde",
                    "@crates__serde_json-1.0.151//:serde_json",
                    "@crates__serde_urlencoded-0.7.1//:serde_urlencoded",
                    "@crates__sync_wrapper-1.0.2//:sync_wrapper",
                    "@crates__tokio-1.53.1//:tokio",
                    "@crates__tokio-rustls-0.26.5//:tokio_rustls",
                    "@crates__tower-0.5.3//:tower",
                    "@crates__tower-http-0.6.11//:tower_http",
                    "@crates__tower-service-0.3.3//:tower_service",
                    "@crates__url-2.5.8//:url",
                    "@crates__webpki-roots-1.0.10//:webpki_roots"
                ],
                "features": [
                    "__rustls",
                    "__rustls-ring",
                    "__tls",
                    "blocking",
                    "cookies",
                    "json",
                    "rustls-tls",
                    "rustls-tls-webpki-roots",
                    "rustls-tls-webpki-roots-no-provider"
                ],
                "proc_macro_deps": []
            }
        },
        "rustix@1.1.5": {
            "host": {
                "aliases": {
                    "@crates__errno-0.3.14//:errno": "libc_errno"
                },
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__bitflags-2.13.1//:bitflags",
                    "@crates__errno-0.3.14//:errno",
                    "@crates__libc-0.2.189//:libc"
                ],
                "features": [
                    "alloc",
                    "default",
                    "fs",
                    "std"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {
                    "@crates__errno-0.3.14//:errno": "libc_errno"
                },
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__bitflags-2.13.1//:bitflags",
                    "@crates__errno-0.3.14//:errno",
                    "@crates__libc-0.2.189//:libc"
                ],
                "features": [
                    "alloc",
                    "default",
                    "event",
                    "fs",
                    "net",
                    "process",
                    "std",
                    "stdio",
                    "system",
                    "time"
                ],
                "proc_macro_deps": []
            }
        },
        "serde@1.0.229": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__serde_core-1.0.229//:serde_core"
                ],
                "features": [
                    "alloc"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__serde_core-1.0.229//:serde_core"
                ],
                "features": [
                    "alloc",
                    "default",
                    "derive",
                    "serde_derive",
                    "std"
                ],
                "proc_macro_deps": [
                    "@crates__serde_derive-1.0.229//:serde_derive"
                ]
            }
        },
        "serde_core@1.0.229": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build"
                ],
                "features": [
                    "alloc",
                    "result",
                    "std"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build"
                ],
                "features": [
                    "alloc",
                    "default",
                    "result",
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "serde_json@1.0.151": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__itoa-1.0.18//:itoa",
                    "@crates__memchr-2.8.3//:memchr",
                    "@crates__serde_core-1.0.229//:serde_core",
                    "@crates__zmij-1.0.23//:zmij"
                ],
                "features": [
                    "default",
                    "std"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    ":build_script_build",
                    "@crates__itoa-1.0.18//:itoa",
                    "@crates__memchr-2.8.3//:memchr",
                    "@crates__serde_core-1.0.229//:serde_core",
                    "@crates__zmij-1.0.23//:zmij"
                ],
                "features": [
                    "alloc",
                    "default",
                    "raw_value",
                    "std"
                ],
                "proc_macro_deps": []
            }
        },
        "syn@2.0.119": {
            "host": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__proc-macro2-1.0.107//:proc_macro2",
                    "@crates__quote-1.0.47//:quote",
                    "@crates__unicode-ident-1.0.24//:unicode_ident"
                ],
                "features": [
                    "clone-impls",
                    "default",
                    "derive",
                    "extra-traits",
                    "fold",
                    "full",
                    "parsing",
                    "printing",
                    "proc-macro",
                    "visit",
                    "visit-mut"
                ],
                "proc_macro_deps": []
            },
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__proc-macro2-1.0.107//:proc_macro2",
                    "@crates__quote-1.0.47//:quote",
                    "@crates__unicode-ident-1.0.24//:unicode_ident"
                ],
                "features": [
                    "clone-impls",
                    "default",
                    "derive",
                    "full",
                    "parsing",
                    "printing",
                    "proc-macro",
                    "visit"
                ],
                "proc_macro_deps": []
            }
        },
        "tokio@1.53.1": {
            "target": {
                "aliases": {},
                "build_aliases": {},
                "build_deps": [],
                "build_proc_macro_deps": [],
                "deps": [
                    "@crates__bytes-1.12.1//:bytes",
                    "@crates__libc-0.2.189//:libc",
                    "@crates__mio-1.2.3//:mio",
                    "@crates__parking_lot-0.12.5//:parking_lot",
                    "@crates__pin-project-lite-0.2.17//:pin_project_lite",
                    "@crates__signal-hook-registry-1.4.8//:signal_hook_registry",
                    "@crates__socket2-0.6.5//:socket2"
                ],
                "features": [
                    "bytes",
                    "default",
                    "fs",
                    "io-util",
                    "libc",
                    "macros",
                    "mio",
                    "net",
                    "parking_lot",
                    "process",
                    "rt",
                    "rt-multi-thread",
                    "signal",
                    "signal-hook-registry",
                    "socket2",
                    "sync",
                    "test-util",
                    "time",
                    "tokio-macros"
                ],
                "proc_macro_deps": [
                    "@crates__tokio-macros-2.7.2//:tokio_macros"
                ]
            }
        }
    }
}
