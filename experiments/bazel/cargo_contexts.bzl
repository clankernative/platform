"""Reviewed Linux context prediction for this isolated Cargo/Bazel experiment.

The target/build-tool split is derived from locked Cargo declarations and was
cross-checked against the prior complete Cargo compiler-artifact feature sets.
The main f97 YAML removal is preserved; these current-source predictions still
require fresh hosted compilation/analysis and do not establish action equality.
"""

CARGO_CONTEXTS = {
    "getrandom@0.4.3": {
        "target": {
            "features": [
                "std",
                "sys_rng"
            ],
            "deps": [
                ":build_script_build",
                "@crates__cfg-if-1.0.4//:cfg_if",
                "@crates__libc-0.2.189//:libc",
                "@crates__rand_core-0.10.1//:rand_core"
            ],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        },
        "host": {
            "features": [],
            "deps": [
                ":build_script_build",
                "@crates__cfg-if-1.0.4//:cfg_if",
                "@crates__libc-0.2.189//:libc"
            ],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        }
    },
    "hashbrown@0.17.1": {
        "target": {
            "features": [
                "allocator-api2",
                "default",
                "default-hasher",
                "equivalent",
                "inline-more",
                "raw-entry"
            ],
            "deps": [
                "@crates__allocator-api2-0.2.21//:allocator_api2",
                "@crates__equivalent-1.0.2//:equivalent",
                "@crates__foldhash-0.2.0//:foldhash"
            ],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        },
        "host": {
            "features": [
                "default-hasher"
            ],
            "deps": [
                "@crates__foldhash-0.2.0//:foldhash"
            ],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        }
    },
    "indexmap@2.14.2": {
        "target": {
            "features": [
                "default",
                "std"
            ],
            "deps": [
                "@crates__equivalent-1.0.2//:equivalent",
                "@crates__hashbrown-0.17.1//:hashbrown"
            ],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        },
        "host": {
            "features": [
                "default",
                "serde",
                "std"
            ],
            "deps": [
                "@crates__equivalent-1.0.2//:equivalent",
                "@crates__hashbrown-0.17.1//:hashbrown",
                "@crates__serde_core-1.0.229//:serde_core"
            ],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        }
    },
    "libc@0.2.189": {
        "target": {
            "features": [
                "default",
                "extra_traits",
                "std"
            ],
            "deps": [
                ":build_script_build"
            ],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        },
        "host": {
            "features": [],
            "deps": [
                ":build_script_build"
            ],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        }
    },
    "linux_raw_sys@0.12.1": {
        "target": {
            "features": [
                "auxvec",
                "elf",
                "errno",
                "general",
                "ioctl",
                "no_std",
                "prctl",
                "system"
            ],
            "deps": [],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        },
        "host": {
            "features": [
                "auxvec",
                "elf",
                "errno",
                "general",
                "ioctl",
                "no_std"
            ],
            "deps": [],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        }
    },
    "log@0.4.34": {
        "target": {
            "features": [
                "alloc",
                "std"
            ],
            "deps": [],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        },
        "host": {
            "features": [],
            "deps": [],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        }
    },
    "phf@0.14.0": {
        "target": {
            "features": [
                "default",
                "macros",
                "phf_macros",
                "std"
            ],
            "deps": [
                "@crates__phf_shared-0.14.0//:phf_shared"
            ],
            "proc_macro_deps": [
                "@crates__phf_macros-0.14.0//:phf_macros"
            ],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        },
        "host": {
            "features": [
                "default",
                "std"
            ],
            "deps": [
                "@crates__phf_shared-0.14.0//:phf_shared"
            ],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        }
    },
    "regex_automata@0.4.18": {
        "target": {
            "features": [
                "alloc",
                "dfa-build",
                "dfa-search",
                "nfa-thompson",
                "std",
                "syntax"
            ],
            "deps": [
                "@crates__regex-syntax-0.8.11//:regex_syntax"
            ],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        },
        "host": {
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
            "deps": [
                "@crates__aho-corasick-1.1.5//:aho_corasick",
                "@crates__memchr-2.8.3//:memchr",
                "@crates__regex-syntax-0.8.11//:regex_syntax"
            ],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        }
    },
    "rustix@1.1.4": {
        "target": {
            "features": [
                "alloc",
                "default",
                "fs",
                "process",
                "std",
                "system",
                "time"
            ],
            "deps": [
                ":build_script_build",
                "@crates__bitflags-2.13.1//:bitflags",
                "@crates__linux-raw-sys-0.12.1//:linux_raw_sys"
            ],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        },
        "host": {
            "features": [
                "alloc",
                "default",
                "fs",
                "std"
            ],
            "deps": [
                ":build_script_build",
                "@crates__bitflags-2.13.1//:bitflags",
                "@crates__linux-raw-sys-0.12.1//:linux_raw_sys"
            ],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        }
    },
    "serde@1.0.229": {
        "target": {
            "features": [
                "alloc",
                "default",
                "derive",
                "serde_derive",
                "std"
            ],
            "deps": [
                ":build_script_build",
                "@crates__serde_core-1.0.229//:serde_core"
            ],
            "proc_macro_deps": [
                "@crates__serde_derive-1.0.229//:serde_derive"
            ],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        },
        "host": {
            "features": [
                "alloc"
            ],
            "deps": [
                ":build_script_build",
                "@crates__serde_core-1.0.229//:serde_core"
            ],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        }
    },
    "serde_core@1.0.229": {
        "target": {
            "features": [
                "alloc",
                "default",
                "result",
                "std"
            ],
            "deps": [
                ":build_script_build"
            ],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        },
        "host": {
            "features": [
                "alloc",
                "result",
                "std"
            ],
            "deps": [
                ":build_script_build"
            ],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        }
    },
    "serde_json@1.0.151": {
        "target": {
            "features": [
                "alloc",
                "default",
                "raw_value",
                "std"
            ],
            "deps": [
                ":build_script_build",
                "@crates__itoa-1.0.18//:itoa",
                "@crates__memchr-2.8.3//:memchr",
                "@crates__serde_core-1.0.229//:serde_core",
                "@crates__zmij-1.0.23//:zmij"
            ],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        },
        "host": {
            "features": [
                "default",
                "std"
            ],
            "deps": [
                ":build_script_build",
                "@crates__itoa-1.0.18//:itoa",
                "@crates__memchr-2.8.3//:memchr",
                "@crates__serde_core-1.0.229//:serde_core",
                "@crates__zmij-1.0.23//:zmij"
            ],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        }
    },
    "syn@2.0.119": {
        "target": {
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
            "deps": [
                "@crates__proc-macro2-1.0.107//:proc_macro2",
                "@crates__quote-1.0.47//:quote",
                "@crates__unicode-ident-1.0.24//:unicode_ident"
            ],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        },
        "host": {
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
            "deps": [
                "@crates__proc-macro2-1.0.107//:proc_macro2",
                "@crates__quote-1.0.47//:quote",
                "@crates__unicode-ident-1.0.24//:unicode_ident"
            ],
            "proc_macro_deps": [],
            "aliases": {},
            "build_deps": [],
            "build_proc_macro_deps": [],
            "build_aliases": {}
        }
    }
}
