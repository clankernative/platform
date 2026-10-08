# WOFF2 admission fixture

`test-subset.rs` contains the bytes of a 344-byte WOFF2 subset of Geist Sans containing `A` and the required `.notdef` glyph. It exercises real WOFF2 packaging and CSS URL closure without copying complete application fonts into tests. See `GEIST-LICENSE.txt` for the upstream OFL license.

Source: `crates/day2/tests/fixtures/fonts/geist-sans-variable.woff2` at platform commit `0136d5770f346f7ffc7d2408b29b64987d94173a`.

Generated once with FontTools 4.60.1:

```sh
pyftsubset geist-sans-variable.woff2 --unicodes=U+0041 --flavor=woff2 --no-hinting --drop-tables+=STAT,fvar,gvar,HVAR,MVAR,avar,DSIG,GDEF,GPOS,GSUB --name-IDs=1,2 --name-languages=0x409 --output-file=test-subset.woff2
```

The resulting bytes are stored as a Rust byte slice to keep Native's public source export text-only. Tests consume that checked-in slice; FontTools is not a build or test dependency. Synthetic header-only data is used separately for header and byte-budget rejection tests. Native admission checks WOFF2 headers, not font decoding or rendering.
