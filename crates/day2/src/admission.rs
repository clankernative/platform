//! Compiler-enforced separation between authored applications and generated codecs.
//!
//! Two mandatory compiler checks use the same authored modules. The admission SDK
//! renames construction methods; only trusted generated code follows those names.
//! The normal SDK lacks the admission names. Authored code must typecheck against
//! both interfaces, so neither factory spelling is available to applications.
//! No authored Roc source is searched or rewritten, and generated implementations
//! and opaque representations remain the same in both profiles.

use crate::{assets, output_schema, schema::Schema};
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path};

// These are exact edits to trusted SDK sources, not an application-language parser.
// An SDK change requires an explicit update here rather than silently weakening
// the restricted interface. Every other SDK byte is retained.
const FACTORIES: &[(&str, &str)] = &[
    (
        "Model.roc",
        "\tdefine : Str, Str, (Str -> Try(a, Str)), (a -> Str) -> Model(a)\n\tdefine = |name, prefix, decode, encode| { name, prefix, decode, encode }\n",
    ),
    (
        "Input.roc",
        "\tdefine : Str, (Str -> Try(a, Str)), (a -> Str) -> Input(a)\n\tdefine = |name, decoder, encoder| { name, decoder, encoder }\n",
    ),
    (
        "Output.roc",
        "\tdefine : Str, (a -> Str) -> Output(a)\n\tdefine = |key, encoder| { key, encoder }\n",
    ),
    (
        "Field.roc",
        "\tdefine : Str -> Field(a)\n\tdefine = |name| { name, witness: [] }\n",
    ),
    (
        "Asset.roc",
        "\tdefine : Str -> Asset\n\tdefine = |key| { key: key }\n",
    ),
];

const SEALED: &[(&str, &str, &str)] = &[
    (
        "Slack.roc",
        "",
        "bddae0f023114db9f74806a5e9dcae905b490dcc012a409060ed33641ef1ccaf",
    ),
    (
        "Snowflake.roc",
        "",
        "db87bb1fb394de8d5ec59f28026d3780c5cac493a9fa69f7ca7fa5763c4d3ba0",
    ),
    (
        "OpenAi.roc",
        "",
        "588a116a5536a68582bd21e7ff71322da636d72fa0898365e322db01eabc651c",
    ),
    (
        "GoogleDirectory.roc",
        "",
        "412a00e9ffc8988c224efb3da3fb96ed3f00e3fb0c58bfa966461687ee355767",
    ),
    (
        "Linear.roc",
        "",
        "f8695efa1f64c52898737f7369afead1fe4d298547fad77cbdca722623fae729",
    ),
    (
        "OperatorAlerts.roc",
        "",
        "883e696ac97640d73181b0f829a98a98b492c03534f36a6c28231fe94239c40c",
    ),
    (
        "Resource.roc",
        "token",
        "66b5198906b37de5e4e2539ceb86f66557e8b54bb691a2b55a52ebd3fd6dd0f7",
    ),
    (
        "Carta.roc",
        "",
        "755e423d88a45f0d282412100df605e18b53e8cc8d1df3c609e37a62fe73bcce",
    ),
    (
        "Delegate.roc",
        "",
        "972fa2eac8b2fa9aa62ab4ad54f96d35c8865be4a53e10323115b5d8a5c6d79c",
    ),
    (
        "Audit.roc",
        "",
        "f404132bf8e805004716d8cccc4ecf2a48ec34d188b814a457b52620749a4fff",
    ),
    (
        "ObjectStore.roc",
        "",
        "e944b953ebf16fa5735c983e6928bdacac27b75002ad0ccd1ce43ade6aa2e1f1",
    ),
    (
        "GitHubActions.roc",
        "",
        "ec8b99e1af651a481cd15ac742038f8854cdba67ef9f8dc6ff37582da07447df",
    ),
    (
        "LinearWork.roc",
        "",
        "1e6178051dec13bb3e6d0f523b1bb84ca17f90ac3366627a16b336429c11e124",
    ),
    (
        "Predicate.roc",
        "define",
        "49e26c11f0c968381194e31b2feebc6689834015965f83592770ed2fe6b1091d",
    ),
    (
        "Order.roc",
        "define",
        "65da0bd2034c609ff2e10ac69cb35b316726647c880459229e6207c7804dd3a8",
    ),
    (
        "Selection.roc",
        "indexed",
        "2c1549a162acdef2f08bb09bf130c83fbf4f5a6b6158c891be7afe3c35548969",
    ),
    (
        "Api.roc",
        "",
        "d1d52af6bebeef4a7065a65b496c6a9220924aab9a3139b3cb6fac16cb0b74de",
    ),
    (
        "Effects.roc",
        "program",
        "3f8b36149e329a52cf7ebacd57a7909232e443a64e1b039b60cd6f9323c4e795",
    ),
    (
        "Notifications.roc",
        "",
        "7c81817aa1d71f517ea5c375dfdc6971e6e874e1d86eb6a49245cc3f931bd134",
    ),
    (
        "Handler.roc",
        "program",
        "f4fde4bd638de22e662b0c9fad6a86777db28946cd2e04ecc064b1f948bd431f",
    ),
    (
        "Observe.roc",
        "program",
        "a99390e8fc67c05209ca9d87a378e6e53d596ff938bdf235772cbdb3b4aa3ab0",
    ),
    (
        "Failure.roc",
        "define",
        "7986ca8c11501d56f18c0bba6a1b6b837bd1494535b54cc8f15a652f68fcaf09",
    ),
    (
        "Text.roc",
        "from_spec",
        "afbe0661da55fb9bad5b21a13bc1439eeea10dfa742fb093fd29a9083650bda4",
    ),
    (
        "Path.roc",
        "define",
        "585a7c2acafb4c14c6ad9850b00bfb5b7a779cd266a7a71a30526916c34aeb6c",
    ),
    (
        "Write.roc",
        "define",
        "bd082ba2d59c1e3dab2fb36434b55a166c85440371a18d6d09c1777daf3b6d4b",
    ),
    (
        "Read.roc",
        "define",
        "ef1221214095749f681956caa6261405ada3e94893d7b86a81dabe3d672701f7",
    ),
    (
        "CommandBinding.roc",
        "define",
        "e8e7c67e712d503d6b4bd50a9b67d5c584d4020274feea5a38dd1ec75ab7b83a",
    ),
    (
        "QueryBinding.roc",
        "define",
        "9369fa928c6c2dcd5ee525c5a6c5a4a009e852373446ffe585ad6ff64e5f33cc",
    ),
    (
        "Context.roc",
        "from_wire",
        "3cfa16ca524528cedbdafcdcc4b7feaeb66db920b3806b0023831b6b2d0d4fa5",
    ),
    (
        "Product.roc",
        "step",
        "70ea8aa49599a5ed455e651a3dc9dbf81770ad647d5e5a045bfdc6ac0d7b48ef",
    ),
    (
        "Tx.roc",
        "evaluate",
        "f0b63e65441932e9d60d4efacc1c36e492bb47e240bb69dfecd2bfe4f0c28813",
    ),
    (
        "Operation.roc",
        "",
        "60d4fdac7d8a9f6a8c6c43a8073f04c52696134536c57b3b2a972de3980aa181",
    ),
];

/// Every construction call the restricted profile renames, as (owner, method).
///
/// A sealed module's own definitions are renamed by the per-module arms below;
/// these are the *call sites*, and they are what a module written against the
/// normal SDK spells. The restricted profile does not define the original
/// spellings, so a module carrying one of these must be rewritten or it cannot
/// compile — which is why `a_module_the_admission_stage_copies_verbatim_cannot_
/// use_a_restricted_name` reads this same table rather than a second copy of it.
const RESTRICTED_CALLS: &[(&str, &str)] = &[
    ("Tx", "host_reject"),
    ("Tx", "from_host"),
    ("Tx", "begin_decision"),
    ("Tx", "invoke_command"),
    ("Tx", "begin_effects"),
    ("Tx", "begin_completion"),
    ("Tx", "capability"),
    ("Handler", "program"),
    ("Effects", "program"),
    ("Effects", "capability"),
    ("Observe", "capability"),
    ("Effects", "from_host"),
    ("Observe", "from_host"),
    ("Resource", "token"),
];

pub fn reserved_module(name: &str) -> bool {
    crate::sdk::reserved_module(name)
}

fn restrict_sealed(module: &str, source: &str) -> Result<String> {
    let (_, method, digest) = SEALED
        .iter()
        .find(|(name, _, _)| *name == module)
        .context("unknown sealed SDK module")?;
    ensure!(
        crate::digest(source.as_bytes()) == format!("sha256:{digest}"),
        "sealed SDK interface changed in {module}; review and refresh admission pin"
    );
    let mut restricted = source.to_string();
    if module == "Selection.roc" {
        for suffix in [" :", " ="] {
            let original = format!("\tall{suffix}");
            ensure!(
                source.matches(&original).count() == 1,
                "selection factory boundary changed"
            );
            restricted = restricted.replacen(&original, &format!("\tadmission_all{suffix}"), 1);
        }
        restricted = restricted
            .replace("..all(", "..admission_all(")
            .replace("Predicate.define(", "Predicate.admission_define(");
    }
    if module == "Tx.roc" {
        for method in [
            "host_reject",
            "from_host",
            "begin_decision",
            "invoke_command",
            "begin_effects",
            "begin_completion",
            "capability",
        ] {
            ensure!(
                source.matches(&format!("\t{method} :")).count() == 1,
                "host failure boundary changed"
            );
            restricted = restricted.replace(method, &format!("admission_{method}"));
        }
    } else {
        for (owner, method) in RESTRICTED_CALLS {
            restricted = restricted.replace(
                &format!("{owner}.{method}("),
                &format!("{owner}.admission_{method}("),
            );
        }
    }
    if ["Observe.roc", "Effects.roc"].contains(&module) {
        for name in ["capability", "from_host"] {
            restricted = restricted
                .replace(&format!("\t{name} :"), &format!("\tadmission_{name} :"))
                .replace(&format!("\t{name} ="), &format!("\tadmission_{name} ="));
        }
    }
    if module == "Handler.roc" {
        restricted = restricted.replace(").program()", ").admission_program()");
    }
    if module == "Resource.roc" {
        restricted = restricted
            .replace("\tdecode :", "\tadmission_decode :")
            .replace("\tdecode =", "\tadmission_decode =")
            .replace(".and_then(decode)", ".and_then(admission_decode)");
    }
    if module == "Api.roc" {
        for name in ["command_program", "query_program"] {
            for suffix in [" :", " ="] {
                let original = format!("\t{name}{suffix}");
                ensure!(
                    restricted.matches(&original).count() == 1,
                    "operation program boundary changed"
                );
                restricted =
                    restricted.replacen(&original, &format!("\tadmission_{name}{suffix}"), 1);
            }
        }
    }
    if ["CommandBinding.roc", "QueryBinding.roc"].contains(&module) {
        restricted = restricted
            .replace("\tbind :", "\tadmission_bind :")
            .replace("\tbind =", "\tadmission_bind =")
            .replace(" define(command,", " admission_define(command,");
    }
    if !method.is_empty() {
        for suffix in [" :", " ="] {
            let original = format!("\t{method}{suffix}");
            ensure!(
                restricted.matches(&original).count() == 1,
                "sealed SDK method boundary changed"
            );
            restricted =
                restricted.replacen(&original, &format!("\tadmission_{method}{suffix}"), 1);
        }
    }
    if module == "Operation.roc" {
        ensure!(
            restricted.contains("Context.from_wire("),
            "trusted context adapter missing"
        );
        restricted = restricted.replace("Context.from_wire(", "Context.admission_from_wire(");
    }
    if module == "Product.roc" {
        let call = "guarded.evaluate(request.observations)";
        ensure!(
            restricted.matches(call).count() == 1,
            "trusted transaction evaluator boundary changed"
        );
        restricted =
            restricted.replacen(call, "guarded.admission_evaluate(request.observations)", 1);
    }
    Ok(restricted)
}

fn restrict_sdk(module: &str, source: &str) -> Result<String> {
    let reviewed_digest = match module {
        "Model.roc" => "260a6b7f24ec648fe54d8488b102f155485be3ec192ea032902a2da643b482bb",
        "Input.roc" => "983d57859994106787ef3dd02b642c8770ddd12987fc7973a32c3500e6238715",
        "Output.roc" => "d8e95f12bdb90baf693fe3de58094c9dda1afb23e5a49a15c92e077eb6cac42b",
        "Field.roc" => "1746349c9c7333536b15e0d4b2a6f928f549083abc7232663c3d8e7a881f1823",
        "Asset.roc" => "0799a3bd5222274c31be03edaa1b97ad358648f1838c0f5d4731b9773b2f487b",
        _ => anyhow::bail!("unknown restricted SDK module"),
    };
    ensure!(
        crate::digest(source.as_bytes()) == format!("sha256:{reviewed_digest}"),
        "generated-only factory interface changed in {module}; review all constructors and refresh the admission pin"
    );
    let block = FACTORIES
        .iter()
        .find_map(|(name, block)| (*name == module).then_some(*block))
        .context("unknown restricted SDK module")?;
    ensure!(
        source.matches(block).count() == 1,
        "generated-only factory boundary changed in {module}; review the restricted SDK interface"
    );
    let renamed = block
        .replace("\tdefine ", "\tadmission_define ")
        .replace("\tall ", "\tadmission_all ")
        .replace("\tindexed ", "\tadmission_indexed ");
    Ok(source.replacen(block, &renamed, 1))
}

fn copy_modules(source: &Path, target: &Path, depth: usize, count: &mut usize) -> Result<()> {
    ensure!(depth <= 16, "admission module depth budget");
    ensure!(
        fs::symlink_metadata(source)?.file_type().is_dir(),
        "admission source must be a real directory"
    );
    fs::create_dir(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        ensure!(!kind.is_symlink(), "admission rejects module symlinks");
        let path = entry.path();
        let destination = target.join(entry.file_name());
        if kind.is_dir() {
            copy_modules(&path, &destination, depth + 1, count)?;
        } else if path.extension().is_some_and(|extension| extension == "roc") {
            ensure!(kind.is_file(), "admission rejects special module files");
            *count += 1;
            ensure!(*count <= 512, "admission module count budget");
            ensure!(
                entry.metadata()?.len() <= 2_000_000,
                "admission module byte budget"
            );
            fs::write(destination, fs::read(path)?)?;
        }
    }
    Ok(())
}

/// Prepare a fresh sibling directory for `roc check --no-cache app/main.roc`.
/// This directory is not a release artifact. The caller must require successful
/// pinned, sandboxed checks of BOTH this directory and the original stage, then
/// build only the original stage. Renamed methods are deliberately available in
/// just this profile, so omitting the original check would reopen the boundary.
pub fn prepare(
    stage: &Path,
    target: &Path,
    schema: &Schema,
    outputs: &output_schema::Catalog,
    images: &assets::Catalog,
) -> Result<()> {
    let stage = stage.canonicalize()?;
    ensure!(!target.exists(), "admission target must be fresh");
    let parent = target
        .parent()
        .context("admission target parent")?
        .canonicalize()?;
    ensure!(
        !parent.starts_with(&stage),
        "admission check must be isolated from the executable stage"
    );
    fs::create_dir(target)?;
    let mut count = 0;
    copy_modules(&stage.join("app"), &target.join("app"), 0, &mut count)?;
    copy_modules(&stage.join("sdk"), &target.join("sdk"), 0, &mut count)?;
    for (module, _) in FACTORIES {
        let path = target.join("sdk").join(module);
        let restricted = restrict_sdk(module, &fs::read_to_string(&path)?)?;
        fs::write(path, restricted)?;
    }
    for (module, _, _) in SEALED {
        let path = target.join("sdk").join(module);
        let restricted = restrict_sealed(module, &fs::read_to_string(&path)?)?;
        fs::write(path, restricted)?;
    }
    for (module, source) in [
        ("Data.roc", schema.admission_data_module()?),
        ("Domains.roc", crate::domain::module(schema, true)?),
        ("Inputs.roc", schema.admission_inputs_module()?),
        ("Outputs.roc", output_schema::admission_roc_module(outputs)?),
        ("Assets.roc", assets::admission_roc_module(images)?),
    ] {
        fs::write(target.join("app").join(module), source)?;
    }
    if stage.join("registry.json").exists() {
        let catalog: crate::registry::Catalog =
            serde_json::from_slice(&fs::read(stage.join("registry.json"))?)?;
        for (module, source) in catalog.modules(schema, outputs, true)? {
            fs::write(target.join("app").join(module), source)?;
        }
        fs::write(
            target.join("app/main.roc"),
            crate::registry::entrypoint(true),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restricted_sdk_has_no_stale_factory_patches() {
        let sdk = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk");
        for (module, _) in FACTORIES {
            let source =
                fs::read_to_string(crate::sdk::source_path(&sdk, module).unwrap()).unwrap();
            let restricted = restrict_sdk(module, &source).unwrap();
            assert_eq!(
                restricted
                    .replace("admission_define", "define")
                    .replace("admission_all", "all")
                    .replace("admission_indexed", "indexed"),
                source
            );
            assert!(restrict_sdk(module, &restricted).is_err());
            assert!(
                restrict_sdk(
                    module,
                    &format!("{source}\n# unreviewed interface change\n")
                )
                .is_err()
            );
        }
    }

    #[test]
    fn changed_sdk_factory_is_not_silently_admitted() {
        assert!(restrict_sdk("Model.roc", "Model(a) :: Str.{}\n").is_err());
        assert!(restrict_sdk("Other.roc", "Other :: [].{}\n").is_err());
    }

    #[test]
    fn sealed_registry_and_context_interfaces_are_review_pinned() {
        let sdk = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk");
        for (module, _, _) in SEALED {
            let source =
                fs::read_to_string(crate::sdk::source_path(&sdk, module).unwrap()).unwrap();
            let restricted = restrict_sealed(module, &source).unwrap();
            assert_eq!(restricted.replace("admission_", ""), source);
            assert!(restrict_sealed(module, &restricted).is_err());
            assert!(restrict_sealed(module, &format!("{source}\n# changed\n")).is_err());
        }
        for name in crate::sdk::module_files() {
            assert!(
                reserved_module(name),
                "SDK module must not be shadowable: {name}"
            );
        }
    }

    /// The admission stage copies every SDK module it is not told to rewrite.
    ///
    /// That copy is verbatim, so a module spelling a construction call the
    /// restricted profile has renamed compiles against the normal SDK and fails
    /// against the restricted one — at `roc check`, at the end of the build,
    /// pointing at the missing *member* rather than the missing seal. Adding
    /// `ObjectStore.roc` without a `SEALED` entry produced exactly that:
    /// "Effects is in scope, but it has no associated capability."
    ///
    /// The list is what falls behind, so this enumerates from the SDK catalog
    /// instead: every module the stage would copy, checked against the same
    /// `RESTRICTED_CALLS` the rewriter uses.
    #[test]
    fn a_module_the_admission_stage_copies_verbatim_cannot_use_a_restricted_name() {
        let sdk = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk");
        let mut copied = 0;
        for name in crate::sdk::module_files() {
            if SEALED.iter().any(|(module, _, _)| *module == name)
                || FACTORIES.iter().any(|(module, _)| *module == name)
            {
                continue;
            }
            copied += 1;
            let source = fs::read_to_string(crate::sdk::source_path(&sdk, name).unwrap()).unwrap();
            for (owner, method) in RESTRICTED_CALLS {
                assert!(
                    !source.contains(&format!("{owner}.{method}(")),
                    "{name} calls {owner}.{method} but the admission stage copies it \
                     verbatim; seal it in SEALED so the call is renamed, or the \
                     restricted profile cannot compile it"
                );
            }
        }
        // A gate that inspected nothing would pass for the case it exists to
        // catch, and the copied set is the larger one.
        assert!(
            copied > 0,
            "no module is copied verbatim — gate inspected nothing"
        );
    }
}
