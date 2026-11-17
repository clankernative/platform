//! Operator-measured OCI composition DATA, separate from reusable runtime identity.
//! Registry descriptors, native image witnesses, OCI configurations and app artifacts
//! have separate roles. Only the native verifier may claim their measured relationship;
//! an operator pins that output in the maintenance request. This is not pod attestation.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Composition {
    pub version: u32,
    pub base_image: String,
    pub base_native: String,
    pub base_config: String,
    pub base_manifest: String,
    pub image: String,
    pub manifest: String,
    pub config: String,
    pub artifact: String,
    pub artifact_tree: String,
    pub layer: String,
    pub verifier: String,
    pub recipe: String,
}

impl Composition {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "runtime_image_composition_version");
        rollout::image(&self.base_image)?;
        rollout::image(&self.image)?;
        ensure!(
            self.base_image != self.image,
            "runtime_image_composition_required"
        );
        for value in [
            &self.base_native,
            &self.base_config,
            &self.base_manifest,
            &self.manifest,
            &self.config,
            &self.artifact,
            &self.artifact_tree,
            &self.layer,
            &self.verifier,
            &self.recipe,
        ] {
            day2_assets::hash_part(value)?;
        }
        let base_root = self
            .base_image
            .rsplit_once('@')
            .context("immutable base image required")?
            .1;
        ensure!(
            [
                base_root,
                self.base_manifest.as_str(),
                self.base_config.as_str()
            ]
            .contains(&self.base_native.as_str()),
            "qualified_image_not_in_base_oci_graph"
        );
        ensure!(
            self.base_config != self.config && self.manifest != self.config,
            "runtime_image_configuration_unchanged"
        );
        Ok(())
    }

    /// The qualified OCI graph binds the pinned index/manifest and its one
    /// native runnable manifest. Containerd may report either descriptor.
    /// Configuration digests and unrelated descriptors are never accepted.
    pub fn require_image_id(&self, image_id: &str) -> Result<()> {
        self.validate()?;
        let root = self
            .image
            .rsplit_once('@')
            .context("immutable image required")?
            .1;
        ensure!(
            image_id.ends_with(&format!("@{root}"))
                || image_id.ends_with(&format!("@{}", self.manifest)),
            "runtime_pair_pulled_image_changed"
        );
        Ok(())
    }

    pub(super) fn require(
        &self,
        runtime: &RuntimeIdentity,
        image: &str,
        artifact: &str,
    ) -> Result<()> {
        self.validate()?;
        runtime.require_qualified()?;
        let Some(Containment::LinuxQualifiedV1 { evidence }) = &runtime.containment else {
            anyhow::bail!("runtime_pair_requires_linux_qualification")
        };
        ensure!(
            self.base_native == evidence.runtime_image
                && self.image == image
                && self.artifact == artifact,
            "runtime_pair_image_changed"
        );
        Ok(())
    }
}

impl Generation {
    pub(crate) fn require_runtime_image(&self) -> Result<()> {
        self.composition
            .as_ref()
            .context("runtime_pair_image_composition_required")?
            .require(&self.runtime, &self.image, &self.artifact)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn composition(
        runtime: &RuntimeIdentity,
        image: &str,
        artifact: &str,
    ) -> Composition {
        let Some(Containment::LinuxQualifiedV1 { evidence }) = &runtime.containment else {
            panic!("fixture qualification")
        };
        Composition {
            version: 1,
            base_image: format!("registry/runtime@{}", evidence.runtime_image),
            base_native: evidence.runtime_image.clone(),
            base_config: crate::digest(b"base OCI configuration"),
            base_manifest: crate::digest(b"base native manifest"),
            image: image.into(),
            manifest: crate::digest(format!("manifest:{image}").as_bytes()),
            config: crate::digest(image.as_bytes()),
            artifact: artifact.into(),
            artifact_tree: crate::digest(b"artifact tree"),
            layer: crate::digest(b"app layer"),
            verifier: crate::digest(b"verifier"),
            recipe: crate::digest(b"recipe"),
        }
    }

    #[test]
    fn composed_manifest_is_bound_to_exact_qualified_configuration_and_artifact() -> Result<()> {
        let runtime = super::super::tests::manifest(b"runtime").runtime;
        let artifact = crate::digest(b"artifact");
        let image = format!("registry/app@{}", crate::digest(b"app manifest"));
        let measured = composition(&runtime, &image, &artifact);
        measured.require(&runtime, &image, &artifact)?;
        for node in [&measured.base_config, &measured.base_manifest] {
            let mut another_witness = measured.clone();
            another_witness.base_native = node.clone();
            another_witness.validate()?;
            assert!(
                another_witness
                    .require(&runtime, &image, &artifact)
                    .is_err()
            );
        }
        measured.require_image_id(&format!("docker-pullable://{image}"))?;
        measured.require_image_id(&format!("registry/app@{}", measured.manifest))?;
        for id in [
            &measured.config,
            &measured.base_config,
            &measured.base_native,
            &crate::digest(b"unrelated"),
        ] {
            assert!(
                measured
                    .require_image_id(&format!("registry/app@{id}"))
                    .is_err()
            );
        }
        assert_ne!(measured.base_config, image.rsplit_once('@').unwrap().1);
        assert!(
            measured
                .require(&runtime, &measured.base_image, &artifact)
                .is_err()
        );
        assert!(
            measured
                .require(&runtime, &image, &crate::digest(b"another artifact"))
                .is_err()
        );
        let another = super::super::tests::manifest(b"another runtime").runtime;
        assert!(measured.require(&another, &image, &artifact).is_err());
        let mut changed = measured.clone();
        changed.version = 2;
        assert!(changed.require(&runtime, &image, &artifact).is_err());
        changed = measured;
        changed.config = changed.base_config.clone();
        assert!(changed.require(&runtime, &image, &artifact).is_err());
        Ok(())
    }
}
