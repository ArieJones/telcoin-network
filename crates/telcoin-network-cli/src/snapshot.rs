//! Snapshot manifest primitives used by db snapshot commands.

use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::File,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tar::{Archive, Builder, Header};
use sha2::{Digest, Sha256};

/// Current snapshot manifest schema version.
pub const SNAPSHOT_MANIFEST_VERSION: u32 = 1;
/// Canonical snapshot manifest file name.
pub const SNAPSHOT_MANIFEST_FILE_NAME: &str = "manifest.json";
/// Placeholder value until packaging pipeline injects stronger checksum semantics.
pub const SNAPSHOT_MANIFEST_EXTERNAL_CHECKSUM: &str = "external-sidecar-sha256";

/// Result values for a snapshot artifact creation run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotCreateResult {
    /// Path to the created tar artifact.
    pub artifact_path: PathBuf,
    /// Path to the checksum sidecar file.
    pub checksum_path: PathBuf,
    /// Computed artifact SHA256 digest as lower-case hex.
    pub checksum_sha256: String,
}

/// Top-level snapshot manifest written alongside snapshot data.
///
/// This mirrors Reth's snapshot-manifest approach:
/// - chain and storage metadata at the top level
/// - component map describing what is included
/// - per-file metadata for restore-time verification and planning
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotManifest {
    /// Block number this snapshot was taken at.
    pub block: u64,
    /// Chain ID.
    pub chain_id: u64,
    /// Storage version (1 = legacy, 2 = current).
    pub storage_version: u64,
    /// Timestamp when the snapshot was created (unix seconds).
    pub timestamp: u64,
    /// Optional base URL for hosted archives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// TN version that produced this snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tn_version: Option<String>,
    /// Available snapshot components.
    pub components: BTreeMap<String, ComponentManifest>,
}

/// Manifest entry for a single snapshot component.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ComponentManifest {
    /// A single archive-like payload (used by current TN implementation).
    Single(SingleArchive),
    /// A chunked archive set (reserved for future chunked packaging support).
    Chunked(ChunkedArchive),
}

/// A single component payload with included output files and metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SingleArchive {
    /// Artifact file name (relative to base_url when hosted).
    pub file: String,
    /// Component payload size in bytes.
    pub size: u64,
    /// Total extracted plain-output size in bytes.
    #[serde(default)]
    pub decompressed_size: u64,
    /// Optional SHA256 checksum of the artifact file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Expected extracted plain files for this component.
    #[serde(default)]
    pub output_files: Vec<OutputFileChecksum>,
    /// Relative paths included for this component.
    #[serde(default)]
    pub included_paths: Vec<String>,
    /// Relative paths explicitly excluded for this component.
    #[serde(default)]
    pub excluded_paths: Vec<String>,
    /// Whether this component is required for a functional restore.
    #[serde(default)]
    pub required: bool,
}

/// A reserved chunked component layout for future parity with Reth chunk manifests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChunkedArchive {
    /// Block range span per chunk.
    pub blocks_per_file: u64,
    /// Total blocks represented by this component.
    pub total_blocks: u64,
    /// Compressed chunk sizes.
    #[serde(default)]
    pub chunk_sizes: Vec<u64>,
    /// Extracted plain output metadata per chunk.
    #[serde(default)]
    pub chunk_output_files: Vec<Vec<OutputFileChecksum>>,
}

/// Expected metadata for one extracted plain file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutputFileChecksum {
    /// Relative path under target datadir.
    pub path: String,
    /// Plain file size in bytes.
    pub size: u64,
    /// SHA256 checksum of plain file contents.
    pub sha256: String,
}

impl SnapshotManifest {
    /// Build a manifest scaffold from a datadir in a reth-style component map format.
    pub fn scaffold(datadir: &Path, artifact_file_name: &str) -> eyre::Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();

        let mut components = BTreeMap::new();
        components.insert(
            "consensus".to_string(),
            ComponentManifest::Single(build_single_component(
                datadir,
                "consensus-db",
                artifact_file_name,
                true,
                &[],
            )?),
        );
        components.insert(
            "execution_db".to_string(),
            ComponentManifest::Single(build_single_component(
                datadir,
                "db",
                artifact_file_name,
                true,
                &[],
            )?),
        );
        components.insert(
            "execution_static_files".to_string(),
            ComponentManifest::Single(build_single_component(
                datadir,
                "static_files",
                artifact_file_name,
                true,
                &[],
            )?),
        );

        Ok(Self {
            block: 0,
            chain_id: 0,
            storage_version: 2,
            timestamp,
            base_url: None,
            tn_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            components,
        })
    }

    /// Validate required manifest fields and schema compatibility.
    pub fn validate(&self) -> eyre::Result<()> {
        if self.storage_version != 2 {
            return Err(eyre::eyre!(
                "unsupported storage version {}, expected 2",
                self.storage_version
            ));
        }
        if self.components.is_empty() {
            return Err(eyre::eyre!("snapshot manifest missing components"));
        }
        for (name, component) in &self.components {
            match component {
                ComponentManifest::Single(single) => {
                    if single.included_paths.is_empty() {
                        return Err(eyre::eyre!(
                            "snapshot component '{}' has no included paths",
                            name
                        ));
                    }
                }
                ComponentManifest::Chunked(chunked) => {
                    if chunked.blocks_per_file == 0 {
                        return Err(eyre::eyre!(
                            "snapshot component '{}' has invalid chunk metadata",
                            name
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

fn build_single_component(
    datadir: &Path,
    relative_root: &str,
    artifact_file_name: &str,
    required: bool,
    excluded_basenames: &[&str],
) -> eyre::Result<SingleArchive> {
    let root = datadir.join(relative_root);
    if !root.exists() {
        return Err(eyre::eyre!(
            "required snapshot input path is missing: {}",
            root.display()
        ));
    }

    let mut output_files = Vec::new();
    collect_output_files_recursive(&root, &root, relative_root, excluded_basenames, &mut output_files)?;
    output_files.sort_unstable_by(|a, b| a.path.cmp(&b.path));
    let decompressed_size = output_files.iter().map(|f| f.size).sum();

    Ok(SingleArchive {
        file: artifact_file_name.to_string(),
        size: decompressed_size,
        decompressed_size,
        sha256: Some(SNAPSHOT_MANIFEST_EXTERNAL_CHECKSUM.to_string()),
        output_files,
        included_paths: vec![relative_root.to_string()],
        excluded_paths: excluded_basenames.iter().map(|s| s.to_string()).collect(),
        required,
    })
}

fn collect_output_files_recursive(
    root: &Path,
    current: &Path,
    relative_prefix: &str,
    excluded_basenames: &[&str],
    out: &mut Vec<OutputFileChecksum>,
) -> eyre::Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_output_files_recursive(
                root,
                &path,
                relative_prefix,
                excluded_basenames,
                out,
            )?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }

        let base = path.file_name().and_then(|f| f.to_str()).unwrap_or_default();
        if excluded_basenames.iter().any(|excluded| *excluded == base) {
            continue;
        }

        let rel = path.strip_prefix(root)?;
        let rel_str = if rel.as_os_str().is_empty() {
            relative_prefix.to_string()
        } else {
            format!("{}/{}", relative_prefix, rel.to_string_lossy())
        };

        out.push(OutputFileChecksum {
            path: rel_str,
            size: fs::metadata(&path)?.len(),
            sha256: sha256_file_hex(&path)?,
        });
    }

    Ok(())
}

/// Create a tar snapshot artifact plus sidecar SHA256 for the provided datadir.
pub fn create_snapshot_artifact(
    datadir: &Path,
    output_artifact: &Path,
) -> eyre::Result<SnapshotCreateResult> {
    let consensus_db = datadir.join("consensus-db");
    let execution_db = datadir.join("db");
    let static_files = datadir.join("static_files");

    for required in [&consensus_db, &execution_db, &static_files] {
        if !required.exists() {
            return Err(eyre::eyre!(
                "required snapshot input path is missing: {}",
                required.display()
            ));
        }
    }

    if let Some(parent) = output_artifact.parent() {
        fs::create_dir_all(parent)?;
    }

    let artifact_file_name = output_artifact
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("snapshot.tnsnap");
    let mut manifest = SnapshotManifest::scaffold(datadir, artifact_file_name)?;

    let file = File::create(output_artifact)?;
    let mut tar_builder = Builder::new(file);

    append_manifest_entry(&mut tar_builder, &manifest)?;
    tar_builder.append_dir_all("consensus-db", &consensus_db)?;
    tar_builder.append_dir_all("db", &execution_db)?;
    tar_builder.append_dir_all("static_files", &static_files)?;
    tar_builder.finish()?;
    drop(tar_builder);

    let checksum_sha256 = sha256_file_hex(output_artifact)?;
    let checksum_path = output_artifact.with_extension("sha256");
    let artifact_name = output_artifact
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("snapshot.tar");
    fs::write(&checksum_path, format!("{checksum_sha256}  {artifact_name}\n"))?;

    for component in manifest.components.values_mut() {
        if let ComponentManifest::Single(single) = component {
            single.sha256 = Some(checksum_sha256.clone());
        }
    }

    Ok(SnapshotCreateResult {
        artifact_path: output_artifact.to_path_buf(),
        checksum_path,
        checksum_sha256,
    })
}

fn append_manifest_entry<W: std::io::Write>(
    tar_builder: &mut Builder<W>,
    manifest: &SnapshotManifest,
) -> eyre::Result<()> {
    let data = serde_json::to_vec_pretty(manifest)?;
    let mut header = Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(manifest.timestamp);
    header.set_uid(0);
    header.set_gid(0);
    header.set_cksum();
    tar_builder.append_data(&mut header, SNAPSHOT_MANIFEST_FILE_NAME, data.as_slice())?;
    Ok(())
}

fn sha256_file_hex(path: &Path) -> eyre::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0_u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Resolve a readable manifest path from a directory or manifest file input.
pub fn resolve_manifest_read_path(input: &Path) -> eyre::Result<PathBuf> {
    if input.is_dir() {
        return Ok(input.join(SNAPSHOT_MANIFEST_FILE_NAME));
    }
    if input
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == SNAPSHOT_MANIFEST_FILE_NAME)
    {
        return Ok(input.to_path_buf());
    }

    Err(eyre::eyre!("manifest path could not be resolved from input"))
}

/// Write a manifest to the provided snapshot directory.
pub fn write_manifest_to_dir(snapshot_dir: &Path, manifest: &SnapshotManifest) -> eyre::Result<()> {
    fs::create_dir_all(snapshot_dir)?;
    let manifest_path = snapshot_dir.join(SNAPSHOT_MANIFEST_FILE_NAME);
    let data = serde_json::to_vec_pretty(manifest)?;
    fs::write(manifest_path, data)?;
    Ok(())
}

/// Read and validate a snapshot manifest from a directory or manifest file path.
pub fn read_manifest(input: &Path) -> eyre::Result<SnapshotManifest> {
    if input.is_file()
        && input
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n != SNAPSHOT_MANIFEST_FILE_NAME)
    {
        return read_manifest_from_artifact(input);
    }

    let manifest_path = resolve_manifest_read_path(input)?;
    let data = fs::read(&manifest_path)?;
    let manifest: SnapshotManifest = serde_json::from_slice(&data)?;
    manifest.validate()?;
    Ok(manifest)
}

fn read_manifest_from_artifact(artifact: &Path) -> eyre::Result<SnapshotManifest> {
    let file = File::open(artifact)?;
    let mut archive = Archive::new(file);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == SNAPSHOT_MANIFEST_FILE_NAME)
        {
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            let manifest: SnapshotManifest = serde_json::from_slice(&data)?;
            manifest.validate()?;
            return Ok(manifest);
        }
    }

    Err(eyre::eyre!(
        "snapshot artifact does not contain {}",
        SNAPSHOT_MANIFEST_FILE_NAME
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        create_snapshot_artifact, read_manifest, resolve_manifest_read_path, write_manifest_to_dir,
        ComponentManifest, SnapshotManifest,
        SNAPSHOT_MANIFEST_FILE_NAME,
    };
    use std::fs;

    #[test]
    fn writes_and_reads_manifest() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("consensus-db")).unwrap();
        fs::create_dir_all(temp.path().join("db")).unwrap();
        fs::create_dir_all(temp.path().join("static_files")).unwrap();
        let manifest = SnapshotManifest::scaffold(temp.path(), "snapshot.tnsnap").unwrap();
        write_manifest_to_dir(temp.path(), &manifest).unwrap();

        let read_back = read_manifest(temp.path()).unwrap();
        assert_eq!(read_back.storage_version, manifest.storage_version);
        assert_eq!(read_back.components.len(), manifest.components.len());
    }

    #[test]
    fn resolve_manifest_path_for_directory() {
        let temp = tempfile::tempdir().unwrap();
        let resolved = resolve_manifest_read_path(temp.path()).unwrap();
        assert_eq!(resolved.file_name().unwrap(), SNAPSHOT_MANIFEST_FILE_NAME);
    }

    #[test]
    fn creates_snapshot_artifact_and_checksum_sidecar() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("consensus-db")).unwrap();
        fs::create_dir_all(temp.path().join("db")).unwrap();
        fs::create_dir_all(temp.path().join("static_files")).unwrap();
        fs::write(temp.path().join("consensus-db").join("marker.txt"), b"x").unwrap();

        let artifact = temp.path().join("snapshot.tnsnap");
        let result = create_snapshot_artifact(temp.path(), &artifact).unwrap();

        assert!(result.artifact_path.exists());
        assert!(result.checksum_path.exists());
        assert!(!result.checksum_sha256.is_empty());
    }

    #[test]
    fn reads_manifest_from_artifact_file() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("consensus-db")).unwrap();
        fs::create_dir_all(temp.path().join("db")).unwrap();
        fs::create_dir_all(temp.path().join("static_files")).unwrap();

        let artifact = temp.path().join("snapshot.tnsnap");
        create_snapshot_artifact(temp.path(), &artifact).unwrap();

        let manifest = read_manifest(&artifact).unwrap();
        assert_eq!(manifest.storage_version, 2);
        assert!(manifest.components.contains_key("consensus"));
        match manifest.components.get("consensus").unwrap() {
            ComponentManifest::Single(single) => {
                assert!(single.included_paths.contains(&"consensus-db".to_string()));
            }
            ComponentManifest::Chunked(_) => panic!("unexpected chunked component"),
        }
    }
}
