//! Snapshot manifest primitives used by db snapshot commands.

use serde::{Deserialize, Serialize};
use std::{
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

/// Head metadata for either consensus or execution state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotHead {
    /// Header number associated with this snapshot head.
    pub number: u64,
    /// Header hash string associated with this snapshot head.
    pub hash: String,
}

/// Top-level snapshot manifest written alongside snapshot data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotManifest {
    /// Manifest schema version.
    pub version: u32,
    /// Manifest creation timestamp in UNIX seconds.
    pub created_at_unix_secs: u64,
    /// Data directory used to create this snapshot.
    pub datadir: String,
    /// Consensus state head metadata.
    pub consensus_head: SnapshotHead,
    /// Execution state head metadata.
    pub execution_head: SnapshotHead,
    /// SHA256 digest of the packaged snapshot artifact.
    pub checksum_sha256: String,
}

impl SnapshotManifest {
    /// Build a scaffolding manifest for snapshot workflow initialization.
    pub fn scaffold(datadir: &Path) -> Self {
        let created_at_unix_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();

        Self {
            version: SNAPSHOT_MANIFEST_VERSION,
            created_at_unix_secs,
            datadir: datadir.display().to_string(),
            consensus_head: SnapshotHead { number: 0, hash: "unknown".to_string() },
            execution_head: SnapshotHead { number: 0, hash: "unknown".to_string() },
            checksum_sha256: SNAPSHOT_MANIFEST_EXTERNAL_CHECKSUM.to_string(),
        }
    }

    /// Validate required manifest fields and schema compatibility.
    pub fn validate(&self) -> eyre::Result<()> {
        if self.version != SNAPSHOT_MANIFEST_VERSION {
            return Err(eyre::eyre!(
                "unsupported snapshot manifest version {}, expected {}",
                self.version,
                SNAPSHOT_MANIFEST_VERSION
            ));
        }
        if self.datadir.trim().is_empty() {
            return Err(eyre::eyre!("snapshot manifest missing datadir"));
        }
        Ok(())
    }
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

    let mut manifest = SnapshotManifest::scaffold(datadir);
    manifest.checksum_sha256 = SNAPSHOT_MANIFEST_EXTERNAL_CHECKSUM.to_string();

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
    header.set_mtime(manifest.created_at_unix_secs);
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
        SnapshotManifest,
        SNAPSHOT_MANIFEST_FILE_NAME,
    };
    use std::fs;

    #[test]
    fn writes_and_reads_manifest() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = SnapshotManifest::scaffold(temp.path());
        write_manifest_to_dir(temp.path(), &manifest).unwrap();

        let read_back = read_manifest(temp.path()).unwrap();
        assert_eq!(read_back.version, manifest.version);
        assert_eq!(read_back.datadir, manifest.datadir);
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
        assert_eq!(manifest.version, super::SNAPSHOT_MANIFEST_VERSION);
    }
}
