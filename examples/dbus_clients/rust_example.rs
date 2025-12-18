// Example Rust client for openssl_encrypt D-Bus service
//
// Add to Cargo.toml:
// [dependencies]
// zbus = "3.15"
// tokio = { version = "1", features = ["full"] }
// anyhow = "1.0"

use zbus::{Connection, Result, dbus_proxy};
use std::collections::HashMap;
use zbus::zvariant::Value;

#[dbus_proxy(
    interface = "ch.rm-rf.openssl_encrypt.Crypto",
    default_service = "ch.rm-rf.openssl_encrypt",
    default_path = "/ch/rm_rf/openssl_encrypt/CryptoService"
)]
trait Crypto {
    /// Get openssl_encrypt version
    fn get_version(&self) -> Result<String>;

    /// Get list of supported encryption algorithms
    fn get_supported_algorithms(&self) -> Result<Vec<String>>;

    /// Validate password against security policy
    fn validate_password(&self, password: &str) -> Result<(bool, Vec<String>)>;

    /// Encrypt a file
    fn encrypt_file(
        &self,
        input_path: &str,
        output_path: &str,
        password: &str,
        algorithm: &str,
        options: HashMap<String, Value<'_>>,
    ) -> Result<(bool, String, String)>;

    /// Decrypt a file
    fn decrypt_file(
        &self,
        input_path: &str,
        output_path: &str,
        password: &str,
    ) -> Result<(bool, String, String)>;

    /// Generate a post-quantum cryptographic key
    fn generate_pqc_key(
        &self,
        algorithm: &str,
        keystore_path: &str,
        keystore_password: &str,
        key_name: &str,
    ) -> Result<(bool, String, String)>;

    /// Get active operations count
    #[dbus_proxy(property)]
    fn active_operations(&self) -> Result<u32>;

    /// Get max concurrent operations
    #[dbus_proxy(property)]
    fn max_concurrent_operations(&self) -> Result<u32>;
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("=======================================================");
    println!("openssl_encrypt D-Bus Service - Rust Example");
    println!("=======================================================");

    // Connect to session bus
    let connection = Connection::session().await?;
    let proxy = CryptoProxy::new(&connection).await?;

    // 1. Get service information
    println!("\n1. Service Information");
    println!("-------------------------------------------------------");

    let version = proxy.get_version().await?;
    println!("Version: {}", version);

    let algorithms = proxy.get_supported_algorithms().await?;
    println!("Supported algorithms ({}):", algorithms.len());
    for algo in algorithms.iter().take(10) {
        println!("  - {}", algo);
    }
    if algorithms.len() > 10 {
        println!("  ... and {} more", algorithms.len() - 10);
    }

    // 2. Validate passwords
    println!("\n2. Password Validation");
    println!("-------------------------------------------------------");

    let test_passwords = vec!["weak", "StrongPass123!", "short"];
    for pwd in test_passwords {
        let (valid, issues) = proxy.validate_password(pwd).await?;
        let status = if valid { "✓" } else { "✗" };
        if issues.is_empty() {
            println!("{} '{}': Valid", status, pwd);
        } else {
            println!("{} '{}': {}", status, pwd, issues.join(" / "));
        }
    }

    // 3. Get service properties
    println!("\n3. Service Properties");
    println!("-------------------------------------------------------");

    let active_ops = proxy.active_operations().await?;
    println!("Active operations: {}", active_ops);

    let max_ops = proxy.max_concurrent_operations().await?;
    println!("Max concurrent operations: {}", max_ops);

    // 4. File encryption example
    println!("\n4. File Encryption Example");
    println!("-------------------------------------------------------");

    // Create temporary test file
    use std::fs::File;
    use std::io::Write;
    let test_file = "/tmp/rust_test_file.txt";
    let encrypted_file = "/tmp/rust_test_file.txt.enc";
    let decrypted_file = "/tmp/rust_test_file.txt.dec";

    let mut file = File::create(test_file)?;
    writeln!(file, "This is a test file for encryption.")?;
    for _ in 0..10 {
        writeln!(file, "It contains some sample data.")?;
    }
    drop(file);

    println!("Test file: {}", test_file);
    println!("Encrypted file: {}", encrypted_file);
    println!("Decrypted file: {}", decrypted_file);

    // Encrypt the file
    println!("\nEncrypting file...");
    let mut options = HashMap::new();
    options.insert("sha512_rounds".to_string(), Value::new(10000_i32));
    options.insert("enable_hkdf".to_string(), Value::new(true));

    let (success, error, op_id) = proxy.encrypt_file(
        test_file,
        encrypted_file,
        "TestPassword123!",
        "fernet",
        options,
    ).await?;

    if !success {
        println!("✗ Encryption failed: {}", error);
        return Ok(());
    }

    println!("✓ Encryption initiated: {}", op_id);

    // Wait for operation to complete
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Decrypt the file
    println!("\nDecrypting file...");
    let (success, error, op_id) = proxy.decrypt_file(
        encrypted_file,
        decrypted_file,
        "TestPassword123!",
    ).await?;

    if !success {
        println!("✗ Decryption failed: {}", error);
        return Ok(());
    }

    println!("✓ Decryption initiated: {}", op_id);
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Verify decrypted content
    let original = std::fs::read_to_string(test_file)?;
    match std::fs::read_to_string(decrypted_file) {
        Ok(decrypted) => {
            if original == decrypted {
                println!("✓ Decrypted content matches original");
            } else {
                println!("✗ Decrypted content does not match original");
            }
        }
        Err(_) => {
            println!("✗ Decrypted file not found (operation may still be running)");
        }
    }

    // 5. Post-quantum key generation
    println!("\n5. Post-Quantum Key Generation Example");
    println!("-------------------------------------------------------");

    let keystore_file = "/tmp/rust_keystore.pqc";
    println!("Keystore file: {}", keystore_file);

    println!("\nGenerating ML-KEM-768 key...");
    let (success, key_id, error) = proxy.generate_pqc_key(
        "ml-kem-768",
        keystore_file,
        "KeystorePassword123!",
        "Example Key",
    ).await?;

    if success {
        println!("✓ Key generated: {}", key_id);
    } else {
        println!("✗ Key generation failed: {}", error);
        if error.contains("Not implemented") {
            println!("  (Keystore integration pending)");
        }
    }

    // Cleanup
    println!("\n6. Cleanup");
    println!("-------------------------------------------------------");
    println!("Cleaning up temporary files...");
    for path in &[test_file, encrypted_file, decrypted_file, keystore_file] {
        match std::fs::remove_file(path) {
            Ok(_) => println!("  ✓ Deleted {}", path),
            Err(_) => (), // File doesn't exist, ignore
        }
    }

    println!("\n=======================================================");
    println!("Example completed successfully!");
    println!("=======================================================");

    Ok(())
}
