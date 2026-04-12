//! Backend registry with lazy initialization.
//!
//! The registry owns all backend lifecycle state and provides typed access
//! methods for different backend traits.
//!
//! ## Lazy Initialization
//!
//! Backends are **declared** (config stored) at startup and **initialized**
//! (hardware opened) the first time a step actually needs them. This means:
//!
//! - Ceremony setup steps (presence checks, clock sync, etc.) run before
//!   any hardware is touched.
//! - A missing or unplugged device fails at the step that uses it, not at
//!   ceremony startup.
//! - Failed initialization is cached: the hardware is never probed twice.
//!
//! ## Design Notes
//!
//! `BackendRegistry` stores a `BackendState` enum instead of `Box<dyn Backend>`
//! directly. A factory closure injected at construction time creates concrete
//! backends on first use.

use rite_sdk::{
    AttestationBackend, Backend, BackendConfig, BackendError, CertStoreBackend, KeyStoreBackend,
    KeyTransportBackend, PivBackend, Pkcs11AdminBackend, Pkcs11Backend, RandomBackend, SignBackend,
    TpmBackend, YubikeyBackend,
};
use std::collections::HashMap;

// ============================================================================
// Factory type
// ============================================================================

/// A closure that creates a concrete backend from its name and config.
///
/// This is the bridge between `rite-runtime` (which defines the registry) and
/// `rite-stdlib` (which provides the concrete implementations). The CLI
/// injects `rite_stdlib::backend::create_backend` as this closure.
///
/// **Transitional**: This type will be removed when the plugin system is implemented
/// (v1 target). The registry will spawn plugin processes rather than invoking a factory
/// closure.
pub type BackendFactory =
    Box<dyn Fn(String, &BackendConfig) -> Result<Box<dyn Backend>, BackendError> + Send + Sync>;

// ============================================================================
// BackendState
// ============================================================================

enum BackendState {
    /// Declared but not yet initialized — hardware not yet touched.
    Uninitialized(BackendConfig),
    /// Successfully initialized — ready to use.
    Ready(Box<dyn Backend>),
    /// Initialization failed — error cached, hardware will not be retried.
    Failed(String),
}

// ============================================================================
// BackendRegistry
// ============================================================================

/// Backend registry that owns all backend lifecycle state.
///
/// Provides typed accessor methods for different backend traits. Backends are
/// declared at startup (via [`declare`]) and initialized lazily on first use.
///
/// Note: This uses `Box<dyn Backend>` for storage to avoid circular
/// dependencies between rite-runtime and rite-stdlib. Concrete backend
/// implementations live in rite-stdlib.
///
/// [`declare`]: BackendRegistry::declare
pub struct BackendRegistry {
    factory: BackendFactory,
    backends: HashMap<String, BackendState>,
}

impl BackendRegistry {
    /// Create a new registry with a backend factory.
    ///
    /// The factory is called the first time a declared backend is used.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let registry = BackendRegistry::with_factory(
    ///     Box::new(|name, config| rite_stdlib::backend::create_backend(name, config))
    /// );
    /// ```
    pub fn with_factory(factory: BackendFactory) -> Self {
        Self {
            factory,
            backends: HashMap::new(),
        }
    }

    /// Create an empty registry without a factory (for tests).
    ///
    /// The factory always returns `BackendError::NotFound`. Use [`register`]
    /// to insert fully-initialized backends directly.
    ///
    /// [`register`]: BackendRegistry::register
    pub fn new() -> Self {
        Self {
            factory: Box::new(|name, _config| Err(BackendError::NotFound(name))),
            backends: HashMap::new(),
        }
    }

    /// Declare a backend from YAML configuration (lazy — no hardware touched).
    ///
    /// Stores the config only. The backend is not initialized until first use.
    ///
    /// If a backend with the same name already exists, it will be replaced.
    pub fn declare(&mut self, name: String, config: BackendConfig) {
        self.backends
            .insert(name, BackendState::Uninitialized(config));
    }

    /// Register a fully-initialized backend directly (for tests).
    ///
    /// If a backend with the same name already exists, it will be replaced.
    pub fn register(&mut self, backend: Box<dyn Backend>) {
        let name = backend.name().to_string();
        self.backends.insert(name, BackendState::Ready(backend));
    }

    /// Get backend by name (immutable).
    ///
    /// Only returns backends that are already in the `Ready` state. Does not
    /// trigger initialization. Primarily for testing.
    pub fn get(&self, name: &str) -> Option<&dyn Backend> {
        match self.backends.get(name) {
            Some(BackendState::Ready(b)) => Some(b.as_ref()),
            _ => None,
        }
    }

    /// Get backend by name (mutable), initializing it lazily if needed.
    ///
    /// Returns the backend on success, `Err(NotFound)` if the backend was
    /// never declared, or `Err(HardwareFailure)` if initialization failed.
    pub fn get_mut(&mut self, name: &str) -> Result<&mut dyn Backend, BackendError> {
        self.get_ready(name)
    }

    /// Get backend as `KeyStoreBackend` trait.
    pub fn get_keystore(&mut self, name: &str) -> Result<&mut dyn KeyStoreBackend, BackendError> {
        self.get_ready(name)?
            .as_keystore_mut()
            .ok_or_else(|| unsupported(name, "KeyStoreBackend"))
    }

    /// Get backend as `SignBackend` trait.
    pub fn get_sign(&mut self, name: &str) -> Result<&mut dyn SignBackend, BackendError> {
        self.get_ready(name)?
            .as_sign_mut()
            .ok_or_else(|| unsupported(name, "SignBackend"))
    }

    /// Get backend as `AttestationBackend` trait (mutable).
    pub fn get_attest_mut(
        &mut self,
        name: &str,
    ) -> Result<&mut dyn AttestationBackend, BackendError> {
        self.get_ready(name)?
            .as_attest_mut()
            .ok_or_else(|| unsupported(name, "AttestationBackend"))
    }

    /// Get backend as `PivBackend` trait (mutable).
    pub fn get_piv(&mut self, name: &str) -> Result<&mut dyn PivBackend, BackendError> {
        self.get_ready(name)?
            .as_piv_mut()
            .ok_or_else(|| unsupported(name, "PivBackend"))
    }

    /// Get backend as `YubikeyBackend` trait (mutable).
    pub fn get_yubikey(&mut self, name: &str) -> Result<&mut dyn YubikeyBackend, BackendError> {
        self.get_ready(name)?
            .as_yubikey_mut()
            .ok_or_else(|| unsupported(name, "YubikeyBackend"))
    }

    /// Get backend as `KeyTransportBackend` trait (mutable).
    pub fn get_transport(
        &mut self,
        name: &str,
    ) -> Result<&mut dyn KeyTransportBackend, BackendError> {
        self.get_ready(name)?
            .as_transport_mut()
            .ok_or_else(|| unsupported(name, "KeyTransportBackend"))
    }

    /// Get backend as `CertStoreBackend` trait (mutable).
    pub fn get_certstore(
        &mut self,
        name: &str,
    ) -> Result<&mut dyn CertStoreBackend, BackendError> {
        self.get_ready(name)?
            .as_certstore_mut()
            .ok_or_else(|| unsupported(name, "CertStoreBackend"))
    }

    /// Get backend as `RandomBackend` trait (mutable).
    pub fn get_random(&mut self, name: &str) -> Result<&mut dyn RandomBackend, BackendError> {
        self.get_ready(name)?
            .as_random_mut()
            .ok_or_else(|| unsupported(name, "RandomBackend"))
    }

    /// Get backend as `Pkcs11Backend` trait (mutable).
    pub fn get_pkcs11(&mut self, name: &str) -> Result<&mut dyn Pkcs11Backend, BackendError> {
        self.get_ready(name)?
            .as_pkcs11_mut()
            .ok_or_else(|| unsupported(name, "Pkcs11Backend"))
    }

    /// Get backend as `Pkcs11AdminBackend` trait (mutable).
    pub fn get_pkcs11_admin(
        &mut self,
        name: &str,
    ) -> Result<&mut dyn Pkcs11AdminBackend, BackendError> {
        self.get_ready(name)?
            .as_pkcs11_admin_mut()
            .ok_or_else(|| unsupported(name, "Pkcs11AdminBackend"))
    }

    /// Get backend as `TpmBackend` trait (mutable).
    pub fn get_tpm(&mut self, name: &str) -> Result<&mut dyn TpmBackend, BackendError> {
        self.get_ready(name)?
            .as_tpm_mut()
            .ok_or_else(|| unsupported(name, "TpmBackend"))
    }

    /// List all registered backend names.
    pub fn backend_names(&self) -> impl Iterator<Item = &String> {
        self.backends.keys()
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// Initialize (if needed) and return a mutable reference to the backend.
    fn get_ready(&mut self, name: &str) -> Result<&mut dyn Backend, BackendError> {
        self.try_initialize(name)?;
        match self.backends.get_mut(name) {
            Some(BackendState::Ready(b)) => Ok(b.as_mut()),
            Some(BackendState::Failed(msg)) => Err(BackendError::HardwareFailure(msg.clone())),
            None => Err(BackendError::NotFound(name.to_string())),
            Some(BackendState::Uninitialized(_)) => {
                unreachable!("backend should be Ready or Failed after try_initialize")
            }
        }
    }

    /// Initialize a declared backend, caching success or failure.
    ///
    /// Uses a two-pass approach to satisfy the borrow checker:
    /// 1. Clone the config (releases the immutable borrow on `self.backends`).
    /// 2. Call the factory (no borrow held on `self.backends`).
    /// 3. Update the entry in place.
    fn try_initialize(&mut self, name: &str) -> Result<(), BackendError> {
        // First pass: inspect state (borrow released at end of match).
        let config = match self.backends.get(name) {
            Some(BackendState::Uninitialized(config)) => config.clone(),
            Some(BackendState::Ready(_)) => return Ok(()),
            Some(BackendState::Failed(msg)) => {
                return Err(BackendError::HardwareFailure(msg.clone()));
            }
            None => return Err(BackendError::NotFound(name.to_string())),
        };

        // Second pass: call factory and update in place (key already exists).
        match (self.factory)(name.to_string(), &config) {
            Ok(backend) => {
                // Key is guaranteed to exist — we checked above.
                if let Some(state) = self.backends.get_mut(name) {
                    *state = BackendState::Ready(backend);
                }
                Ok(())
            }
            Err(e) => {
                let msg = e.to_string();
                if let Some(state) = self.backends.get_mut(name) {
                    *state = BackendState::Failed(msg);
                }
                Err(e)
            }
        }
    }
}

impl Default for BackendRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn unsupported(name: &str, trait_name: &str) -> BackendError {
    BackendError::UnsupportedOperation(format!(
        "Backend '{name}' does not implement {trait_name}"
    ))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rite_sdk::{Backend, BackendError, KeyId, KeyMetadata, KeySpec, KeyStoreBackend};

    // -------------------------------------------------------------------------
    // Minimal mock backend for registry tests
    // -------------------------------------------------------------------------

    struct MinimalMock {
        name: String,
    }

    impl Backend for MinimalMock {
        fn name(&self) -> &str {
            &self.name
        }
        fn provider(&self) -> &str {
            "mock"
        }
        fn fingerprint(&self) -> String {
            format!("mock={}", self.name)
        }
        fn as_keystore_mut(&mut self) -> Option<&mut dyn KeyStoreBackend> {
            Some(self)
        }
    }

    impl KeyStoreBackend for MinimalMock {
        fn generate_key(&mut self, spec: KeySpec) -> Result<KeyMetadata, BackendError> {
            Ok(KeyMetadata {
                key_id: KeyId::new("mock-key-1"),
                algorithm: spec.algorithm,
                label: spec.label,
                public_key: None,
                attestation: None,
            })
        }
        fn import_private_key(
            &mut self,
            spec: KeySpec,
            _key_bytes: &[u8],
        ) -> Result<KeyMetadata, BackendError> {
            Ok(KeyMetadata {
                key_id: KeyId::new("mock-imported-1"),
                algorithm: spec.algorithm,
                label: spec.label,
                public_key: None,
                attestation: None,
            })
        }
        fn export_public_key(&self, _key_id: &KeyId) -> Result<Vec<u8>, BackendError> {
            Ok(vec![])
        }
        fn list_keys(&self) -> Result<Vec<KeyMetadata>, BackendError> {
            Ok(vec![])
        }
        fn delete_key(&mut self, _key_id: &KeyId) -> Result<(), BackendError> {
            Ok(())
        }
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    #[test]
    fn registry_not_found_returns_none() {
        let registry = BackendRegistry::new();
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn registry_lists_backend_names_empty() {
        let registry = BackendRegistry::new();
        assert_eq!(registry.backend_names().count(), 0);
    }

    #[test]
    fn register_then_get_returns_backend() {
        let mut registry = BackendRegistry::new();
        registry.register(Box::new(MinimalMock {
            name: "mock".to_string(),
        }));
        assert!(registry.get("mock").is_some());
        assert_eq!(registry.get("mock").unwrap().name(), "mock");
    }

    #[test]
    fn register_then_get_keystore_succeeds() {
        let mut registry = BackendRegistry::new();
        registry.register(Box::new(MinimalMock {
            name: "mock".to_string(),
        }));
        assert!(registry.get_keystore("mock").is_ok());
    }

    #[test]
    fn declare_and_lazy_init_via_factory() {
        let mut registry = BackendRegistry::with_factory(Box::new(|name, _config| {
            Ok(Box::new(MinimalMock { name }) as Box<dyn Backend>)
        }));

        let config = BackendConfig {
            provider: "mock".to_string(),
            extra: serde_json::json!({}),
        };

        // Declare without initializing
        registry.declare("lazy".to_string(), config);

        // Backend not yet in ready state
        assert!(registry.get("lazy").is_none());

        // First access triggers initialization
        let result = registry.get_keystore("lazy");
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result.err());

        // Now it's in ready state
        assert!(registry.get("lazy").is_some());
    }

    #[test]
    fn unsupported_trait_returns_error() {
        // MinimalMock only implements KeyStoreBackend, not SignBackend.
        let mut registry = BackendRegistry::new();
        registry.register(Box::new(MinimalMock {
            name: "mock".to_string(),
        }));

        let result = registry.get_sign("mock");
        assert!(result.is_err());
        match result.err().unwrap() {
            BackendError::UnsupportedOperation(msg) => {
                assert!(
                    msg.contains("SignBackend"),
                    "Expected UnsupportedOperation for SignBackend, got: {}",
                    msg
                );
            }
            e => panic!("Expected UnsupportedOperation, got: {}", e),
        }
    }

    #[test]
    fn get_mut_undeclared_returns_not_found() {
        let mut registry = BackendRegistry::new();
        let result = registry.get_mut("nonexistent");
        assert!(result.is_err());
        match result.err().unwrap() {
            BackendError::NotFound(name) => assert_eq!(name, "nonexistent"),
            e => panic!("Expected NotFound, got: {}", e),
        }
    }

    #[test]
    fn factory_failure_cached_no_retry() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);

        let mut registry = BackendRegistry::with_factory(Box::new(move |_name, _config| {
            call_count_clone.fetch_add(1, Ordering::SeqCst);
            Err(BackendError::HardwareFailure(
                "device not found".to_string(),
            ))
        }));

        let config = BackendConfig {
            provider: "mock".to_string(),
            extra: serde_json::json!({}),
        };
        registry.declare("failing".to_string(), config);

        // First call triggers factory
        let _ = registry.get_keystore("failing");
        assert_eq!(call_count.load(Ordering::SeqCst), 1);

        // Second call must NOT call factory again (error cached)
        let _ = registry.get_keystore("failing");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "Factory called more than once"
        );
    }

    #[test]
    fn lazy_init_unsupported_trait_returns_error() {
        // Factory creates a MinimalMock (only KeyStore), then asking for
        // AttestationBackend should return UnsupportedOperation.
        let mut registry = BackendRegistry::with_factory(Box::new(|name, _config| {
            Ok(Box::new(MinimalMock { name }) as Box<dyn Backend>)
        }));

        let config = BackendConfig {
            provider: "yubikey".to_string(),
            extra: serde_json::json!({}),
        };
        registry.declare("yk".to_string(), config);

        let result = registry.get_attest_mut("yk");
        match result {
            Err(BackendError::UnsupportedOperation(msg)) => {
                assert!(
                    msg.contains("AttestationBackend"),
                    "Expected AttestationBackend error, got: {}",
                    msg
                );
            }
            Ok(_) => panic!("Expected UnsupportedOperation, got Ok"),
            Err(e) => panic!("Expected UnsupportedOperation, got: {:?}", e),
        }
    }
}
