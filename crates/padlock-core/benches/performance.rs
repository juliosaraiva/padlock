use criterion::{black_box, criterion_group, criterion_main, Criterion};
use padlock_core::entries::crud::{create_entry, search_by_name, search_by_tag};
use padlock_core::entries::types::EntryData;
use padlock_core::error::{Error, VaultError};
use padlock_core::traits::storage::StorageBackend;
use padlock_core::vault::lifecycle::{KdfParams, Vault};

struct InMemStorage {
    data: std::sync::Mutex<Option<Vec<u8>>>,
}

impl InMemStorage {
    fn new() -> Self {
        Self {
            data: std::sync::Mutex::new(None),
        }
    }
}

impl StorageBackend for InMemStorage {
    fn write_vault(&self, data: &[u8]) -> padlock_core::error::Result<()> {
        *self.data.lock().unwrap() = Some(data.to_vec());
        Ok(())
    }
    fn read_vault(&self) -> padlock_core::error::Result<Vec<u8>> {
        self.data.lock().unwrap().clone().ok_or_else(|| {
            Error::Vault(VaultError::NotFound {
                path: "<mem>".to_string(),
            })
        })
    }
    fn vault_exists(&self) -> padlock_core::error::Result<bool> {
        Ok(self.data.lock().unwrap().is_some())
    }
    fn write_backup(&self, _data: &[u8]) -> padlock_core::error::Result<()> {
        Ok(())
    }
}

fn test_params() -> KdfParams {
    KdfParams::testing()
}

fn make_credential(name: &str) -> (String, EntryData, Vec<String>) {
    (
        name.to_string(),
        EntryData::Credential {
            username: "user".to_string(),
            password: "password123".to_string(),
            url: Some("https://example.com".to_string()),
            notes: None,
        },
        vec!["test".to_string()],
    )
}

fn make_vault_with_entries(count: usize) -> (Vault, InMemStorage) {
    let storage = InMemStorage::new();
    let mut vault = Vault::init("bench-pass", &storage, &test_params()).unwrap();

    for i in 0..count {
        let (name, data, tags) = make_credential(&format!("entry-{i}"));
        create_entry(&mut vault, name, data, tags).unwrap();
    }

    (vault, storage)
}

fn bench_create_entry_in_vault(c: &mut Criterion) {
    let mut group = c.benchmark_group("create_entry");

    for count in [10, 100, 500] {
        group.bench_function(format!("vault_with_{count}_entries"), |b| {
            b.iter_with_setup(
                || make_vault_with_entries(count),
                |(mut vault, _storage)| {
                    let (name, data, tags) = make_credential("new-entry");
                    let _ = black_box(create_entry(&mut vault, name, data, tags));
                },
            );
        });
    }

    group.finish();
}

fn bench_vault_write_to_storage(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_to_storage");

    for count in [10, 100, 500] {
        group.bench_function(format!("vault_with_{count}_entries"), |b| {
            let (_vault, storage) = make_vault_with_entries(count);
            b.iter_with_setup(
                || {
                    let s = InMemStorage::new();
                    s.write_vault(&storage.read_vault().unwrap()).unwrap();
                    let v = Vault::open("bench-pass", &s, &test_params()).unwrap();
                    (v, s)
                },
                |(mut vault, storage)| {
                    let _ = black_box(vault.write_to_storage(&storage));
                },
            );
        });
    }

    group.finish();
}

fn bench_change_passphrase(c: &mut Criterion) {
    let mut group = c.benchmark_group("change_passphrase");
    group.sample_size(10);

    for count in [10, 50] {
        group.bench_function(format!("vault_with_{count}_entries"), |b| {
            let (_, ref_storage) = make_vault_with_entries(count);
            b.iter_with_setup(
                || {
                    let s = InMemStorage::new();
                    s.write_vault(&ref_storage.read_vault().unwrap()).unwrap();
                    Vault::open("bench-pass", &s, &test_params())
                        .map(|v| (v, s))
                        .unwrap()
                },
                |(mut vault, storage)| {
                    let _ =
                        black_box(vault.change_passphrase("new-pass", &storage, &test_params()));
                },
            );
        });
    }

    group.finish();
}

fn bench_search_by_name(c: &mut Criterion) {
    let mut group = c.benchmark_group("search_by_name");

    for count in [10, 100, 500] {
        group.bench_function(format!("vault_with_{count}_entries"), |b| {
            let (vault, _storage) = make_vault_with_entries(count);
            b.iter(|| {
                let _ = black_box(search_by_name(&vault, "entry-5"));
            });
        });
    }

    group.finish();
}

fn bench_search_by_tag(c: &mut Criterion) {
    let mut group = c.benchmark_group("search_by_tag");

    for count in [10, 100, 500] {
        group.bench_function(format!("vault_with_{count}_entries"), |b| {
            let (vault, _storage) = make_vault_with_entries(count);
            b.iter(|| {
                let _ = black_box(search_by_tag(&vault, "test"));
            });
        });
    }

    group.finish();
}

fn bench_encrypt_decrypt_round_trip(c: &mut Criterion) {
    use padlock_core::vault::entries::{decrypt_entry, encrypt_entry};

    let mut group = c.benchmark_group("encrypt_decrypt");

    let storage = InMemStorage::new();
    let vault = Vault::init("bench-pass", &storage, &test_params()).unwrap();
    let kek = vault.kek().unwrap();

    let plaintext = b"username=admin\npassword=secret123\nurl=https://example.com";
    let encrypted = encrypt_entry(plaintext, kek).unwrap();

    group.bench_function("encrypt_entry", |b| {
        b.iter(|| {
            let _ = black_box(encrypt_entry(black_box(plaintext), kek));
        });
    });

    group.bench_function("decrypt_entry", |b| {
        b.iter(|| {
            let _ = black_box(decrypt_entry(black_box(&encrypted), kek));
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_create_entry_in_vault,
    bench_vault_write_to_storage,
    bench_change_passphrase,
    bench_search_by_name,
    bench_search_by_tag,
    bench_encrypt_decrypt_round_trip,
);
criterion_main!(benches);
