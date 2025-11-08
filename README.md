# DBcake — C++ single-file append-only key/value DB

> Compact, educational, single-file C++ key/value database with:
>
> * centralized append-only `.dbce` file (fast appends)
> * decentralized per-key directory store (one file per key)
> * selectable on-disk formats: `binary`, `bits01`, `dec`, `hex`
> * simple `pw` modes: `low` | `normal` | `high` (encryption enabled in `high`)
> * CLI and embeddable `dbcake::DB` API

**Important:** This project is an educational/demo implementation. The fallback encryption is **not** cryptographically secure. Compile with OpenSSL (see below) to enable AES-GCM. Review security before using for real secrets.

---

## Table of contents

* [Quick start](#quick-start)
* [Build & install](#build--install)
* [CLI usage](#cli-usage)
* [API reference (summary)](#api-reference-summary)
* [Examples](#examples)
* [Formats, locking and files](#formats-locking-and-files)
* [Security & encryption](#security--encryption)
* [Limitations and roadmap](#limitations-and-roadmap)
* [Backup, recovery & troubleshooting](#backup-recovery--troubleshooting)
* [Contributing & license](#contributing--license)

---

## Quick start

Save the single-file `dbcake.cpp` into your project, compile, and use it as a CLI tool or link it into your program.

Build (no crypto / demo):

```bash
g++ -std=c++17 dbcake.cpp -o dbcake
```

Build (with OpenSSL for AES-GCM):

```bash
g++ -std=c++17 -DUSE_OPENSSL dbcake.cpp -o dbcake -lcrypto -lssl
```

Minimal CLI example:

```bash
./dbcake create mydata.dbce
./dbcake set mydata.dbce username armin
./dbcake get mydata.dbce username
```

---

## CLI usage

```
Usage:
  dbcake create [path] [--format binary|bits01|dec|hex]
  dbcake set [path] key value
  dbcake get [path] key
  dbcake delete [path] key
  dbcake keys [path]
  dbcake preview [path]
  dbcake compact [path]
  dbcake title [path]
  dbcake pw [path] low|normal|high [--passphrase secret]
```

Examples:

```bash
# create DB file
./dbcake create data.dbce --format binary

# set / get
./dbcake set data.dbce username "armin"
./dbcake get data.dbce username

# enable encryption in memory
./dbcake pw data.dbce high --passphrase "my secret"
./dbcake set data.dbce secret_key "very-secret"
```

---

## API reference (summary)

> See `dbcake.cpp` for full method signatures and implementation notes.

### `dbcake::DB` (primary class)

```cpp
namespace dbcake {
  class DB {
    DB(const std::string& path = "data.dbce",
       StoreFormat fmt = StoreFormat::Binary,
       bool centralized=true);

    void centerilized();   // centralized append-only .dbce
    void decentralized();  // per-key directory store (path + ".d")

    void set(const std::string& key, const std::string& value);
    std::optional<std::string> get(const std::string& key);
    bool delete_key(const std::string& key);
    bool contains(const std::string& key);

    std::vector<std::string> keys();
    std::vector<std::pair<std::string,std::string>> preview(size_t limit=10);

    void compact();
    std::string export_db(const std::string& dest);
    void title(const std::string& filename, StoreFormat fmt = StoreFormat::Binary);
    void set_format(StoreFormat fmt);

    void set_pw(const std::string& level);       // "low" | "normal" | "high"
    void set_passphrase(const std::string& pass);

    void close();
  };
}
```

### `StoreFormat`

```cpp
enum class StoreFormat { Binary, Bits01, Dec, Hex };
```

---

## Examples

### Embed in a C++ program

```cpp
#include "dbcake.cpp" // or compile separately and link

int main() {
    dbcake::DB db("mydata.dbce");
    db.set("username", "armin");
    auto val = db.get("username");
    if (val) std::cout << "username = " << *val << "\n";
    db.close();
    return 0;
}
```

### Enable high security (in-memory passphrase)

```bash
./dbcake pw mydata.dbce high --passphrase "s3cr3t"
./dbcake set mydata.dbce secret_key "very-secret"
```

C++:

```cpp
dbcake::DB db("mydata.dbce");
db.set_pw("high");
db.set_passphrase("s3cr3t");
db.set("token", "top-secret");
```

### Switch to decentralized store

```cpp
dbcake::DB db("mydata.dbce", dbcake::StoreFormat::Binary, true);
db.decentralized(); // now uses "mydata.dbce.d" directory
db.set("k","v");
```

---

## Formats, locking and files

* **Centralized** (`BinaryKV`): `.dbce` append-only file. Each record stored as `[u32 length][payload]`. Payloads are plain (`'P'`) or encrypted (`'E'`).
* **Decentralized** (`DecentralizedKV`): directory `path + ".d"` with one file per key (hashed filenames).
* **Store formats**:

  * `binary` — raw bytes
  * `bits01` — ASCII `'0'`/`'1'` representation (big expansion)
  * `dec` — each byte as three decimal digits (`000`–`255`)
  * `hex` — hex encoding
* **Locking**:

  * POSIX: `flock`.
  * Fallback: lockfile advisory approach on non-POSIX systems.
* **Index**: in-memory index built on startup by scanning backend files. Use `compact()` to rebuild a compact file and speed future startups.

---

## Security & encryption

* **Modes**:

  * `low` / `normal`: no encryption for stored records.
  * `high`: encryption enabled. Key material derived from passphrase or generated keyfile.
* **Crypto options**:

  * **Recommended**: compile with OpenSSL (`-DUSE_OPENSSL -lssl -lcrypto`) to enable AES-GCM encryption.
  * **Fallback**: an insecure XOR/PRNG stream cipher is used when OpenSSL is not available. **Do not use fallback for real secrets.**
* **KDF**:

  * Demo uses a simple derivation. For production, use PBKDF2/Argon2 with per-DB salt.
* **Key rotation**:

  * The code includes places to implement key rotation. Rotation should re-encrypt all payloads atomically; the demo includes a `compact()` function that can be used to rewrite records.

**Security checklist**

1. Compile with OpenSSL for AES-GCM support.
2. Use a strong passphrase and implement PBKDF2/Argon2 if modifying the code.
3. Keep backups of keyfiles/passphrases; losing key material will render encrypted data unrecoverable.

---

## Limitations and roadmap

This port is intentionally compact and educational. Known limitations:

* **Not an RDBMS** — no SQL, joins, foreign keys, constraints. This is key/value storage.
* **No full ACID transactional layer** — append-only and per-operation locking provide some atomicity; multi-operation transactions are not implemented.
* **Indexing & performance** — index is memory-resident and built by scanning. For large datasets, add an on-disk index or memory-mapped index.
* **Concurrency** — basic file locking is provided; heavy concurrent multi-writer workloads may need additional coordination.
* **Migrations / schema management** — not included (Flask-Migrate equivalent not applicable).

Possible improvements:

* Implement PBKDF2 + AES-GCM fully (OpenSSL path).
* On-disk index / memmap for faster startup.
* Transaction layer (commit/rollback).
* Better key rotation workflow.
* Unit tests and CMake build.

---

## Backup, recovery & troubleshooting

**Backup**

* Centralized: copy the `.dbce` file while DB is closed, or use `export_db()` while locking is engaged.
* Decentralized: copy the `.d` directory.

**Recovery**

* If `.dbce` is corrupted, scan the file and extract valid records (append-only format helps).
* `compact()` writes a `.compact.tmp` then atomically replaces the file; a `.bak` may exist on failure.

**Common errors**

* File open errors → check file permissions and path.
* Lock timeouts → check for stale lockfiles or processes holding locks.
* Decryption failures → ensure correct `pw` level and passphrase.

---

## Contributing

Contributions welcome. Typical tasks:

* Add OpenSSL PBKDF2 + AES-GCM KDF improvements.
* Add unit tests (Catch2 / GoogleTest).
* Add CMake configuration and packaging.
* Implement on-disk indexes and transaction layer.

When contributing, include tests and documentation for behavior changes.

---

## License

**Apache-2 License** read License please.

---

## FAQ (short)

**Q:** Is DBcake a replacement for SQLite/Postgres?
**A:** No. DBcake is a small educational key/value store. For production relational workloads use SQLite/Postgres.

**Q:** Can I store binary blobs?
**A:** Yes — the internal record format stores raw bytes. The provided `DB::set` accepts strings in the demo; extend the API to accept `Bytes` for arbitrary binary payloads.

**Q:** Is encryption on by default?
**A:** No. Use `set_pw("high")` and `set_passphrase(...)` to enable encryption.
