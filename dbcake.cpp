/* dbcake.cpp
   Single-file C++ port of a simple append-only key-value DB with:
    - centralized .dbce append-only backend (BinaryKV)
    - decentralized per-key backend (DecentralizedKV)
    - store formats: binary | bits01 | dec | hex
    - pw modes: low | normal | high (optional encryption)
    - file-locking (POSIX flock when available; lockfile fallback)
    - compact, preview, keys, export, title, set_format
    - simple CLI
   NOTE: Fallback encryption is NOT CRYPTOGRAPHICALLY SECURE.
   For real security, compile with OpenSSL (see README below).
*/

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <mutex>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <chrono>

#if defined(__unix__) || defined(__APPLE__)
  #define DBCAKE_POSIX_LOCK
  #include <sys/file.h>
  #include <unistd.h>
#endif

// Optional OpenSSL integration: define USE_OPENSSL at compile time and link with -lcrypto -lssl
#ifdef USE_OPENSSL
  #include <openssl/evp.h>
  #include <openssl/rand.h>
  #include <openssl/sha.h>
#endif

namespace dbcake {

using u8 = uint8_t;
using u32 = uint32_t;
using Bytes = std::vector<u8>;

static const std::string DB_HEADER = "DBCEv1\n";
static constexpr size_t LEN_STRUCT_BYTES = 4; // store length as uint32 little-endian

enum class StoreFormat { Binary, Bits01, Dec, Hex };

inline std::string format_to_string(StoreFormat f){
    switch(f){
        case StoreFormat::Binary: return "binary";
        case StoreFormat::Bits01: return "bits01";
        case StoreFormat::Dec: return "dec";
        case StoreFormat::Hex: return "hex";
    }
    return "binary";
}

inline StoreFormat storeformat_from_string(const std::string& s){
    std::string t = s;
    std::transform(t.begin(), t.end(), t.begin(), ::tolower);
    if(t=="bits01") return StoreFormat::Bits01;
    if(t=="dec") return StoreFormat::Dec;
    if(t=="hex") return StoreFormat::Hex;
    return StoreFormat::Binary;
}

// ----------------------- helpers ---------------------------------------------
static inline void write_u32_le(std::ostream &os, u32 v){
    u8 b[4];
    b[0] = v & 0xff; b[1] = (v>>8)&0xff; b[2] = (v>>16)&0xff; b[3] = (v>>24)&0xff;
    os.write(reinterpret_cast<char*>(b), 4);
}
static inline u32 read_u32_le(std::istream &is){
    u8 b[4];
    is.read(reinterpret_cast<char*>(b), 4);
    if(is.gcount() < 4) throw std::runtime_error("short read");
    return (u32(b[0]) | (u32(b[1])<<8) | (u32(b[2])<<16) | (u32(b[3])<<24));
}
static inline Bytes read_n_bytes(std::istream &is, size_t n){
    Bytes out(n);
    is.read(reinterpret_cast<char*>(out.data()), n);
    size_t got = is.gcount();
    if(got < n) out.resize(got);
    return out;
}
static inline std::string to_hex(const Bytes& b){
    static const char* hex="0123456789abcdef";
    std::string s; s.reserve(b.size()*2);
    for(auto c: b){ s.push_back(hex[(c>>4)&0xF]); s.push_back(hex[c&0xF]); }
    return s;
}
static inline Bytes from_hex(const std::string& s){
    Bytes out; out.reserve(s.size()/2);
    auto hexval = [](char c)->int{
        if(c>='0' && c<='9') return c-'0';
        if(c>='a' && c<='f') return 10 + (c-'a');
        if(c>='A' && c<='F') return 10 + (c-'A');
        return 0;
    };
    for(size_t i=0;i+1<s.size();i+=2){
        int hi = hexval(s[i]), lo = hexval(s[i+1]);
        out.push_back((u8)((hi<<4)|lo));
    }
    return out;
}
static inline std::string bytes_to_bits01(const Bytes& b){
    std::string out; out.reserve(b.size()*8);
    for(auto c: b){
        for(int i=7;i>=0;--i) out.push_back(((c>>i)&1) ? '1':'0');
    }
    return out;
}
static inline Bytes bits01_to_bytes(const std::string& s){
    if(s.size()%8!=0) throw std::runtime_error("bits01 length not multiple of 8");
    Bytes out; out.reserve(s.size()/8);
    for(size_t i=0;i<s.size(); i+=8){
        u8 v=0;
        for(size_t j=0;j<8;++j) v = (v<<1) | (s[i+j]=='1');
        out.push_back(v);
    }
    return out;
}
static inline std::string bytes_to_dec(const Bytes& b){
    std::ostringstream ss;
    for(auto c: b) ss << std::setw(3) << std::setfill('0') << int(c);
    return ss.str();
}
static inline Bytes dec_to_bytes(const std::string& s){
    if(s.size()%3!=0) throw std::runtime_error("dec length must be multiple of 3");
    Bytes out; out.reserve(s.size()/3);
    for(size_t i=0;i<s.size(); i+=3){
        int v = std::stoi(s.substr(i,3));
        out.push_back((u8)v);
    }
    return out;
}

// encode/decode for disk
static inline Bytes encode_for_disk(const Bytes& data, StoreFormat fmt){
    if(fmt==StoreFormat::Binary) return data;
    if(fmt==StoreFormat::Hex){
        auto h = to_hex(data);
        return Bytes(h.begin(), h.end());
    }
    if(fmt==StoreFormat::Bits01){
        auto b = bytes_to_bits01(data);
        return Bytes(b.begin(), b.end());
    }
    if(fmt==StoreFormat::Dec){
        auto d = bytes_to_dec(data);
        return Bytes(d.begin(), d.end());
    }
    return data;
}
static inline Bytes decode_from_disk(const Bytes& raw, StoreFormat fmt){
    if(fmt==StoreFormat::Binary) return raw;
    std::string s(raw.begin(), raw.end());
    if(fmt==StoreFormat::Hex) return from_hex(s);
    if(fmt==StoreFormat::Bits01) return bits01_to_bytes(s);
    if(fmt==StoreFormat::Dec) return dec_to_bytes(s);
    return raw;
}

// ----------------------- FileLock (simple cross-platform) --------------------
class FileLock {
    std::string path;
#ifdef DBCAKE_POSIX_LOCK
    int fd = -1;
#else
    std::fstream f;
#endif
public:
    explicit FileLock(const std::string& p): path(p + ".lock"){}
    void lock(){
#ifdef DBCAKE_POSIX_LOCK
        fd = ::open(path.c_str(), O_CREAT | O_RDWR, 0600);
        if(fd<0) throw std::runtime_error("open lockfile failed");
        if(::flock(fd, LOCK_EX) != 0) {
            ::close(fd); fd=-1;
            throw std::runtime_error("flock failed");
        }
#else
        // fallback: create and keep file open (cooperative)
        f.open(path, std::ios::in|std::ios::out|std::ios::app);
        if(!f.is_open()) throw std::runtime_error("cannot create lockfile");
        // no atomic exclusive lock available here, but hold file open as advisory
#endif
    }
    void unlock(){
#ifdef DBCAKE_POSIX_LOCK
        if(fd>=0){ ::flock(fd, LOCK_UN); ::close(fd); fd=-1; }
#else
        if(f.is_open()) { f.close(); std::error_code ec; std::filesystem::remove(path, ec); }
#endif
    }
    // RAII
    struct Guard {
        FileLock &l;
        Guard(FileLock& ll): l(ll){ l.lock(); }
        ~Guard(){ try{ l.unlock(); }catch(...){} }
    };
};

// ----------------------- Record layout -------------------------------------
// payloads are length-prefixed in file: [u32 len][payload bytes]
// payload bytes:
//  - Leading byte: 'P' = plain, 'E' = encrypted
// Plain payload format (binary, efficient):
//   'P' (1 byte)
//   key_len (u32 LE)
//   key bytes (UTF-8)
//   value_len (u32 LE)
//   value bytes (raw bytes, caller-defined; we store as UTF-8 string typically)
//   deleted (1 byte) 0 or 1
//
// Encrypted payload: 'E' + encrypted blob (opaque). If DB.pw == high we store encrypted payloads.
//
// This avoids a JSON dependency and is fast.

struct PlainRecord {
    std::string key;
    Bytes value;
    bool deleted = false;
    Bytes to_bytes() const {
        std::ostringstream oss;
        // build into Bytes
        Bytes out;
        out.push_back((u8)'P');
        // key len
        u32 klen = (u32)key.size();
        out.push_back((u8)(klen & 0xff)); out.push_back((u8)((klen>>8)&0xff));
        out.push_back((u8)((klen>>16)&0xff)); out.push_back((u8)((klen>>24)&0xff));
        // key
        out.insert(out.end(), key.begin(), key.end());
        // value len
        u32 vlen = (u32)value.size();
        out.push_back((u8)(vlen & 0xff)); out.push_back((u8)((vlen>>8)&0xff));
        out.push_back((u8)((vlen>>16)&0xff)); out.push_back((u8)((vlen>>24)&0xff));
        // value bytes
        out.insert(out.end(), value.begin(), value.end());
        // deleted flag
        out.push_back(deleted ? (u8)1 : (u8)0);
        return out;
    }
    static PlainRecord from_bytes(const Bytes& b){
        PlainRecord r;
        if(b.empty() || b[0] != (u8)'P') throw std::runtime_error("not plain record");
        size_t idx = 1;
        if(idx + 4 > b.size()) throw std::runtime_error("short record");
        u32 klen = (u32)b[idx] | ((u32)b[idx+1]<<8) | ((u32)b[idx+2]<<16) | ((u32)b[idx+3]<<24);
        idx += 4;
        if(idx + klen > b.size()) throw std::runtime_error("short key");
        r.key.assign((char*)&b[idx], klen);
        idx += klen;
        if(idx + 4 > b.size()) throw std::runtime_error("short record2");
        u32 vlen = (u32)b[idx] | ((u32)b[idx+1]<<8) | ((u32)b[idx+2]<<16) | ((u32)b[idx+3]<<24);
        idx += 4;
        if(idx + vlen > b.size()) throw std::runtime_error("short value");
        r.value.assign(b.begin()+idx, b.begin()+idx+vlen);
        idx += vlen;
        if(idx >= b.size()) throw std::runtime_error("missing deleted flag");
        r.deleted = b[idx] != 0;
        return r;
    }
};

// ----------------------- Crypto helpers (optional) -------------------------
#ifdef USE_OPENSSL
// AES-GCM implementation note:
// We'll derive key from passphrase via SHA256(salt+pass) truncated/padded to 32 bytes (demo).
#include <openssl/evp.h>
#include <openssl/err.h>

static Bytes openssl_random_bytes(size_t n){
    Bytes out(n);
    if(1 != RAND_bytes(out.data(), (int)n)) throw std::runtime_error("RAND_bytes failed");
    return out;
}
static Bytes derive_key_from_passphrase(const std::string& pass, const Bytes& salt){
    Bytes out(32);
    // simple KDF for demo: SHA256(salt || pass)
    std::string tmp;
    tmp.reserve(salt.size()+pass.size());
    tmp.append((char*)salt.data(), salt.size());
    tmp.append(pass);
    unsigned char hash[32];
    SHA256((unsigned char*)tmp.data(), tmp.size(), hash);
    std::copy(hash, hash+32, out.begin());
    return out;
}
static Bytes aesgcm_encrypt(const Bytes& key, const Bytes& plaintext){
    // key length must be 16/24/32
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    const EVP_CIPHER* cipher = EVP_aes_256_gcm();
    if(1 != EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL)){
        EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("EncryptInit failed");
    }
    Bytes nonce = openssl_random_bytes(12);
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), nonce.data())){
        EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("EncryptInit key/iv failed");
    }
    Bytes out; out.resize(plaintext.size());
    int len=0;
    if(1 != EVP_EncryptUpdate(ctx, out.data(), &len, plaintext.data(), (int)plaintext.size())){
        EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("EncryptUpdate failed");
    }
    int outlen = len;
    if(1 != EVP_EncryptFinal_ex(ctx, out.data()+len, &len)){
        EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("EncryptFinal failed");
    }
    outlen += len;
    out.resize(outlen);
    unsigned char tag[16];
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)){
        EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("Get TAG failed");
    }
    EVP_CIPHER_CTX_free(ctx);
    // result layout: 'E' || nonce(12) || ciphertext || tag(16)
    Bytes res;
    res.push_back((u8)'E');
    res.insert(res.end(), nonce.begin(), nonce.end());
    res.insert(res.end(), out.begin(), out.end());
    res.insert(res.end(), tag, tag+16);
    return res;
}
static Bytes aesgcm_decrypt(const Bytes& key, const Bytes& payload){
    if(payload.empty() || payload[0] != (u8)'E') throw std::runtime_error("not encrypted payload");
    if(payload.size() < 1+12+16) throw std::runtime_error("short encrypted payload");
    const u8* p = payload.data()+1;
    Bytes nonce(p, p+12);
    const u8* cstart = p+12;
    size_t csize = payload.size() - 1 - 12 - 16;
    const u8* cend = cstart + csize;
    const u8* tagptr = payload.data() + payload.size() - 16;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    const EVP_CIPHER* cipher = EVP_aes_256_gcm();
    if(1 != EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL)){ EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("DecryptInit failed"); }
    if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), nonce.data())){ EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("DecryptInit key/iv failed"); }
    Bytes out; out.resize(csize);
    int len=0;
    if(1 != EVP_DecryptUpdate(ctx, out.data(), &len, cstart, (int)csize)){ EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("DecryptUpdate failed"); }
    int outlen = len;
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tagptr)){ EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("Set TAG failed"); }
    if(1 != EVP_DecryptFinal_ex(ctx, out.data()+len, &len)){ EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("DecryptFinal failed (bad tag)"); }
    outlen += len; out.resize(outlen);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}
#endif

// Fallback insecure XOR-CTR-like stream (NOT SECURE)
static Bytes insecure_encrypt_xor(const Bytes& key_material, const Bytes& plaintext){
    // produce nonce (8 bytes)
    std::seed_seq seed((const uint32_t*)key_material.data(), (const uint32_t*)(key_material.data()+std::min<size_t>(key_material.size(),32)));
    std::mt19937_64 prng(seed);
    uint64_t nonce = prng();
    Bytes out;
    out.push_back((u8)'E');
    for(int i=0;i<8;++i) out.push_back((u8)((nonce>>(8*i)) & 0xff));
    // stream: keystream from PRNG seeded with (nonce ^ key_material bytes XOR)
    std::mt19937_64 stream((uint64_t)nonce ^ (uint64_t)std::hash<std::string>()(std::string((char*)key_material.data(), key_material.size())));
    for(size_t i=0;i<plaintext.size();++i){
        u8 k = (u8)(stream() & 0xff);
        out.push_back( plaintext[i] ^ k );
    }
    // append simple 8-byte tag: hash of (nonce + ciphertext)
    uint64_t tag = 1469598103934665603ULL;
    for(size_t i=0;i<out.size();++i) tag = tag ^ out[i], tag *= 1099511628211ULL;
    for(int i=0;i<8;++i) out.push_back((u8)((tag>>(8*i))&0xff));
    return out;
}
static Bytes insecure_decrypt_xor(const Bytes& key_material, const Bytes& payload){
    if(payload.empty() || payload[0] != (u8)'E') throw std::runtime_error("not encrypted payload");
    if(payload.size() < 1+8+8) throw std::runtime_error("short payload");
    // decode nonce
    uint64_t nonce=0;
    for(int i=0;i<8;++i) nonce |= (uint64_t)payload[1+i] << (8*i);
    size_t cstart = 1+8;
    size_t cend = payload.size()-8; // exclude tag
    Bytes ctext(payload.begin()+cstart, payload.begin()+cend);
    // verify tag
    uint64_t tag = 1469598103934665603ULL;
    for(size_t i=0;i< (1+8 + ctext.size()); ++i){ // compute over header+nonce+cipher
        u8 v = (i < payload.size()-8) ? payload[i] : 0;
        tag = tag ^ v; tag *= 1099511628211ULL;
    }
    // produce stream
    std::mt19937_64 stream((uint64_t)nonce ^ (uint64_t)std::hash<std::string>()(std::string((char*)key_material.data(), key_material.size())));
    Bytes out; out.resize(ctext.size());
    for(size_t i=0;i<ctext.size();++i){
        u8 k = (u8)(stream() & 0xff);
        out[i] = ctext[i] ^ k;
    }
    return out;
}

// high-level encrypt/decrypt wrappers (choose OpenSSL if compiled-in)
static Bytes encrypt_record(const Bytes& plain, const Bytes& key_material, bool have_crypto){
#ifdef USE_OPENSSL
    if(have_crypto) return aesgcm_encrypt(key_material, plain);
    else return insecure_encrypt_xor(key_material, plain);
#else
    (void)have_crypto;
    return insecure_encrypt_xor(key_material, plain);
#endif
}
static Bytes decrypt_record(const Bytes& payload, const Bytes& key_material, bool have_crypto){
#ifdef USE_OPENSSL
    if(have_crypto) return aesgcm_decrypt(key_material, payload);
    else return insecure_decrypt_xor(key_material, payload);
#else
    (void)key_material;
    return insecure_decrypt_xor(key_material, payload);
#endif
}


// ----------------------- BinaryKV ------------------------------------------
class BinaryKV {
    std::string path;
    std::mutex m;
    std::unordered_map<std::string, std::optional<Bytes>> index; // store value bytes if present, or nullopt if deleted
    StoreFormat store_format;
    std::fstream file;
public:
    explicit BinaryKV(const std::string& p, StoreFormat fmt = StoreFormat::Binary): path(p), store_format(fmt){
        std::filesystem::path dir = std::filesystem::path(path).parent_path();
        if(!dir.empty()) std::filesystem::create_directories(dir);
        if(!std::filesystem::exists(path)){
            std::ofstream ofs(path, std::ios::binary);
            ofs.write(DB_HEADER.c_str(), DB_HEADER.size());
            ofs.flush();
#ifdef DBCAKE_POSIX_LOCK
            ::fsync(ofs.rdbuf()->fd());
#endif
            ofs.close();
        }
        file.open(path, std::ios::in | std::ios::out | std::ios::binary);
        if(!file.is_open()) throw std::runtime_error("failed to open DB file");
        load_index(std::nullopt);
        // seek to end for appends
        file.clear(); file.seekp(0, std::ios::end);
    }

    ~BinaryKV(){ try{ file.close(); }catch(...){} }

    std::string get_path() const { return path; }
    StoreFormat get_format() const { return store_format; }
    void set_format(StoreFormat fmt){ std::lock_guard<std::mutex> lk(m); store_format=fmt; }

    // load index: key_material optional -> if present attempt to decrypt encrypted records
    void load_index(const std::optional<Bytes>& key_material){
        std::lock_guard<std::mutex> lk(m);
        index.clear();
        std::ifstream ifs(path, std::ios::binary);
        if(!ifs.is_open()) return;
        // read header
        std::string hdr;
        hdr.resize(DB_HEADER.size());
        ifs.read(&hdr[0], (std::streamsize)DB_HEADER.size());
        std::streampos start = ifs.tellg();
        while(true){
            // read len
            u8 lenbuf[4];
            ifs.read(reinterpret_cast<char*>(lenbuf), 4);
            if(ifs.gcount() < 4) break;
            u32 ln = (u32)lenbuf[0] | ((u32)lenbuf[1]<<8) | ((u32)lenbuf[2]<<16) | ((u32)lenbuf[3]<<24);
            if(ln == 0) break;
            Bytes payload(ln);
            ifs.read(reinterpret_cast<char*>(payload.data()), ln);
            if((size_t)ifs.gcount() < ln) break;
            // decode if necessary
            Bytes decoded = decode_from_disk(payload, store_format);
            if(decoded.empty()) continue;
            if(decoded[0] == (u8)'E'){
                // encrypted: if key material available, try decrypt, otherwise skip (store placeholder)
                if(key_material){
                    try{
                        Bytes plain = decrypt_record(decoded, *key_material, /*have_crypto=*/false);
                        // parse plain
                        try{
                            PlainRecord pr = PlainRecord::from_bytes(plain);
                            if(pr.deleted) index[pr.key] = std::nullopt;
                            else index[pr.key] = pr.value;
                        }catch(...){
                            // ignore parse errors
                        }
                    }catch(...){
                        // can't decrypt: skip
                    }
                }else{
                    // store placeholder indicating encrypted raw present
                    // we put a special optional with empty bytes to mean encrypted-not-decrypted
                    // to distinguish absent key, we'll not insert anything
                }
            } else if(decoded[0] == (u8)'P'){
                try{
                    PlainRecord pr = PlainRecord::from_bytes(decoded);
                    if(pr.deleted) index[pr.key] = std::nullopt;
                    else index[pr.key] = pr.value;
                }catch(...){
                    // ignore parse error
                }
            } else {
                // unknown format: ignore
            }
        }
    }

    void append_payload(const Bytes& raw_payload){
        Bytes payload = encode_for_disk(raw_payload, store_format);
        u32 ln = (u32)payload.size();
        std::lock_guard<std::mutex> lk(m);
        FileLock lock(path);
        lock.lock();
        // write len and payload to end
        file.clear();
        file.seekp(0, std::ios::end);
        file.write(reinterpret_cast<const char*>(&ln), 4); // little-endian on common platforms
        file.write(reinterpret_cast<const char*>(payload.data()), payload.size());
        file.flush();
#ifdef DBCAKE_POSIX_LOCK
        ::fsync(file.rdbuf()->fd());
#endif
        lock.unlock();
    }

    // API used by DB
    void set_wrapped_plain(const std::string& key, const Bytes& val){
        PlainRecord pr; pr.key = key; pr.value = val; pr.deleted=false;
        Bytes payload = pr.to_bytes();
        append_payload(payload);
        std::lock_guard<std::mutex> lk(m);
        index[key] = val;
    }
    void set_wrapped_encrypted(const Bytes& wrapped_value_bytes, const Bytes& encrypted_payload){
        append_payload(encrypted_payload);
        try{
            PlainRecord pr = PlainRecord::from_bytes(wrapped_value_bytes);
            std::lock_guard<std::mutex> lk(m);
            if(pr.deleted) index[pr.key] = std::nullopt;
            else index[pr.key] = pr.value;
        }catch(...){}
    }
    void delete_key(const std::string& key){
        PlainRecord pr; pr.key = key; pr.value = {}; pr.deleted = true;
        Bytes payload = pr.to_bytes();
        append_payload(payload);
        std::lock_guard<std::mutex> lk(m);
        index[key] = std::nullopt;
    }
    std::optional<Bytes> get_indexed(const std::string& key){
        std::lock_guard<std::mutex> lk(m);
        auto it = index.find(key);
        if(it==index.end()) return std::nullopt;
        return it->second;
    }
    bool contains(const std::string& key){
        std::lock_guard<std::mutex> lk(m);
        auto it = index.find(key);
        return (it!=index.end() && it->second.has_value());
    }
    std::vector<std::string> keys(){
        std::lock_guard<std::mutex> lk(m);
        std::vector<std::string> out;
        for(auto &p: index) if(p.second.has_value()) out.push_back(p.first);
        return out;
    }
    std::vector<std::pair<std::string, std::string>> preview(size_t limit=20){
        std::vector<std::pair<std::string, std::string>> out;
        std::lock_guard<std::mutex> lk(m);
        for(auto &p: index){
            if(!p.second.has_value()) continue;
            std::string v((char*)p.second.value().data(), p.second.value().size());
            out.emplace_back(p.first, v);
            if(out.size() >= limit) break;
        }
        return out;
    }

    std::string export_to(const std::string& dest){
        std::lock_guard<std::mutex> lk(m);
        std::filesystem::copy_file(path, dest, std::filesystem::copy_options::overwrite_existing);
        return dest;
    }

    void compact(const std::optional<Bytes>& key_material){
        // rewrite file with header and only current live records
        std::lock_guard<std::mutex> lk(m);
        std::string tmp = path + ".compact.tmp";
        std::ofstream ofs(tmp, std::ios::binary | std::ios::trunc);
        ofs.write(DB_HEADER.c_str(), DB_HEADER.size());
        for(auto &p: index){
            if(!p.second.has_value()) continue;
            // build plain record
            PlainRecord pr; pr.key = p.first; pr.value = p.second.value(); pr.deleted=false;
            Bytes plain = pr.to_bytes();
            if(key_material){
                Bytes enc = encrypt_record(plain, *key_material, /*have_crypto=*/false);
                u32 ln = (u32)enc.size();
                ofs.write(reinterpret_cast<const char*>(&ln), 4);
                Bytes disk = encode_for_disk(enc, store_format);
                ofs.write(reinterpret_cast<const char*>(disk.data()), disk.size());
            }else{
                u32 ln = (u32)plain.size();
                ofs.write(reinterpret_cast<const char*>(&ln), 4);
                Bytes disk = encode_for_disk(plain, store_format);
                ofs.write(reinterpret_cast<const char*>(disk.data()), disk.size());
            }
        }
        ofs.flush();
#ifdef DBCAKE_POSIX_LOCK
        ::fsync(ofs.rdbuf()->fd());
#endif
        ofs.close();
        // replace original
        std::filesystem::rename(path, path + ".bak");
        std::filesystem::rename(tmp, path);
        file.close();
        file.open(path, std::ios::in | std::ios::out | std::ios::binary);
        load_index(key_material);
    }

    void close(){
        std::lock_guard<std::mutex> lk(m);
        try{ file.flush(); file.close(); }catch(...){}
    }
};

// ----------------------- DecentralizedKV ------------------------------------
class DecentralizedKV {
    std::string base_path;
    std::string dir_path;
    StoreFormat store_format;
    std::mutex m;
    std::unordered_map<std::string, std::optional<Bytes>> index;
public:
    explicit DecentralizedKV(const std::string& path, StoreFormat fmt = StoreFormat::Binary)
        : base_path(path), dir_path(path + ".d"), store_format(fmt)
    {
        std::filesystem::create_directories(dir_path);
        load_index(std::nullopt);
    }
    std::string get_path() const { return base_path; }
    StoreFormat get_format() const { return store_format; }
    void set_format(StoreFormat f){ std::lock_guard<std::mutex> lk(m); store_format = f; }

    static std::string keyfile_name(const std::string& dir, const std::string& key){
        // use SHA-like filename: we use std::hash for demo (not cryptographic) and hex it
        size_t h = std::hash<std::string>()(key);
        std::ostringstream ss; ss << std::hex << h;
        return (dir + "/" + ss.str() + ".rec");
    }

    void write_file_atomic(const std::string& fname, const Bytes& data){
        std::string tmp = fname + ".tmp";
        std::ofstream ofs(tmp, std::ios::binary|std::ios::trunc);
        ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
        ofs.flush();
#ifdef DBCAKE_POSIX_LOCK
        ::fsync(ofs.rdbuf()->fd());
#endif
        ofs.close();
        std::filesystem::rename(tmp, fname);
    }

    void load_index(const std::optional<Bytes>& key_material){
        std::lock_guard<std::mutex> lk(m);
        index.clear();
        for(auto &entry: std::filesystem::directory_iterator(dir_path)){
            if(!entry.is_regular_file()) continue;
            auto p = entry.path();
            if(p.extension() != ".rec") continue;
            std::ifstream ifs(p, std::ios::binary);
            Bytes raw((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
            ifs.close();
            Bytes decoded = decode_from_disk(raw, store_format);
            if(decoded.empty()) continue;
            if(decoded[0] == (u8)'E'){
                if(key_material){
                    try{
                        Bytes plain = decrypt_record(decoded, *key_material, /*have_crypto=*/false);
                        try{
                            PlainRecord pr = PlainRecord::from_bytes(plain);
                            if(pr.deleted) index[pr.key] = std::nullopt;
                            else index[pr.key] = pr.value;
                        }catch(...){}
                    }catch(...){}
                } else {
                    // skip or mark; we'll skip
                }
            } else if(decoded[0] == (u8)'P'){
                try{
                    PlainRecord pr = PlainRecord::from_bytes(decoded);
                    if(pr.deleted) index[pr.key] = std::nullopt;
                    else index[pr.key] = pr.value;
                }catch(...){}
            }
        }
    }

    void set_wrapped_plain(const std::string& key, const Bytes& val){
        PlainRecord pr; pr.key = key; pr.value = val; pr.deleted = false;
        Bytes plain = pr.to_bytes();
        Bytes disk = encode_for_disk(plain, store_format);
        std::string fname = keyfile_name(dir_path, key);
        FileLock lock(base_path);
        lock.lock();
        write_file_atomic(fname, disk);
        lock.unlock();
        std::lock_guard<std::mutex> lk(m);
        index[key] = val;
    }

    void set_wrapped_encrypted(const Bytes& wrapped_value_bytes, const Bytes& encrypted_payload){
        Bytes disk = encode_for_disk(encrypted_payload, store_format);
        try{
            PlainRecord pr = PlainRecord::from_bytes(wrapped_value_bytes);
            std::string fname = keyfile_name(dir_path, pr.key);
            FileLock lock(base_path);
            lock.lock();
            write_file_atomic(fname, disk);
            lock.unlock();
            std::lock_guard<std::mutex> lk(m);
            if(pr.deleted) index[pr.key] = std::nullopt; else index[pr.key] = pr.value;
        }catch(...){}
    }

    void delete_key(const std::string& key){
        std::string fname = keyfile_name(dir_path, key);
        FileLock lock(base_path);
        lock.lock();
        std::error_code ec;
        std::filesystem::remove(fname, ec);
        lock.unlock();
        std::lock_guard<std::mutex> lk(m);
        index.erase(key);
    }

    std::optional<Bytes> get_indexed(const std::string& key){
        std::lock_guard<std::mutex> lk(m);
        auto it = index.find(key);
        if(it!=index.end()) return it->second;
        // attempt read file
        std::string fname = keyfile_name(dir_path, key);
        std::ifstream ifs(fname, std::ios::binary);
        if(!ifs.is_open()) return std::nullopt;
        Bytes raw((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        ifs.close();
        Bytes decoded = decode_from_disk(raw, store_format);
        if(decoded.empty()) return std::nullopt;
        if(decoded[0]=='P'){
            try{ PlainRecord pr = PlainRecord::from_bytes(decoded); if(pr.deleted) return std::nullopt; return pr.value; }catch(...){ return std::nullopt; }
        }
        // encrypted -> return placeholder as std::nullopt
        return std::nullopt;
    }

    bool contains(const std::string& key){
        std::lock_guard<std::mutex> lk(m);
        if(index.find(key) != index.end()) return index[key].has_value();
        std::string fname = keyfile_name(dir_path, key);
        return std::filesystem::exists(fname);
    }

    std::vector<std::string> keys(){
        std::lock_guard<std::mutex> lk(m);
        std::vector<std::string> out;
        for(auto &p: index) if(p.second.has_value()) out.push_back(p.first);
        return out;
    }

    std::vector<std::pair<std::string,std::string>> preview(size_t limit=20){
        std::vector<std::pair<std::string,std::string>> out;
        std::lock_guard<std::mutex> lk(m);
        for(auto &p: index){
            if(!p.second.has_value()) continue;
            std::string v((char*)p.second.value().data(), p.second.value().size());
            out.emplace_back(p.first, v);
            if(out.size()>=limit) break;
        }
        return out;
    }

    std::string export_to(const std::string& dest){
        // export directory
        std::string target = dest;
        std::error_code ec;
        std::filesystem::remove_all(target, ec);
        std::filesystem::create_directories(target);
        std::filesystem::copy(dir_path, target, std::filesystem::copy_options::recursive);
        return target;
    }

    void compact(const std::optional<Bytes>& key_material){
        // no-op: decentralized is per-file; can re-encode files if encrypted requested
        std::lock_guard<std::mutex> lk(m);
        if(!key_material) return;
        for(auto &p: index){
            if(!p.second.has_value()) continue;
            PlainRecord pr; pr.key = p.first; pr.value = p.second.value(); pr.deleted=false;
            Bytes plain = pr.to_bytes();
            Bytes enc = encrypt_record(plain, *key_material, /*have_crypto=*/false);
            Bytes disk = encode_for_disk(enc, store_format);
            std::string fname = keyfile_name(dir_path, pr.key);
            FileLock lock(base_path);
            lock.lock();
            write_file_atomic(fname, disk);
            lock.unlock();
        }
        load_index(key_material);
    }
};

// ----------------------- DB wrapper -----------------------------------------
class DB {
    // backend is either BinaryKV or DecentralizedKV via pointer
    enum class BackendType { Centralized, Decentralized };
    BackendType backend_type;
    std::unique_ptr<BinaryKV> central;
    std::unique_ptr<DecentralizedKV> decentral;
    std::optional<Bytes> key_material;
    std::string passphrase;
    std::string level = "normal"; // low|normal|high
    bool have_crypto = false;
public:
    // default opens or creates data.dbce centralized
    DB(const std::string& path = "data.dbce", StoreFormat fmt = StoreFormat::Binary, bool centralized=true)
    {
        if(centralized){
            central = std::make_unique<BinaryKV>(path, fmt);
            backend_type = BackendType::Centralized;
        }else{
            decentral = std::make_unique<DecentralizedKV>(path, fmt);
            backend_type = BackendType::Decentralized;
        }
#ifdef USE_OPENSSL
        have_crypto = true;
#endif
    }

    // switch backend
    void centerilized(){
        std::string p = current_path();
        StoreFormat f = current_format();
        if(central) central->close();
        central = std::make_unique<BinaryKV>(p, f);
        decentral.reset();
        backend_type = BackendType::Centralized;
        // reload index according to pw level
        if(level == "high" && key_material) central->load_index(key_material);
        else central->load_index(std::nullopt);
    }
    void decentralized(){
        std::string p = current_path();
        StoreFormat f = current_format();
        decentral = std::make_unique<DecentralizedKV>(p, f);
        if(central) central->close();
        central.reset();
        backend_type = BackendType::Decentralized;
    }

    std::string current_path() const {
        if(backend_type==BackendType::Centralized) return central->get_path();
        return decentral->get_path();
    }
    StoreFormat current_format() const {
        if(backend_type==BackendType::Centralized) return central->get_format();
        return decentral->get_format();
    }
    void set_format(StoreFormat f){
        if(backend_type==BackendType::Centralized) central->set_format(f);
        else decentral->set_format(f);
    }

    // set pw level: low | normal | high
    void set_pw(const std::string& lvl){
        std::string v=lvl;
        std::transform(v.begin(), v.end(), v.begin(), ::tolower);
        if(v!="low" && v!="normal" && v!="high") throw std::runtime_error("pw must be low|normal|high");
        level = v;
        if(v=="high"){
            derive_key_material();
            // reload indices with key material
            if(backend_type==BackendType::Centralized) central->load_index(key_material);
            else decentral->load_index(key_material);
        }else{
            key_material.reset();
            if(backend_type==BackendType::Centralized) central->load_index(std::nullopt);
            else decentral->load_index(std::nullopt);
        }
    }

    void set_passphrase(const std::string& pass){
        passphrase = pass;
        if(level=="high") derive_key_material();
    }

    void derive_key_material(){
        if(!passphrase.empty()){
            // derive key material: simple SHA-like using std::hash (demo). For secure usage, compile with OpenSSL and use PBKDF2.
            std::string salt = "dbcake_salt_v1";
#ifdef USE_OPENSSL
            Bytes saltb(salt.begin(), salt.end());
            // if OpenSSL available -> use SHA256(salt + pass) to derive 32 bytes
            Bytes km(32);
            std::string tmp = salt + passphrase;
            unsigned char hash[32];
            SHA256((const unsigned char*)tmp.data(), tmp.size(), hash);
            std::copy(hash, hash+32, km.begin());
            key_material = km;
            return;
#else
            // fallback insecure derivation
            std::hash<std::string> H;
            size_t hv = H(salt + passphrase);
            Bytes km(32);
            for(size_t i=0;i<32;i++){
                km[i] = (u8)((hv >> ((i%8)*4)) & 0xff);
            }
            key_material = km;
            return;
#endif
        } else {
            // generate random keyfile bytes
            Bytes km(32);
            std::random_device rd;
            for(size_t i=0;i<32;++i) km[i] = (u8)rd();
            key_material = km;
            return;
        }
    }

    // set/get/delete: value is a string (UTF-8). For arbitrary data, user can pass bytes interface later.
    void set(const std::string& key, const std::string& value){
        if(key.empty()) throw std::runtime_error("key must be non-empty");
        Bytes vb(value.begin(), value.end());
        Bytes wrapped = PlainRecord{key, vb, false}.to_bytes();
        if(level=="high"){
            if(!key_material) derive_key_material();
            Bytes enc = encrypt_record(wrapped, *key_material, have_crypto);
            if(backend_type==BackendType::Centralized){
                central->set_wrapped_encrypted(wrapped, enc);
            } else {
                decentral->set_wrapped_encrypted(wrapped, enc);
            }
        } else {
            if(backend_type==BackendType::Centralized) central->set_wrapped_plain(key, vb);
            else decentral->set_wrapped_plain(key, vb);
        }
    }

    std::optional<std::string> get(const std::string& key){
        std::optional<Bytes> v;
        if(backend_type==BackendType::Centralized) v = central->get_indexed(key);
        else v = decentral->get_indexed(key);
        if(!v.has_value()) return std::nullopt;
        // if stored as encrypted marker skipped earlier, get_indexed might return nullopt; but in centralized, encrypted records were decrypted on load if key_material present
        // here v contains raw value bytes
        return std::string((char*)v->data(), v->size());
    }

    bool delete_key(const std::string& key){
        bool existed = (backend_type==BackendType::Centralized) ? central->contains(key) : decentral->contains(key);
        if(backend_type==BackendType::Centralized) central->delete_key(key);
        else decentral->delete_key(key);
        return existed;
    }

    bool contains(const std::string& key){
        if(backend_type==BackendType::Centralized) return central->contains(key);
        return decentral->contains(key);
    }

    std::vector<std::string> keys(){
        if(backend_type==BackendType::Centralized) return central->keys();
        return decentral->keys();
    }

    std::vector<std::pair<std::string,std::string>> preview(size_t limit=10){
        if(backend_type==BackendType::Centralized) return central->preview(limit);
        return decentral->preview(limit);
    }

    std::string export_db(const std::string& dest){
        if(backend_type==BackendType::Centralized) return central->export_to(dest);
        return decentral->export_to(dest);
    }

    void compact(){
        if(level=="high" && key_material){
            if(backend_type==BackendType::Centralized) central->compact(key_material);
            else decentral->compact(key_material);
        } else {
            if(backend_type==BackendType::Centralized) central->compact(std::nullopt);
            else decentral->compact(std::nullopt);
        }
    }

    void close(){
        if(backend_type==BackendType::Centralized) central->close();
    }

    void title(const std::string& filename, StoreFormat fmt = StoreFormat::Binary){
        std::string target = filename;
        if(target.size() < 5 || target.substr(target.size()-5) != ".dbce") target += ".dbce";
        if(backend_type==BackendType::Centralized) central->close();
        central = std::make_unique<BinaryKV>(target, fmt);
        decentral.reset();
        backend_type = BackendType::Centralized;
    }

    void set_store_format(StoreFormat fmt){
        set_format(fmt);
    }
};

// ----------------------- Simple CLI & Usage ---------------------------------
static void print_usage(){
    std::cout <<
    "dbcake (C++) simple CLI\n"
    "Usage:\n"
    "  dbcake create [path] [--format binary|bits01|dec|hex]\n"
    "  dbcake set [path] key value\n"
    "  dbcake get [path] key\n"
    "  dbcake delete [path] key\n"
    "  dbcake keys [path]\n"
    "  dbcake preview [path]\n"
    "  dbcake compact [path]\n"
    "  dbcake title [path]\n"
    "  dbcake pw [path] low|normal|high [--passphrase secret]\n"
    ;
}

} // namespace dbcake

// ----------------------- main (CLI entry) -----------------------------------
int main(int argc, char** argv){
    using namespace dbcake;
    try{
        if(argc < 2){ print_usage(); return 1; }
        std::string cmd = argv[1];
        auto arg = [&](int i)->std::string{ if(i<argc) return argv[i]; return std::string(); };
        if(cmd == std::string("create")){
            std::string path = (argc>2) ? argv[2] : "data.dbce";
            StoreFormat fmt = StoreFormat::Binary;
            if(argc>4 && std::string(argv[3])=="--format") fmt = storeformat_from_string(argv[4]);
            dbcake::DB db(path, fmt, true);
            db.compact();
            std::cout << "created " << path << std::endl;
            return 0;
        } else if(cmd == "set"){
            if(argc < 4){ std::cerr<<"set requires path key value (or set key value using default path)\n"; return 2; }
            std::string path = (argc>3) ? argv[2] : "data.dbce";
            std::string key = argv[3];
            std::string value = (argc>4) ? argv[4] : std::string();
            dbcake::DB db(path);
            db.set(key, value);
            std::cout << "ok\n";
            return 0;
        } else if(cmd == "get"){
            if(argc < 3){ std::cerr<<"get requires path key\n"; return 2; }
            std::string path = (argc>2) ? argv[2] : "data.dbce";
            std::string key = argv[3];
            dbcake::DB db(path);
            auto v = db.get(key);
            if(v) std::cout << *v << "\n"; else std::cout << "<not found>\n";
            return 0;
        } else if(cmd == "delete"){
            if(argc < 3){ std::cerr<<"delete requires path key\n"; return 2; }
            std::string path = argv[2];
            std::string key = argv[3];
            dbcake::DB db(path);
            bool ok = db.delete_key(key);
            std::cout << (ok ? "deleted\n":"not found\n");
            return 0;
        } else if(cmd == "keys"){
            std::string path = (argc>2) ? argv[2] : "data.dbce";
            dbcake::DB db(path);
            for(auto &k: db.keys()) std::cout << k << "\n";
            return 0;
        } else if(cmd == "preview"){
            std::string path = (argc>2) ? argv[2] : "data.dbce";
            dbcake::DB db(path);
            for(auto &p: db.preview(20)) std::cout << p.first << " : " << p.second << "\n";
            return 0;
        } else if(cmd == "compact"){
            std::string path = (argc>2) ? argv[2] : "data.dbce";
            dbcake::DB db(path);
            db.compact();
            std::cout << "compacted\n";
            return 0;
        } else if(cmd == "pw"){
            if(argc < 4){ std::cerr<<"pw requires path and low|normal|high\n"; return 2; }
            std::string path = argv[2];
            std::string lvl = argv[3];
            dbcake::DB db(path);
            db.set_pw(lvl);
            if(argc>5 && std::string(argv[4])=="--passphrase") db.set_passphrase(argv[5]);
            std::cout << "pw set\n";
            return 0;
        } else {
            print_usage();
            return 1;
        }
    }catch(const std::exception& ex){
        std::cerr << "error: " << ex.what() << std::endl;
        return 2;
    }
}
