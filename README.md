# Pubky Core Mobile SDK

The Pubky Core Mobile SDK provides native bindings for iOS and Android platforms to interact with Pubky. This SDK allows you to perform operations like publishing content, retrieving data and managing authentication.

## String Contracts

These output formats are intentional and relied upon by downstream consumers
(react-native-pubky, Pubky Ring, Bitkit). Do not change them without
coordinating a migration across those apps.

- **Public keys are always bare z-base32** (52 chars, no prefix) in every
  output: `public_key` fields, the session `pubky` field, `get_homeserver`,
  and the `publish`/`publish_https` return values. The underlying
  `pubky` crate (0.16.x) renders `PublicKey::to_string()` as
  `pubky<z32>`, so all output sites must use `.z32()` instead — pubky's own
  storage URL parser rejects `pubky://pubky<z32>/...`, and downstream apps
  build `pubky://<key>/...` URLs from these values. Inputs accept either form.
- **`uri` fields** use the pkarr URI form `pk:<z32>`.
- **Response vectors** are `[error, data]` where `error` is the string
  `"true"` or `"false"`.
- **`parse_auth_url`** returns `relay`, `capabilities`, `secret`, plus
  `kind` (`"signin"` or `"signup"`; legacy `pubkyauth:///?...` URLs are
  `"signin"`) and, for signup links, optional `homeserver` (bare z32) and
  `signup_token` fields.
- **Authentication mirrors pubky 0.16.** Grant auth is exposed through
  `sign_up_grant`, `sign_in_grant`, `start_grant_auth_flow`, and
  `await_grant_auth_approval`; these return `grant_secret` in session JSON.
  The unqualified `sign_up`, `sign_in`, `start_auth_flow`, and
  `await_auth_approval` names are Grant aliases for downstream migration.
- **Signer approval can be narrowed.** `auth` approves every capability in an
  auth request, while `auth_with_capabilities` accepts the user-approved
  comma-separated `scope:actions` subset. An empty string approves no
  capabilities; the SDK rejects approvals that exceed the request.
- **Legacy cookie auth remains available** through `sign_up_cookie`,
  `sign_in_cookie`, `start_cookie_auth_flow`, and
  `await_cookie_auth_approval`; these return `session_secret` in session JSON.
  Cookie auth is deprecated upstream, but it is still exposed here because this
  crate is a low-level binding layer.
- **Session-token APIs accept either strategy.** `sign_out`,
  `revalidate_session`, `put_with_session`, and `delete_with_session` call
  `Pubky::restore_session`, so they accept a Grant `grant_secret` or a legacy
  cookie `session_secret`.
- **Many identities in one process.** A hosted client that signs many users in at once
  (loopky#214) uses the id-addressed grant flows instead of the process-wide slot:
  `start_grant_auth_flow_handle(capabilities, client_id, relay)` returns
  `{"flow_id", "authorization_url"}`; `poll_grant_auth_flow_handle(flow_id)` never blocks and
  answers `{"status": "pending"}` or `{"status": "approved", "session": {…}}`, where `session` is
  the same object `await_grant_auth_approval` returns (`grant_secret` included);
  `await_grant_auth_flow_handle(flow_id, timeout_secs)` blocks for at most `timeout_secs` and
  answers the same two shapes, a timeout being `pending` with the flow kept; and
  `cancel_grant_auth_flow_handle(flow_id)` drops one. An approval is handed out **once** — the
  flow is removed with it, as it is on failure, cancellation and expiry. Pending flows are
  capped (64) and swept after a TTL (300s, the relay's hold); `configure_grant_auth_flows(max,
  ttl_secs)` changes both. The old slot-based functions are unchanged.
- **The session cache is an LRU with single-flight minting.** `*_with_session` calls reuse the
  imported session per secret; `configure_session_cache(capacity)` sets how many are kept
  (default 4, for a phone). Overflow evicts the least recently used session only. Two concurrent
  imports of the same secret — or two re-mints after the same `401` — perform one grant exchange
  and share it, so they cannot replace each other's bearer.
- **`revoke_own_grant(session_secret)` revokes a grant from its stored secret alone.** It
  signs the revocation proof with the secret's `PoP` key (`DELETE /auth/grant/session`), so it
  works after the last bearer expired and needs no root session; every session minted from the
  grant dies with it, and the cache forgets it. A grant that is already gone answers with the
  `Session rejected` marker, which for an unlink means there is nothing left to do. `revoke_grant`
  (by id, root session) also evicts any cached session minted from that grant.
- **Grant management requires a root-capability session.** `list_grants`
  returns the account's active grants and `revoke_grant` revokes a grant by
  id, invalidating all sessions minted from it.
- **Every request has a deadline, and every body read has a ceiling.** The client is built with
  a 300s request timeout and a 120s read timeout (pubky's own default is none), so a homeserver
  that accepts the connection and never answers cannot park the calling thread for good;
  `configure_client` overrides both. `get`, `get_bytes`, `public_get_bytes` and
  `session_get_bytes` refuse a body over 50 MiB — on its `Content-Length` before a byte is read,
  or while reading one that declares nothing — and `configure_max_body_bytes(max_bytes)` sets
  the limit (returning the one in force; `0` only reads it). The homeserver is whatever the
  resolved pubky names, so neither number is something a consumer should leave to that host.
- **New Pubky 0.16 APIs use typed native errors.** Existing functions keep the
  `[error, data]` vector contract. The additive storage, event, lock, client
  configuration, blocking-signin, and advanced Grant-flow APIs return native
  `Result` values with `PubkyCoreError` variants instead.

## Pubky 0.16 Client Bindings

The high-level Pubky 0.16 client surface is available to generated Swift,
Kotlin, and Python bindings:

- Client configuration: request/read timeouts, connection pooling, bounded
  error bodies, user-agent suffixes, mainnet, and custom-host testnet.
- Storage: public and authenticated reads, public and private paths, raw bytes,
  existence checks, metadata, paginated listings, writes, and deletes.
- Authentication: Grant signin and signup flows, relay and callback
  configuration, save/restore, non-blocking polling, cancellation, blocking
  signin, session revalidation, Grant management, signed approvals, scoped
  encryption keys, and custom offline-verifiable proofs.
- Events: historical and live streams, multiple users, cursors, path filters,
  private authenticated streams, reverse order, limits, and cancellation.
- Locks: acquire, inspect, refresh, write, delete, and unlock.
- Structured failures: transport, server status, validation, JSON decoding,
  PKARR retryability, parsing, authentication expiry, build, and binding-state
  errors.

See [BINDING_PARITY.md](BINDING_PARITY.md) for the SDK-to-FFI mapping and the
small set of Rust-specific low-level primitives intentionally kept internal.

## Building the SDK

### To build both iOS and Android bindings:
```
./build.sh all
```

### To build only iOS bindings:
```
./build.sh ios
```

### To build only Android bindings:
```
./build.sh android
```

The Android build is pinned to the NDK version in `.ndk-version` (currently
r29) and requires NDK r28 or newer. Install the pinned version with
`sdkmanager "ndk;$(cat .ndk-version)"`. NDK r28+ emits ELF `LOAD` segments
compatible with Android's 16 KB page size by default. After building all four
shipped ABIs, the build runs `scripts/verify_android_page_size.sh` and fails if
any 64-bit shared library has a `LOAD` alignment below `0x4000`.

To verify already-built Android bindings without rebuilding them:

```
ANDROID_NDK_HOME="$ANDROID_SDK_ROOT/ndk/$(cat .ndk-version)" \
  ./scripts/verify_android_page_size.sh
```

### To build only Python bindings:
```
./build.sh python
```

### To build the desktop cdylibs:
```
./build.sh desktop            # every row this host can produce
./build.sh desktop linux      # x86_64-unknown-linux-gnu
./build.sh desktop macos      # aarch64-apple-darwin, Apple Silicon only
./build.sh desktop windows    # x86_64-pc-windows-msvc, on Windows under Git Bash
```

These are for JVM consumers that load the crate through JNA, and they land under
`bindings/desktop/` in JNA's own resource layout so that `Native.load("pubkycore")` works from
inside a jar with no install step:

| Row | Artifact |
| --- | --- |
| Linux x86_64 | `linux-x86-64/libpubkycore.so` |
| macOS, Apple Silicon | `darwin-aarch64/libpubkycore.dylib` |
| Windows x86_64 | `win32-x86-64/pubkycore.dll` — no `lib` prefix, because JNA does not expect one |

Windows is built by CI and nowhere else: the MSVC target needs the Microsoft linker and the Windows
SDK, so unlike the Linux row there is no container that can cross-build it. See
`.github/workflows/desktop-windows.yml`, which also asserts the DLL needs no Visual C++
redistributable — a check the build itself cannot make, since the runner has one installed.

The two Apple rows — the macOS dylib and the iOS XCFramework — come from
`.github/workflows/desktop-macos.yml` whenever the developer's machine is not a Mac. Both
workflows only *upload* artifacts; a person downloads them (`gh run download <run-id>`) and
commits them, so that a workflow running on a pull request can never write a binary into the
repository by itself. The macOS dylib is committed **twice**: under `bindings/desktop/` for JNA
and as `bindings/python/pubkycore/libpubkycore.dylib`, the one the Python module loads.
`build_desktop.sh macos` writes both, and the workflow imports the Python package against the
fresh build, because the module checks every function's checksum at import — a dylib older than
`pubkycore.py` fails `import pubkycore` with a missing symbol, and nothing else notices.

The Linux row is built inside `rust:1-bullseye` rather than on the host: a cdylib links against
its builder's glibc, and consumers (loopky's CLI container is `ubuntu:22.04`) need the floor at
2.34 or below. Check it with
`objdump -T bindings/desktop/linux-x86-64/libpubkycore.so | grep -oE 'GLIBC_[0-9.]+' | sort -Vu | tail -1`.

## Run Tests:
```
cargo test -- --test-threads=1
```

## iOS Integration

### Installation
1. Add the XCFramework to your Xcode project:

   - Drag bindings/ios/PubkyCore.xcframework into your Xcode project
     Ensure "Copy items if needed" is checked
     Add the framework to your target


2. Copy the Swift bindings:

   - Add bindings/ios/pubkycore.swift to your project

### Basic Usage
```swift
import PubkyCore

class PubkyManager {
    // Generate a new secret key
    func generateNewAccount() throws -> String {
        let result = try generateSecretKey()
        guard let jsonData = result[1].data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any],
              let secretKey = json["secret_key"] as? String else {
            throw NSError(domain: "PubkyError", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to parse response"])
        }
        return secretKey
    }
    
    // Get a signup token
    func getSignupToken(homeserverPubky: String, adminPassword: String) async throws -> String {
        let result = try getSignupToken(homeserverPubky: homeserverPubky, adminPassword: adminPassword)
        if result[0] == "true" {
            throw NSError(domain: "PubkyError", code: -1, userInfo: [NSLocalizedDescriptionKey: result[1]])
        }
        return result[1]
    }
    
    // Sign up with a homeserver (with optional signup token)
    func signUp(secretKey: String, homeserver: String, signupToken: String? = nil) async throws -> String {
        let result = try signUp(secretKey: secretKey, homeserver: homeserver, signupToken: signupToken)
        if result[0] == "true" {
            throw NSError(domain: "PubkyError", code: -1, userInfo: [NSLocalizedDescriptionKey: result[1]])
        }
        return result[1]
    }
    
    // Get the homeserver for a Pubky public key
    func getHomeserver(pubky: String) async throws -> String {
        let result = try getHomeserver(pubky: pubky)
        if result[0] == "true" {
            throw NSError(domain: "PubkyError", code: -1, userInfo: [NSLocalizedDescriptionKey: result[1]])
        }
        return result[1]
    }
    
    // Publish content
    func publishContent(recordName: String, content: String, secretKey: String) async throws -> String {
        let result = try publish(recordName: recordName, recordContent: content, secretKey: secretKey)
        if result[0] == "true" {
            throw NSError(domain: "PubkyError", code: -1, userInfo: [NSLocalizedDescriptionKey: result[1]])
        }
        return result[1]
    }
    
    // Retrieve content
    func getContent(url: String) async throws -> String {
        let result = try get(url: url)
        if result[0] == "true" {
            throw NSError(domain: "PubkyError", code: -1, userInfo: [NSLocalizedDescriptionKey: result[1]])
        }
        return result[1]
    }
}
```

### Example Implementation
```swift
class ViewController: UIViewController {
    let pubkyManager = PubkyManager()
    
    func setupAccount() async {
        do {
            // Generate new account
            let secretKey = try pubkyManager.generateNewAccount()
            
            // Sign up with homeserver
            let homeserver = "pubky://8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo"
            
            // For servers requiring signup tokens
            // let adminPassword = "your-admin-password"
            // let signupToken = try await pubkyManager.getSignupToken(homeserverPubky: homeserver, adminPassword: adminPassword)
            // let publicKey = try await pubkyManager.signUp(secretKey: secretKey, homeserver: homeserver, signupToken: signupToken)
            
            // For servers without token requirements
            let publicKey = try await pubkyManager.signUp(secretKey: secretKey, homeserver: homeserver)
            
            // Publish content
            let content = "Hello, Pubky!"
            let recordName = "example.com"
            let publishResult = try await pubkyManager.publishContent(
                recordName: recordName,
                content: content,
                secretKey: secretKey
            )
            
            print("Published with public key: \(publishResult)")
            
            // Get homeserver for a public key
            let foundHomeserver = try await pubkyManager.getHomeserver(pubky: publishResult)
            print("Homeserver for this key: \(foundHomeserver)")
        } catch {
            print("Error: \(error.localizedDescription)")
        }
    }
}
```

## Android Integration

### Installation
1. Add the JNI libraries to your project:

   - Copy the contents of bindings/android/jniLibs to your project's app/src/main/jniLibs directory


2. Add the Kotlin bindings:

   - Copy bindings/android/pubkycore.kt to your project's source directory

### Basic Usage
```kotlin
class PubkyManager {
    init {
        // Initialize the library
        System.loadLibrary("pubkycore")
    }
    
    fun generateNewAccount(): String {
        val result = generateSecretKey()
        if (result[0] == "true") {
            throw Exception(result[1])
        }
        val json = JSONObject(result[1])
        return json.getString("secret_key")
    }
    
    suspend fun getSignupToken(homeserverPubky: String, adminPassword: String): String {
        val result = getSignupToken(homeserverPubky, adminPassword)
        if (result[0] == "true") {
            throw Exception(result[1])
        }
        return result[1]
    }
    
    suspend fun signUp(secretKey: String, homeserver: String, signupToken: String? = null): String {
        val result = signUp(secretKey, homeserver, signupToken)
        if (result[0] == "true") {
            throw Exception(result[1])
        }
        return result[1]
    }
    
    suspend fun getHomeserver(pubky: String): String {
        val result = getHomeserver(pubky)
        if (result[0] == "true") {
            throw Exception(result[1])
        }
        return result[1]
    }
    
    suspend fun publishContent(recordName: String, content: String, secretKey: String): String {
        val result = publish(recordName, content, secretKey)
        if (result[0] == "true") {
            throw Exception(result[1])
        }
        return result[1]
    }
    
    suspend fun getContent(url: String): String {
        val result = get(url)
        if (result[0] == "true") {
            throw Exception(result[1])
        }
        return result[1]
    }
}
```

### Example Implementation
```kotlin   
class MainActivity : AppCompatActivity() {
    private val pubkyManager = PubkyManager()
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        lifecycleScope.launch {
            try {
                // Generate new account
                val secretKey = pubkyManager.generateNewAccount()
                
                // Sign up with homeserver
                val homeserver = "pubky://8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo"
                
                // For servers requiring signup tokens
                // val adminPassword = "your-admin-password"
                // val signupToken = pubkyManager.getSignupToken(homeserver, adminPassword)
                // val publicKey = pubkyManager.signUp(secretKey, homeserver, signupToken)
                
                // For servers without token requirements
                val publicKey = pubkyManager.signUp(secretKey, homeserver)
                
                // Publish content
                val content = "Hello, Pubky!"
                val recordName = "example.com"
                val publishResult = pubkyManager.publishContent(
                    recordName = recordName,
                    content = content,
                    secretKey = secretKey
                )
                
                Log.d("Pubky", "Published with public key: $publishResult")
                
                // Get homeserver for a public key
                val foundHomeserver = pubkyManager.getHomeserver(publishResult)
                Log.d("Pubky", "Homeserver for this key: $foundHomeserver")
            } catch (e: Exception) {
                Log.e("Pubky", "Error: ${e.message}")
            }
        }
    }
}
```

## Advanced Features

### Working with HTTPS Records

```swift
// iOS
func publishHttps(recordName: String, target: String, secretKey: String) async throws -> String {
    let result = try publishHttps(recordName: recordName, target: target, secretKey: secretKey)
    if result[0] == "true" {
        throw NSError(domain: "PubkyError", code: -1, userInfo: [NSLocalizedDescriptionKey: result[1]])
    }
    return result[1]
}
```

```kotlin
// Android
suspend fun publishHttps(recordName: String, target: String, secretKey: String): String {
    val result = publishHttps(recordName, target, secretKey)
    if (result[0] == "true") {
        throw Exception(result[1])
    }
    return result[1]
}
```

### User Authentication with Signup Tokens

For servers that require authentication control:

```swift
// iOS
// 1. Admin generates a signup token
func getServerSignupToken(homeserverPubky: String, adminPassword: String) async throws -> String {
    let result = try getSignupToken(homeserverPubky: homeserverPubky, adminPassword: adminPassword)
    if result[0] == "true" {
        throw NSError(domain: "PubkyError", code: -1, userInfo: [NSLocalizedDescriptionKey: result[1]])
    }
    return result[1]
}

// 2. User signs up with the token
func signUpWithToken(secretKey: String, homeserver: String, token: String) async throws -> String {
    let result = try signUp(secretKey: secretKey, homeserver: homeserver, signupToken: token)
    if result[0] == "true" {
        throw NSError(domain: "PubkyError", code: -1, userInfo: [NSLocalizedDescriptionKey: result[1]])
    }
    return result[1]
}
```

```kotlin
// Android
// 1. Admin generates a signup token
suspend fun getServerSignupToken(homeserverPubky: String, adminPassword: String): String {
    val result = getSignupToken(homeserverPubky, adminPassword)
    if (result[0] == "true") {
        throw Exception(result[1])
    }
    return result[1]
}

// 2. User signs up with the token
suspend fun signUpWithToken(secretKey: String, homeserver: String, token: String): String {
    val result = signUp(secretKey, homeserver, token)
    if (result[0] == "true") {
        throw Exception(result[1])
    }
    return result[1]
}
```

### Getting and Using Homeserver Information

You can retrieve the homeserver information for a Pubky:

```swift
// iOS
func findHomeserver(pubkyKey: String) async throws -> String {
    let result = try getHomeserver(pubky: pubkyKey)
    if result[0] == "true" {
        throw NSError(domain: "PubkyError", code: -1, userInfo: [NSLocalizedDescriptionKey: result[1]])
    }
    return result[1]
}

// Usage example
func checkAndReconnect(pubkyKey: String) async {
    do {
        let homeserver = try await findHomeserver(pubkyKey: pubkyKey)
        print("Found homeserver: \(homeserver)")
    } catch {
        print("Failed to find homeserver: \(error.localizedDescription)")
    }
}
```

```kotlin
// Android
suspend fun findHomeserver(pubkyKey: String): String {
    val result = getHomeserver(pubkyKey)
    if (result[0] == "true") {
        throw Exception(result[1])
    }
    return result[1]
}

// Usage example
suspend fun checkAndReconnect(pubkyKey: String) {
    try {
        val homeserver = findHomeserver(pubkyKey)
        Log.d("Pubky", "Found homeserver: $homeserver")
    } catch (e: Exception) {
        Log.e("Pubky", "Failed to find homeserver: ${e.message}")
    }
}
```

### Recovery File Management
```swift
// iOS
func createRecoveryFile(secretKey: String, passphrase: String) throws -> String {
    let result = try createRecoveryFile(secretKey: secretKey, passphrase: passphrase)
    if result[0] == "true" {
        throw NSError(domain: "PubkyError", code: -1, userInfo: [NSLocalizedDescriptionKey: result[1]])
    }
    return result[1]
}
```

```kotlin
// Android
fun createRecoveryFile(secretKey: String, passphrase: String): String {
    val result = createRecoveryFile(secretKey, passphrase)
    if (result[0] == "true") {
        throw Exception(result[1])
    }
    return result[1]
}
```

## Error Handling
All methods return a `Vec<String>` where:
- The first element ([0]) is the error flag: "true" if the call failed, "false" on success
- The second element ([1]) contains either the result data or error message

It's recommended to wrap all calls in try-catch blocks and handle errors appropriately in your application.

## Network Configuration

You can switch between default and testnet:
```swift
// iOS
try switchNetwork(useTestnet: true) // For testnet
try switchNetwork(useTestnet: false) // For default
```

```kotlin
// Android
switchNetwork(true) // For testnet
switchNetwork(false) // For default
```
