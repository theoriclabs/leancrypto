import Lake

open System Lake DSL

package leancrypto where
  version := v!"0.1.0"
  keywords := #["crypto", "sha256", "hmac", "scrypt", "openssl", "ffi"]
  license := "MIT"

/-- OpenSSL 3 prefix: `OPENSSL_DIR`, then Homebrew (arm64, x86_64), then `/usr`. -/
def opensslPrefix : IO FilePath := do
  if let some d ← IO.getEnv "OPENSSL_DIR" then
    if !d.isEmpty then return d
  for c in ["/opt/homebrew/opt/openssl@3", "/usr/local/opt/openssl@3"] do
    if ← (FilePath.mk c / "include" / "openssl" / "evp.h").pathExists then
      return c
  return "/usr"

/-- Locate the static `libcrypto.a` under the prefix (`lib`, `lib64`, Debian multiarch). -/
def findLibcryptoA (pre : FilePath) : IO FilePath := do
  let mut cands : Array FilePath := #[pre / "lib" / "libcrypto.a", pre / "lib64" / "libcrypto.a"]
  for arch in ["x86_64-linux-gnu", "aarch64-linux-gnu"] do
    cands := cands.push (pre / "lib" / arch / "libcrypto.a")
  for c in cands do
    if ← c.pathExists then return c
  throw <| IO.userError s!"leancrypto: libcrypto.a not found under {pre}; install OpenSSL 3 (brew install openssl@3 / apt install libssl-dev) or set OPENSSL_DIR"

target leancrypto.o pkg : FilePath := do
  let oFile := pkg.buildDir / "leancrypto.o"
  let srcJob ← inputTextFile <| pkg.dir / "bindings" / "leancrypto.c"
  let pre ← opensslPrefix
  let weakArgs := #["-I", (← getLeanIncludeDir).toString, "-I", (pre / "include").toString]
  buildO oFile srcJob weakArgs (traceArgs := #["-fPIC", "-std=c11", "-O2"]) (extraDepTrace := getLeanTrace)

/-- One static archive holding the bindings and every object of OpenSSL's
`libcrypto.a`, so downstream executables link with no extra configuration. -/
extern_lib leancrypto pkg := do
  let obj ← leancrypto.o.fetch
  let libA ← findLibcryptoA (← opensslPrefix)
  let out := pkg.staticLibDir / nameToStaticLib "leancrypto"
  obj.mapM fun o => do
    IO.FS.createDirAll pkg.staticLibDir
    let tmp := pkg.buildDir / "libcrypto-objs"
    if ← tmp.pathExists then IO.FS.removeDirAll tmp
    IO.FS.createDirAll tmp
    let x ← IO.Process.output { cmd := "ar", args := #["x", libA.toString], cwd := tmp }
    if x.exitCode != 0 then error s!"ar x {libA} failed: {x.stderr}"
    let members ← IO.Process.output { cmd := "ar", args := #["t", libA.toString] }
    let expected := (members.stdout.splitOn "\n").filter (·.endsWith ".o") |>.eraseDups |>.length
    if ← out.pathExists then IO.FS.removeFile out
    let objs ← (← tmp.readDir).filterMapM fun e =>
      pure (if e.path.extension == some "o" then some e.path.toString else none)
    if objs.size != expected then
      error s!"leancrypto: extracted {objs.size} objects from {libA}, expected {expected}"
    let r ← IO.Process.output { cmd := "ar", args := #["rcs", out.toString, o.toString] ++ objs }
    if r.exitCode != 0 then error s!"ar failed: {r.stderr}"
    addTrace (← computeTrace libA)
    return out

@[default_target]
lean_lib LeanCrypto where
  needs := #[leancrypto]
  precompileModules := false

lean_exe leancrypto_tests where
  root := `Tests
  srcDir := "tests"
