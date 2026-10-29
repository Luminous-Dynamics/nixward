{ pkgs, commonBuildInputs, commonNativeBuildInputs }:

pkgs.rustPlatform.buildRustPackage {
  pname = "nixward-systemd-job-bus-test-runner";
  version = "0.1.0";
  src = ..;
  cargoLock = {
    lockFile = ../Cargo.lock;
    allowBuiltinFetchGit = true;
  };

  buildInputs = commonBuildInputs;
  nativeBuildInputs = commonNativeBuildInputs;

  env.HOME = "$TMPDIR";
  env.RUSTC_WRAPPER = "";

  doCheck = false;

  # Build the library's unit-test binary but do not execute it during the Nix
  # build. The NixOS VM harness runs exactly one explicit, ignored live test.
  postBuild = ''
    cargo test --no-run --features systemd --lib 2>&1 | tee "$TMPDIR/nixward-test-build.log"
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p "$out/bin"
    test_binary="$(sed -n 's@.*Executable unittests src/lib.rs (target/debug/deps/\(nixward-[^)]*\)).*@\1@p' "$TMPDIR/nixward-test-build.log" | tail -n 1)"
    test -n "$test_binary" || {
      echo "could not locate cargo test binary in build output" >&2
      exit 1
    }
    install -m755 "target/debug/deps/$test_binary" "$out/bin/nixward-systemd-tests"
    runHook postInstall
  '';
}
