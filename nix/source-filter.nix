# Nix source closure filter shared by package builds and its regression check.
{ lib, root }:
let
  excludedDirNames = [ "target" "node_modules" ".git" ".jj" ".direnv" "dist" "result" ];
  sensitiveDirNames = [ ".aws" ".azure" ".docker" ".gnupg" ".kube" ".ssh" ];
  sensitiveFileNames = [
    ".env"
    ".envrc"
    "direnvrc"
    ".netrc"
    ".npmrc"
    ".pypirc"
    ".git-credentials"
    ".gitcookies"
    "application_default_credentials.json"
    "credentials.json"
    "service-account.json"
  ];
  privateKeyPrefixes = [ "id_dsa" "id_ecdsa" "id_ed25519" "id_rsa" ];
  sensitiveFileSuffixes = [ ".key" ".pem" ".p8" ".p12" ".pfx" ".jks" ".keystore" ];
  sensitivePathFragments = [
    "/.cargo/credentials"
    "/.config/nix/nix.conf"
    "/.config/gh/hosts.yml"
    "/.config/gcloud/"
    "/.config/azure/"
    "/.config/1password/"
    "/.config/op/"
    "/.local/share/keyrings/"
  ];
  safeEnvTemplateNames = [ ".env.defaults" ".env.example" ".env.sample" ".env.template" ];
in
path: type:
let
  relPath = lib.removePrefix (toString root) (toString path);
  baseName = lib.toLower (baseNameOf path);
  excludedBuildOrVcsNoise =
    builtins.elem (baseNameOf path) excludedDirNames
    || builtins.any (d: lib.hasInfix "/${d}/" relPath) excludedDirNames;
  # Match sensitive names independent of filesystem type, including symlinks.
  excludedCredentialDirectory = builtins.elem baseName sensitiveDirNames;
  isEnvFile = baseName == ".env" || lib.hasPrefix ".env." baseName;
  safeTemplateFile =
    type == "regular" && builtins.elem baseName safeEnvTemplateNames;
  safePublicKeyFile =
    type == "regular" && lib.hasSuffix ".pub" baseName;
  sensitivePath = builtins.any (fragment: lib.hasInfix fragment relPath) sensitivePathFragments;
  excludedCredentialPath =
    sensitivePath
    || builtins.elem baseName sensitiveFileNames
    || (
      builtins.any (prefix: lib.hasPrefix prefix baseName) privateKeyPrefixes
      && !safePublicKeyFile
    )
    || builtins.any (suffix: lib.hasSuffix suffix baseName) sensitiveFileSuffixes
    || (isEnvFile && !safeTemplateFile);
in
!(excludedBuildOrVcsNoise || excludedCredentialDirectory || excludedCredentialPath)
