# Nix source closure filter shared by package builds and its regression check.
{ lib, root }:
let
  excludedDirNames = [ "target" "node_modules" ".git" ".jj" "dist" "result" ];
  sensitiveDirNames = [ ".aws" ".azure" ".docker" ".gnupg" ".kube" ".ssh" ];
  sensitiveFileNames = [
    ".env"
    ".netrc"
    ".npmrc"
    ".pypirc"
    "application_default_credentials.json"
    "credentials.json"
    "service-account.json"
  ];
  privateKeyPrefixes = [ "id_dsa" "id_ecdsa" "id_ed25519" "id_rsa" ];
  sensitiveFileSuffixes = [ ".key" ".p12" ".pfx" ];
  safeEnvTemplateNames = [ ".env.defaults" ".env.example" ".env.sample" ".env.template" ];
in
path: _type:
let
  relPath = lib.removePrefix (toString root) (toString path);
  baseName = lib.toLower (baseNameOf path);
  excludedBuildOrVcsNoise =
    builtins.elem (baseNameOf path) excludedDirNames
    || builtins.any (d: lib.hasInfix "/${d}/" relPath) excludedDirNames;
  # Match sensitive names independent of filesystem type, including symlinks.
  excludedCredentialDirectory = builtins.elem baseName sensitiveDirNames;
  isEnvFile = baseName == ".env" || lib.hasPrefix ".env." baseName;
  excludedCredentialPath =
    builtins.elem baseName sensitiveFileNames
    || (
      builtins.any (prefix: lib.hasPrefix prefix baseName) privateKeyPrefixes
      && !(lib.hasSuffix ".pub" baseName)
    )
    || builtins.any (suffix: lib.hasSuffix suffix baseName) sensitiveFileSuffixes
    || (isEnvFile && !(builtins.elem baseName safeEnvTemplateNames));
in
!(excludedBuildOrVcsNoise || excludedCredentialDirectory || excludedCredentialPath)
