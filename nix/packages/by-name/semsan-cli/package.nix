{
  buildSemsanGoModule,
  lib,
}:
buildSemsanGoModule {
  name = "semsan-cli";
  version = lib.semsanVersion;

  src = lib.repoRootSrc [
    "go.mod"
    "go.sum"
    "cli"
    "internal"
  ];
}
