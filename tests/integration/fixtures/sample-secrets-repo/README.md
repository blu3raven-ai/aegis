# sample-secrets-repo

Fixture used by `.github/workflows/scanner-http-integration.yml`.

`config.txt` contains AWS's documented test key (`AKIAIOSFODNN7EXAMPLE`) — a
deliberately invalid identifier the secrets scanner is expected to flag. The
CI workflow turns this directory into a git repository, commits the file, and
points the secrets scanner at the resulting checkout.
