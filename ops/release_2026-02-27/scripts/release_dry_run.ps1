param(
    [string]$OutDir = "ops/release_2026-02-27/logs"
)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

"[1/4] cargo clean" | Tee-Object -FilePath "$OutDir/release_dry_run.log" -Append
cargo clean *> "$OutDir/release_dry_run_clean.txt"

"[2/4] cargo build --lib --release" | Tee-Object -FilePath "$OutDir/release_dry_run.log" -Append
cargo build --lib --release *> "$OutDir/release_dry_run_build_lib.txt"

"[3/4] cargo build --release" | Tee-Object -FilePath "$OutDir/release_dry_run.log" -Append
cargo build --release *> "$OutDir/release_dry_run_build_full.txt"

"[4/4] artifact snapshot" | Tee-Object -FilePath "$OutDir/release_dry_run.log" -Append
Get-ChildItem target/release -File | Select-Object Name,Length | Out-File "$OutDir/release_artifacts.txt"

"DONE" | Tee-Object -FilePath "$OutDir/release_dry_run.log" -Append
