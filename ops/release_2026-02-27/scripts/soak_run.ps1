param(
    [int]$Iterations = 25,
    [string]$OutFile = "ops/release_2026-02-27/logs/soak_run.log"
)

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutFile) | Out-Null
"SOAK_START $(Get-Date -Format o) iterations=$Iterations" | Out-File $OutFile

for ($i = 1; $i -le $Iterations; $i++) {
    "ITER=$i START $(Get-Date -Format o)" | Tee-Object -FilePath $OutFile -Append
    cargo test --lib tests::submit_batch_and_flush_fence_completion_poll -- --exact *> "ops/release_2026-02-27/logs/soak_iter_${i}.txt"
    if ($LASTEXITCODE -ne 0) {
        "ITER=$i FAIL code=$LASTEXITCODE" | Tee-Object -FilePath $OutFile -Append
        break
    }
    "ITER=$i PASS" | Tee-Object -FilePath $OutFile -Append
}

"SOAK_END $(Get-Date -Format o)" | Tee-Object -FilePath $OutFile -Append
