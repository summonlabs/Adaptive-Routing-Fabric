<#
.SYNOPSIS
  Full validation of Adaptive Routing Fabric from a clean checkout.

.DESCRIPTION
  Runs every gate the release claims: Release configure/build/test, Debug, the
  installer and an independent find_package consumer, the examples, and the
  benchmarks. AddressSanitizer and MSVC /analyze are opt-in because they need a
  toolchain that supports them; both are diagnosed rather than assumed.

  Nothing here uses a timeout. A hanging step is a defect, not something to wait
  out.

.PARAMETER Configuration
  Build directory to use. Defaults to 'build'.

.PARAMETER SkipSanitizers
  Skip the /analyze and AddressSanitizer passes.

.EXAMPLE
  pwsh -File scripts/validate.ps1 -SkipSanitizers
#>
[CmdletBinding()]
param(
  [string] $Configuration = 'build',
  [switch] $SkipSanitizers
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo
try {
  Write-Host '== Release configure, build and test =='
  cmake -S . -B $Configuration -G Ninja -DCMAKE_BUILD_TYPE=Release
  if ($LASTEXITCODE -ne 0) { throw 'release configure failed' }
  cmake --build $Configuration
  if ($LASTEXITCODE -ne 0) { throw 'release build failed' }
  ctest --test-dir $Configuration --output-on-failure
  if ($LASTEXITCODE -ne 0) { throw 'release tests failed' }

  Write-Host '== Debug configure, build and test =='
  cmake -S . -B "$Configuration-debug" -G Ninja -DCMAKE_BUILD_TYPE=Debug
  if ($LASTEXITCODE -ne 0) { throw 'debug configure failed' }
  cmake --build "$Configuration-debug"
  if ($LASTEXITCODE -ne 0) { throw 'debug build failed' }
  ctest --test-dir "$Configuration-debug" --output-on-failure
  if ($LASTEXITCODE -ne 0) { throw 'debug tests failed' }

  Write-Host '== Examples =='
  Get-ChildItem $Configuration -Filter 'example_*.exe' | ForEach-Object {
    & $_.FullName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "example $($_.Name) failed" }
    Write-Host "  ok $($_.Name)"
  }

  Write-Host '== Benchmarks =='
  & (Join-Path $Configuration 'arf_benchmarks.exe')
  if ($LASTEXITCODE -ne 0) { throw 'benchmarks failed' }

  Write-Host '== Install and independent consumer =='
  $prefix = Join-Path $env:TEMP 'arf-validate-install'
  $consumerBuild = Join-Path $env:TEMP 'arf-validate-consumer'
  Remove-Item -Recurse -Force $prefix, $consumerBuild -ErrorAction SilentlyContinue
  cmake --install $Configuration --prefix $prefix
  if ($LASTEXITCODE -ne 0) { throw 'install failed' }
  if (-not (Test-Path (Join-Path $prefix 'lib/cmake/AdaptiveRoutingFabric/AdaptiveRoutingFabricConfig.cmake'))) {
    throw 'the installed package does not export AdaptiveRoutingFabricConfig.cmake'
  }
  # The -D argument is quoted on purpose: PowerShell mangles an unquoted
  # -DNAME=$value token, and CMake then receives a prefix path it cannot use.
  cmake -S tests/consumer -B $consumerBuild -G Ninja -DCMAKE_BUILD_TYPE=Release "-DCMAKE_PREFIX_PATH=$prefix"
  if ($LASTEXITCODE -ne 0) { throw 'consumer configure failed' }
  cmake --build $consumerBuild
  if ($LASTEXITCODE -ne 0) { throw 'consumer build failed' }
  & (Join-Path $consumerBuild 'arf_consumer.exe')
  if ($LASTEXITCODE -ne 0) { throw 'consumer run failed' }

  if (-not $SkipSanitizers) {
    Write-Host '== MSVC static analysis =='
    cmake -S . -B "$Configuration-analyze" -G Ninja -DCMAKE_BUILD_TYPE=Release -DARF_ENABLE_ANALYZE=ON
    if ($LASTEXITCODE -ne 0) { throw 'analyze configure failed' }
    cmake --build "$Configuration-analyze"
    if ($LASTEXITCODE -ne 0) { throw 'analyze build failed' }

    Write-Host '== AddressSanitizer =='
    cmake -S . -B "$Configuration-asan" -G Ninja -DCMAKE_BUILD_TYPE=Release -DARF_ENABLE_ASAN=ON -DARF_ENABLE_ANALYZE=OFF
    if ($LASTEXITCODE -ne 0) { throw 'sanitizer configure failed' }
    cmake --build "$Configuration-asan"
    if ($LASTEXITCODE -ne 0) { throw 'sanitizer build failed' }
    ctest --test-dir "$Configuration-asan" --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw 'sanitizer tests failed' }
  }

  Write-Host 'VALIDATION PASSED'
} finally {
  Pop-Location
}
