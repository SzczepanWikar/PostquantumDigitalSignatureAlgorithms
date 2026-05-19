# Master's Thesis Project - ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) Implementation

## Topic
_Comparison and implementation of selected post-quantum digital signature algorithms._

## Overview
This master's thesis project focuses on the implementation and testing of selected post-quantum digital signature algorithms.
The chosen algorithms are **ML-DSA (FIPS 204)** and **SLH-DSA (FIPS 205)**. The implementation is based exclusively on the ratified NIST FIPS standards, without reference to earlier round specifications (CRYSTALS-Dilithium, SPHINCS+).

## Public API

### ML-DSA (`CrystalsDilithium`)

| Class | Description |
|---|---|
| `CrystalsDilithiumAlgorithm` | Entry point - KeyGen, Sign, Verify (pure and pre-hash variants) |
| `DilithiumParameters` | Algorithm constants for a given security level |
| `DilithiumParametersProvider` | Predefined parameter sets: `SecurityLevel2Parameters`, `SecurityLevel3Parameters`, `SecurityLevel5Parameters` |

### SLH-DSA (`SphincsPlus`)

| Class | Description |
|---|---|
| `SphincsPlusAlgorithm` | Entry point - KeyGen, Sign, Verify (pure and pre-hash variants) |
| `SphincsPlusParameters` | Algorithm constants for a given parameter set |
| `SphincsPlusParametersProvider` | Predefined parameter sets, e.g. `Sha2_128f`, `Shake_256s` |

## Implementation Notes

Method parameter names in the implementation follow the notation defined in the respective standards (FIPS 204, FIPS 205). For example, parameters such as `rho`, `rhoPrim`, `eta`, `t1`, `ksi` correspond directly to the symbols used in the algorithm specifications.

## Requirements

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)

## Running Tests

### ML-DSA (CRYSTALS-Dilithium)
```bash
dotnet test DilithiumTests/DilithiumTests.csproj
```

### SLH-DSA (SPHINCS+)
```bash
dotnet test SphincsPlusTests/SphincsPlusTests.csproj
```

## Disclaimer
This project is created for educational purposes only. The implementations provided here are not intended for production use and should not be used in real-world applications. The author assumes no responsibility for any consequences arising from the use of this code.