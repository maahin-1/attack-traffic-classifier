# Local research package review — 5 November 2026

**Update:** The project owner subsequently selected MIT and supplied the copyright holder. The workspace now includes `LICENSE`. The version 2 ZIP reviewed below predates that decision and does not contain it. A newer package must be separately checked before distribution; third-party and dataset rights remain separate.

## Package

Candidate: `artifacts/research-package-20261105-v2.zip` (388,185 bytes; SHA-256 `38c6a0954b17ff63a29c29360093f01e6f352d3bac04995bf38394549da562d7`). Its 146 members comprise source, experiment scripts, tests, configurations, documentation, project-authored synthetic fixtures and `PACKAGE-MANIFEST.json`. The builder verifies the ZIP CRC and checks each member against its manifest SHA-256. The manifest is an integrity aid, not a signature or proof of publisher identity.

The builder selects a fixed set of source directories and file extensions. It does not include the local `data/` or `artifacts/` trees, real captures, serialized model bundles or row-level experiment outputs. The package does contain aggregate findings and research references in documentation. Its guide notes that some historical documents link to omitted local artifacts. A limited text scan for common credential assignments, email addresses and Windows user paths found no matches; this is not a guarantee that all sensitive information has been found.

## Validation

The first package was extracted to a fresh local directory and its suite exposed an existing test that assumed `.test-tmp` already existed. The test setup now creates that directory itself. A rebuilt version 2 was extracted to a separate fresh directory and checked:

- All **209 tests and 117 subtests passed** using the host Python environment with pytest plugin autoload disabled.
- The synthetic `run` and `report --charts --parquet` commands completed using the separately prepared project-local virtual environment. This virtual environment and the extracted package share the host operating system and base Python installation.
- Archive contents and CRCs were checked, and archived files matched their manifest hashes. The synthetic run's generated outputs were written only to the extracted test directory, after the ZIP was created, and are not present in the ZIP.

The package is a local review candidate, not a verified production release. A fresh full-data rerun, new independent holdout, exact original UTC reconstruction and fully pinned transitive dependencies were not established. No model-performance improvement is claimed.

## Before external distribution

At the time version 2 was built, no source-code license file or explicit project redistribution grant had been found; see the update above. The source dataset and derived-record redistribution rights remain unverified; this candidate intentionally excludes those files. Carry out a final content and rights review and preserve the caveats in the accompanying description. Preparing the ZIP did not publish or send it anywhere.
