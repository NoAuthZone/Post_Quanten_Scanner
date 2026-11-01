# PQ Code Scanner — single-file edition

**Version 0.10.0 · Cryptography detection only**

This edition consists of exactly two files:

- `post_quanten_scanner.py` — the complete command-line scanner, including the
  local dependency catalog, reference profile and report generation.
- `README.md` — this guide.

No installation, additional Python modules, configuration files or build steps
are required. Reports are created only when you request them. No target code is
executed, installed or uploaded, and scanning makes no network requests.

## Requirements

Python **3.10+** on Windows, Linux or macOS. Use **Python 3.11+** if you also want
to analyze target `pyproject.toml` dependency declarations. On Python 3.10 those
files are skipped with an explicit note. No PHP, Java, Node.js, Ruby or Dart
runtime is needed.

This compact edition runs in a terminal and creates HTML reports that open in a
browser. It does not include the separate Tk desktop interface or the two-report
comparison tool from the larger project.

## Start a scan

Save both files in one folder and open a terminal there:

```sh
python post_quanten_scanner.py /path/to/project --html report.html --json report.json --sarif report.sarif
```

Windows example:

```powershell
py -3 post_quanten_scanner.py "C:\path\to\project" --html report.html --json report.json --sarif report.sarif
```

Open `report.html` in your browser. Output directories must already exist. Existing
reports are preserved; add `--force` only when you want to replace them. Keep
report outputs outside the scanned source directory when repeating scans.

For a single source file:

```sh
python post_quanten_scanner.py application.py --html application-report.html
```

## What each finding contains

- File, line, column, algorithm/library, category and detection method.
- A reason explaining **why it matched**, **why it received that classification**,
  **what remains unverified**, and the **next review step**.
- The original matching line, **five preceding and five following lines**, with
  line numbers and a marked hit. Fewer lines are shown at file boundaries.
- Selected literal parameters where supported; unknown key sizes remain unknown.

HTML uses responsive finding cards: location/category first, reasoning beside
captured details, and the numbered code excerpt below across the full width.
Narrow windows stack the panels. Long code lines scroll within their code box.
CLI help, console output, reasoning and standard HTML reports currently use German;
this README is English. JSON field identifiers are English.

## Exports and source context

The same scan can write **HTML**, **JSON** and **SARIF 2.1.0**. JSON uses the
scanner's schema **1.8**. SARIF includes the reasoning, the hit-line snippet,
standard `contextRegion`, and numbered `sourceContext` metadata. SARIF locations
use line numbers; parser byte offsets are not misrepresented as character columns.

Source context is captured during scanning. Exporting does not reopen the source
files, so the report keeps the scanned snapshot.

**Code excerpts are unredacted. They can contain keys, passwords or other text
from nearby lines.** To explicitly omit them from console output and every export:

```sh
python post_quanten_scanner.py /path/to/project --no-source-context --sarif report.sarif --html report.html
```

Very long source lines are limited to 4,000 characters per excerpt row. The hit
line is centered around the finding where possible. Clipping and starting columns
are recorded and marked. File-level manifest positions show the file beginning;
they do not acquire a precise declaration line.

## Categories

| Category | Meaning |
| --- | --- |
| `migration_review` | Classical asymmetric cryptography such as RSA, DH, DSA or ECC needs PQ migration review |
| `classical_weakness` | MD5/SHA-1 require purpose-specific classical security review; not a specific PQ migration finding |
| `context_review` | Symmetric ciphers, hashes or selected KDFs require parameter/context review; not automatically quantum-insecure |
| `pqc_reference` | A PQC name was recognized, not a secure-implementation or compliance certificate |
| `legacy_pqc_reference` | Verify the exact pre-standard/family name and algorithm revision |
| `dependency_review` | A cataloged cryptography package was declared; installation/use is unverified |

The embedded dependency inventory covers selected Python requirements/constraints,
PEP 621 `pyproject.toml`, Pipfile.lock, npm package.json/package-lock.json and Maven
pom.xml declarations. It does not install packages, resolve a complete dependency
graph or check CVEs. Composer, Bundler, Cargo, Go modules and Dart pubspec dependency
inventories are not included. Source scanning for those languages still works.

## Useful options

```sh
# Python source plus supported Python manifests:
python post_quanten_scanner.py /path/to/project --python-only --html python.html

# Source detection without dependency-declaration inventory:
python post_quanten_scanner.py /path/to/project --no-dependencies

# Repeatable relative exclusions and a larger per-file limit:
python post_quanten_scanner.py /path/to/project --exclude "tests/*" --exclude "generated/*" --max-file-kb 5000

# Manual planning context; no network/protocol scan:
python post_quanten_scanner.py /path/to/project --risk-context high --protocol-context tls --html review.html

# Help and version:
python post_quanten_scanner.py --help
python post_quanten_scanner.py --version
```

Default file limit: 2,000 decimal KB. Typical build/VCS/dependency folders are
excluded, including `.git`, `build`, `dist`, `target`, `node_modules`, `vendor`
and `.venv`. Symbolic links and recognized Windows junctions are skipped.
`.gitignore` is not interpreted. Other than Python encoding declarations, source
files must be UTF-8. Inspect coverage counts, skipped files and analysis errors.

## Exit codes

- `0`: at least one file analyzed without errors, unless a configured gate matches.
- `1`: a `--fail-on` gate matched. Choices: `migration`, `legacy`, `advisory`,
  `dependency`, `any`. Inventory findings can also trigger `any`.
- `2`: input/output or analysis error, or no analyzable files; takes precedence
  over gates. Skipped/unsupported files alone do not automatically cause exit 2.

```sh
python post_quanten_scanner.py /path/to/project --fail-on migration --sarif report.sarif
```

## Limits and reference profile

Cryptography detection only: no SQL injection, XSS, general command injection,
framework-security, memory-safety or complete application-security assessment.
Static matches do not prove execution, correct key strength, secure parameters,
protocol integration, BSI compliance or post-quantum readiness. An empty report
is not evidence of safety. Hardcoded secrets, IV reuse and password-storage design
are not systematically detected.

The embedded BSI/TR reference profile remains the previously reviewed snapshot
recorded in the script, with source versions and hashes (review date 2026-10-23).
It is not automatically updated. Manual risk/protocol selections add planning
notes, not an assessment of applicability or a compliance decision. The scanner
is not issued or certified by BSI. Original BSI PDFs are not bundled.

The 0.10 standalone engine passed the same 245 regression tests as the modular
project on Windows/Python 3.12.14. SARIF exports were checked against the official
2.1.0 schema. The test files are intentionally not part of this compact edition.



