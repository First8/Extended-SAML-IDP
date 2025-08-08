
# Git Branch Diff & Patch Tool

This script compares specific files between two branches of a Git repository, generates a patch, and (optionally) applies that patch to a target directory.

## Features

- Clones a repository into a temporary **.work** directory  
- Extracts only files listed in `keycloak-files.txt`  
- Compares two branches and creates a **unified diff patch**  
- Cleans up paths and replaces package names in the patch  
- Optionally applies the patch to the **parent directory** of the current folder

## Requirements

- **Bash** (Unix/Linux/macOS environment)  
- **git** installed and configured  
- Access to the repository (SSH key if private)  
- A `keycloak-files.txt` file in the current directory containing the relative paths of files to compare

## Usage

```bash
./patch.sh [--apply] OLD_BRANCH NEW_BRANCH
```

### Arguments

* `OLD_BRANCH` – The base branch (e.g., `main`)
* `NEW_BRANCH` – The comparison branch (e.g., `feature-branch`)
* `--apply` – Optional flag to **apply** the generated patch to the parent directory

### Examples

Generate patch without applying:

```bash
./generate-patch.sh main feature-branch
```

Generate and apply patch:

```bash
./generate-patch.sh --apply main feature-branch
```

## How It Works

```plaintext
+-----------------------------+
| Start script                |
+-----------------------------+
              |
              v
+-----------------------------+
| Validate keycloak-files.txt |
+-----------------------------+
              |
              v
+-----------------------------+
| Clone Git repository        |
| into .work/repo             |
+-----------------------------+
              |
              v
+--------------------------------------+
| Export listed files from OLD_BRANCH  |
| to .work/files/old                   |
+--------------------------------------+
              |
              v
+--------------------------------------+
| Export listed files from NEW_BRANCH  |
| to .work/files/new                   |
+--------------------------------------+
              |
              v
+-----------------------------+
| Generate patch file          |
| .work/patch.patch            |
+-----------------------------+
              |
              v
+--------------------------------+
| Post-process patch (clean paths,|
| replace package names)          |
+--------------------------------+
              |
              v
+-----------------------------------------+
| If --apply flag set:                    |
| Apply patch to parent directory         |
+-----------------------------------------+
              |
              v
+-----------------------------+
| Script ends with patch ready|
+-----------------------------+
```

## Output

* Generated patch: `.work/patch.patch`
* Temporary files: `.work/files/old`, `.work/files/new`

## Notes

* The `.work` directory is removed and recreated on each run.
* The script exits on any error (`set -e`).
* Missing files in either branch are reported but do not stop execution.
* The patch is applied **only** if the `--apply` option is given.


