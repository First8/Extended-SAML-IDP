# Keycloak Git Branch Diff & Patch Tool

This script is designed to work **specifically with the [Keycloak Git repository](https://github.com/keycloak/keycloak)**. It compares selected Java files between two branches of the Keycloak repo, generates a patch, and (optionally) applies that patch to a target directory.

## Features

- Clones the Keycloak repository into a temporary **.work** directory
- Extracts only files listed in `keycloak-files.txt` (tailored for Keycloak source paths)
- Compares two branches and creates a **unified diff patch**
- Cleans up file paths and replaces package names in the patch for project-specific needs
- Optionally applies the patch to the **parent directory** of the current folder

## Requirements

- **Bash** (Unix/Linux/macOS environment)
- **git** installed and configured
- Access to the Keycloak repository (SSH key if private)
- A `keycloak-files.txt` file in the current directory containing relative file paths from the Keycloak repo

## Usage

This first command is only necessary for Windows users:
```bash
dos2unix keycloak-files.txt #If this doesn't work, try:  sed -i $'s/\r$//' keycloak-files.txt
```

The main command is:

```bash
./patch.sh [--apply] OLD_BRANCH NEW_BRANCH
```

***Note: The patch process will ask for your SSH passhprase many times***

### Arguments

* `OLD_BRANCH` – The base branch in the Keycloak repo (e.g., `archive/release/27.0`)
* `NEW_BRANCH` – The comparison branch in the Keycloak repo (e.g., `archive/release/27.1`)
* `--apply` – Optional flag to **apply** the generated patch to the parent directory

### Examples

Generate patch without applying:

```bash
./patch.sh release/26.0 archive/release/26.1
```

Generate and apply patch:

```bash
./patch.sh --apply release/26.0 archive/release/26.1
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
| Clone Keycloak repository   |
| into .work/repo             |
+-----------------------------+
              |
              v
+-----------------------------+
| Validate branches           |
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

* Generated patch file: `.work/patch.patch`
* Temporary exported files in `.work/files/old` and `.work/files/new`

## Notes

* The `.work` directory is deleted and recreated on each run to ensure a clean workspace.
* The script exits immediately on any error (`set -e`).
* Missing files on either branch will be reported but won’t stop the script.
* Patch is applied **only** if the `--apply` option is specified.
* Because of Windows' file name(-path) limit, it is recommended to give this repository a short name and put it close to your file system's root, otherwise the nested files in `.work` will be too long.

