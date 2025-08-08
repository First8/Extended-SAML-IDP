#!/bin/bash

set -e

APPLY_PATCH=false

usage() {
    echo "Usage: $0 [--apply] OLD_BRANCH NEW_BRANCH"
    echo "  --apply    Apply patch to parent directory after generation"
    exit 1
}

# Parse options
while [[ "$1" == --* ]]; do
    case "$1" in
        --apply)
            APPLY_PATCH=true
            shift
            ;;
        *)
            usage
            ;;
    esac
done

if [ $# -ne 2 ]; then
    usage
fi

OLD_BRANCH="$1"
NEW_BRANCH="$2"

GIT_REPO_URL="git@github.com:keycloak/keycloak.git"
WORK_DIR="$(pwd)/.work"
REPO_DIR="$WORK_DIR/repo"
OLD_DIR="$WORK_DIR/files/old"
NEW_DIR="$WORK_DIR/files/new"
PATCH_FILE="$WORK_DIR/patch.patch"
FILES_LIST="$(pwd)/keycloak-files.txt"

echo "=== Git Diff Generator ==="
echo "Repository : $GIT_REPO_URL"
echo "Old branch : $OLD_BRANCH"
echo "New branch : $NEW_BRANCH"
echo "Work dir   : $WORK_DIR"
echo "Apply patch: $APPLY_PATCH"

# Ensure keycloak-files.txt exists
if [ ! -f "$FILES_LIST" ]; then
    echo "Error: $FILES_LIST not found in $(pwd)"
    exit 1
fi

# Read file list into array
FILES=()
while IFS= read -r line; do
    [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
    FILES+=("$line")
done < "$FILES_LIST"

# Prepare work directory
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR" "$OLD_DIR" "$NEW_DIR"

echo "Cloning repository..."
git clone "$GIT_REPO_URL" "$REPO_DIR"

# Validate branches exist
for BRANCH in "$OLD_BRANCH" "$NEW_BRANCH"; do
  if ! git -C "$REPO_DIR" ls-remote --exit-code --heads origin "$BRANCH" > /dev/null; then
    echo "Error: Branch '$BRANCH' does not exist in remote repository."
    exit 1
  fi
done

echo "Exporting files..."
for FILE in "${FILES[@]}"; do
    mkdir -p "$OLD_DIR/$(dirname "$FILE")"
    git -C "$REPO_DIR" show "$OLD_BRANCH:$FILE" > "$OLD_DIR/$FILE" 2>/dev/null || echo "Missing in $OLD_BRANCH: $FILE"

    mkdir -p "$NEW_DIR/$(dirname "$FILE")"
    git -C "$REPO_DIR" show "$NEW_BRANCH:$FILE" > "$NEW_DIR/$FILE" 2>/dev/null || echo "Missing in $NEW_BRANCH: $FILE"
done

echo "File count (.java only):"
echo "  $OLD_BRANCH: $(find "$OLD_DIR" -type f -name '*.java' | wc -l)"
echo "  $NEW_BRANCH: $(find "$NEW_DIR" -type f -name '*.java' | wc -l)"

echo "Creating patch..."
diff --color=never -ruN "$OLD_DIR" "$NEW_DIR" > "$PATCH_FILE" || true

# Post-process diff
safe_sed() {
    sed "$1" "$2" > "$2.tmp" && mv "$2.tmp" "$2"
}

safe_sed "s|$OLD_DIR/saml-core/||g" "$PATCH_FILE"
safe_sed "s|$NEW_DIR/saml-core/||g" "$PATCH_FILE"
safe_sed "s|$OLD_DIR/services/||g" "$PATCH_FILE"
safe_sed "s|$NEW_DIR/services/||g" "$PATCH_FILE"
safe_sed 's|org/keycloak/|nl/first8/keycloak/|g' "$PATCH_FILE"

echo "Patch created at: $PATCH_FILE"

if [ "$APPLY_PATCH" = true ]; then
    echo "Applying patch to parent directory: $(dirname "$(pwd)")"
    patch -d "$(dirname "$(pwd)")" < "$PATCH_FILE"
    echo "Patch applied successfully."
fi
