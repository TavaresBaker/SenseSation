#!/bin/sh

# pfSense - Safe Non-Native User Deletion Script (Multi-Delete)

DEFAULT_USERS="admin"
USER_XML="/conf/config.xml"
BACKUP_XML="/conf/config.xml.bak"
USER_DIRS="/home /usr/local/etc"  # Directories to check and delete user directories from

echo "===[ pfSense Non-Native Users Report ]==="
echo ""

# Extract all users
ALL_USERS=$(xmllint --xpath '//user/name/text()' "$USER_XML" 2>/dev/null)

USER_LIST=""
INDEX=1

echo "Found users:"
for USER in $ALL_USERS; do
    if echo "$DEFAULT_USERS" | grep -qw "$USER"; then
        continue
    fi

    echo "$INDEX) Username: $USER"

    GROUPS=$(xmllint --xpath "string(//user[name='$USER']/groups/item)" "$USER_XML" 2>/dev/null)
    [ -z "$GROUPS" ] && GROUPS="(none)"

    DESC=$(xmllint --xpath "string(//user[name='$USER']/descr)" "$USER_XML" 2>/dev/null)
    [ -z "$DESC" ] && DESC="(no description)"

    echo "   Groups: $GROUPS"
    echo "   Description: $DESC"
    echo ""

    USER_LIST="${USER_LIST}${USER}\n"
    INDEX=$((INDEX + 1))
done

TOTAL_USERS=$((INDEX - 1))

if [ "$TOTAL_USERS" -le 0 ]; then
    echo "No non-default users found."
    echo "=== End of Report ==="
    exit 0
fi

echo "Enter user number(s) to delete:"
echo "  - Examples: 1 3 5   OR   1,3,5"
echo "  - Type: all   (delete all listed users)"
echo "Press Enter for none: "
read -r USER_SELECTION

[ -z "$USER_SELECTION" ] && echo "No user deleted." && echo "=== End of Report ===" && exit 0

# Normalize input: commas -> spaces, collapse extra whitespace
USER_SELECTION=$(echo "$USER_SELECTION" | tr ',' ' ' | tr -s ' ')

# Backup once
echo "Backing up current config to $BACKUP_XML..."
cp "$USER_XML" "$BACKUP_XML" || { echo "Backup failed. Aborting."; exit 1; }

# Function: delete a single user from XML + dirs
delete_one_user() {
    DELETE_USER="$1"
    echo ""
    echo "Removing user '$DELETE_USER'..."

    # Escape special regex characters in username (for awk regex match safety)
    ESCAPED_USER=$(printf '%s\n' "$DELETE_USER" | sed 's/[][\.*^$(){}?+|/]/\\&/g')

    # Write to a temp file first to avoid partially-written config on failure
    TMP_XML="/tmp/config.xml.$$"

    awk -v user="$ESCAPED_USER" '
    BEGIN { in_block = 0; block = "" }
    /<user>/ { in_block = 1; block = $0 ORS; next }
    /<\/user>/ {
        block = block $0 ORS;
        if (block ~ "<name>" user "</name>") {
            in_block = 0;
            block = "";
            next;  # skip writing this user block
        } else {
            printf "%s", block;
            in_block = 0;
            block = "";
            next;
        }
    }
    {
        if (in_block) {
            block = block $0 ORS;
        } else {
            print;
        }
    }
    ' "$USER_XML" > "$TMP_XML" || { echo "Failed updating XML for $DELETE_USER"; rm -f "$TMP_XML"; return 1; }

    mv "$TMP_XML" "$USER_XML" || { echo "Failed writing config.xml for $DELETE_USER"; rm -f "$TMP_XML"; return 1; }

    # Remove the user's home directories from the specified locations
    echo "Removing directories associated with '$DELETE_USER'..."
    for DIR in $USER_DIRS; do
        USER_DIR_PATH="$DIR/$DELETE_USER"
        if [ -d "$USER_DIR_PATH" ]; then
            echo "Removing directory: $USER_DIR_PATH"
            rm -rf "$USER_DIR_PATH"
        else
            echo "No directory found for user in $DIR"
        fi
    done

    echo "User '$DELETE_USER' removed."
    return 0
}

# Build list of users to delete
TO_DELETE_USERS=""

if [ "$USER_SELECTION" = "all" ]; then
    # all non-default users
    TO_DELETE_USERS=$(echo -e "$USER_LIST" | sed '/^[[:space:]]*$/d')
else
    # validate and map numbers -> usernames
    for N in $USER_SELECTION; do
        if ! echo "$N" | grep -qE '^[0-9]+$'; then
            echo "Invalid input token: '$N' (must be numbers or 'all')"
            exit 1
        fi
        if [ "$N" -lt 1 ] || [ "$N" -gt "$TOTAL_USERS" ]; then
            echo "Selection out of range: $N (valid: 1-$TOTAL_USERS)"
            exit 1
        fi

        U=$(echo -e "$USER_LIST" | sed -n "${N}p" | xargs)
        [ -z "$U" ] && echo "Failed to resolve user #$N" && exit 1

        # dedupe (avoid deleting same user twice)
        echo "$TO_DELETE_USERS" | grep -qw "$U" || TO_DELETE_USERS="$TO_DELETE_USERS $U"
    done
fi

echo ""
echo "Selected user(s) for deletion:"
for U in $TO_DELETE_USERS; do
    echo " - $U"
done

# Delete each selected user
FAIL=0
for U in $TO_DELETE_USERS; do
    # Extra safety: never delete defaults
    if echo "$DEFAULT_USERS" | grep -qw "$U"; then
        echo "Skipping default/protected user: $U"
        continue
    fi
    delete_one_user "$U" || FAIL=1
done

echo ""
echo "Reloading pfSense config..."
/etc/rc.reload_all

if [ "$FAIL" -eq 0 ]; then
    echo "All selected users removed and config reloaded."
else
    echo "Some deletions failed (config reloaded anyway). Review output above."
    echo "Backup is at: $BACKUP_XML"
fi

echo "=== End of Report ==="
