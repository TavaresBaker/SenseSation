#!/bin/sh

# pfSense - Safe Non-Native User Deletion Script

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

    USER_LIST="$USER_LIST$USER\n"
    INDEX=$((INDEX + 1))
done

echo "Enter the number of the user you want to delete (press Enter for none): "
read -r USER_NUMBER

if [ -n "$USER_NUMBER" ] && echo "$USER_NUMBER" | grep -qE '^[0-9]+$'; then
    DELETE_USER=$(echo -e "$USER_LIST" | sed -n "${USER_NUMBER}p" | xargs)

    if [ -z "$DELETE_USER" ]; then
        echo "Invalid selection."
        exit 1
    fi

    echo "Selected user for deletion: $DELETE_USER"

    echo "Backing up current config to $BACKUP_XML..."
    cp "$USER_XML" "$BACKUP_XML"

    echo "Removing user '$DELETE_USER'..."

    # Escape special regex characters in username
    ESCAPED_USER=$(printf '%s\n' "$DELETE_USER" | sed 's/[][\.*^$(){}?+|/]/\\&/g')

    # Delete the <user> block with <name> matching the selected username
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
    ' "$BACKUP_XML" > "$USER_XML"

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

    echo "Reloading pfSense config..."
    /etc/rc.reload_all

    echo "User '$DELETE_USER' and associated directories successfully removed and config reloaded."
else
    echo "No user deleted."
fi

echo "=== End of Report ==="
