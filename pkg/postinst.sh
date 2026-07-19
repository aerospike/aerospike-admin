#!/bin/sh
# Create /etc/aerospike/astools.conf from the packaged sample when no config
# exists yet. The live file is deliberately NOT owned by this package so the
# standalone tools and the aerospike-tools bundle can coexist without
# package-manager conflicts over the path. Existing files (the bundle's
# conffile, user edits) are never touched.
#
# Wired as BOTH --after-install and --after-upgrade in pkg/Makefile: on deb,
# fpm routes an install-only script into an after_upgrade() that never runs on
# upgrade or reinstall, so both hooks are required for the file to be seeded
# for users upgrading an already-installed package.
conf=/etc/aerospike/astools.conf
sample=/opt/aerospike/doc/asadm/astools.conf.sample

if [ ! -e "$conf" ] && [ ! -L "$conf" ] && [ -f "$sample" ]; then
    if install -D -m 644 "$sample" "$conf" 2>/dev/null; then
        [ -x /sbin/restorecon ] && /sbin/restorecon "$conf" 2>/dev/null
    else
        echo "warning: could not create $conf (sample at $sample)" >&2
    fi
fi
exit 0
