#!/bin/bash
# TEST FIXTURE HELPER, not part of PodShield.
#
# Every pstest Containerfile builds on ubi-minimal and must trip exactly ONE PodShield rule.
# A stock ubi-minimal already trips PS-010 (setuid su/mount/...) and PS-015 (bash, microdnf),
# so each image calls this script twice around its single deliberate defect:
#
#   harden.sh clean    strip setuid/setgid bits and package-manager caches (before the defect)
#   harden.sh finish   remove shells and package managers, then delete this script
#                      (after the defect: once the shell is gone nothing else can RUN)
#
#   harden.sh finish --keep-shell    same, but leave the shells in place (the PS-015 image)
set -eu

mode="${1:?usage: harden.sh clean|finish [--keep-shell]}"
shift || true

case "$mode" in
  clean)
    shopt -s globstar dotglob nullglob
    for f in /etc/**/* /usr/**/* /var/**/* /opt/**/* /root/**/* /home/**/* /srv/**/*; do
      if [ -f "$f" ] && [ ! -L "$f" ] && { [ -u "$f" ] || [ -g "$f" ]; }; then
        chmod a-s -- "$f"
      fi
    done
    rm -rf /var/cache/dnf /var/cache/yum /var/cache/microdnf /var/cache/apt \
           /var/lib/apt/lists /var/cache/apk
    ;;
  finish)
    keep_shell=0
    [ "${1:-}" = "--keep-shell" ] && keep_shell=1
    rm -f -- /tmp/harden.sh   # bash keeps the open file; this just removes it from the image
    names="dnf yum microdnf rpm apt apt-get dpkg apk zypper pip pip3"
    if [ "$keep_shell" -eq 0 ]; then
      names="$names sh bash rbash dash zsh ksh csh tcsh fish ash"
    fi
    for dir in /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin; do
      for name in $names; do
        rm -f -- "$dir/$name"
      done
    done
    ;;
  *)
    echo "unknown mode: $mode" >&2
    exit 2
    ;;
esac
