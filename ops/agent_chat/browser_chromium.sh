#!/bin/sh
# Browser has no workspace, original files, outer process tree, network or home.
browser_bin=$(cat /skills/chromium-path)
exec bwrap --unshare-all --die-with-parent --new-session --clearenv \
  --ro-bind /usr /usr --ro-bind /bin /bin --ro-bind /lib /lib --ro-bind /lib64 /lib64 \
  --ro-bind /opt/ms-playwright /opt/ms-playwright --proc /proc --dev /dev \
  --ro-bind /etc/fonts /etc/fonts \
  --tmpfs /tmp --tmpfs /home --setenv HOME /tmp --setenv LANG C.UTF-8 \
  "$browser_bin" "$@"
