#!/bin/bash
set -eux
find . -name '*.warts' -print -exec bash -c 'i="$1"; sc_wartsdump "$1" > $(basename "$1" .warts).txt' shell {} \;
