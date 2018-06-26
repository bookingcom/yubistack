#!/bin/sh
export quiet=
export program=${0##*/}
export program_version=0.1.0


print() { [ -n "$quiet" ] && return 0 || printf "${1} %s\n" "$2" >&2; }
msg() { print "$GREEN>>>${NORMAL}" "$1"; }
warning() { print "${YELLOW}>>> WARNING:${NORMAL}" "$1"; }
warning2() { print "	${YELLOW}>>> ${NORMAL}" "$1"; }
error() { print "${RED}>>> ERROR:${NORMAL}" "$1"; }
die() { error "$1"; exit 1; }
enable_colors() {
	NORMAL="\033[1;0m"
	RED="\033[1;31m"
	GREEN="\033[1;32m"
	YELLOW="\033[1;33m"
}

