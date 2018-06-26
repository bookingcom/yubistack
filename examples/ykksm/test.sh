#!/bin/sh

trap clean EXIT
cd "$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)/../.." || exit 1
# shellcheck source=../functions.sh
. ./examples/functions.sh

config=

usage() {
	cat >&2 <<-__EOF__
		${program} ${program_version} - run a ykksm standalone server and test it
		Usage: ${program} [-qhe] [--config-only]
		Options:
		  --only-config  Only generate config files and exits

		  -q, --quiet    Disable the messages
		  -h, --help     Show this help
	__EOF__
}

keys() {
	msg "generating keys"
	openssl req \
		-newkey rsa:2048 -nodes -x509 -days 365 \
		-keyout ./examples/ykksm/ykksm.key -out ./examples/ykksm/ykksm.crt \
		-subj "/C=NL/ST=Randstad/L=Amsterdam/O=Booking/CN=yubistack.booking.com"

}

dbs() {
	msg "generating databases"

	cat <<- EOF |
		$(cat "./assets/sql/sqlite/ykksm.sql")

		-- https://github.com/dgryski/go-yubiauth/blob/master/ksmd/test.sh
		INSERT INTO yubikeys (
			serialnr, publicname, created, internalname, aeskey, lockcode, creator,
			active, hardware
		) VALUES (
			1, "dteffuje", "Sun, 06 Oct 2013 21:47:50 GMT", "8792ebfe26cc",
			"ecde18dbe76fbd0c33330f1c354871db", "111111", "dgryski", 1, 1
		);
	EOF
	sqlite3 ./examples/ykksm/ykksm.db
}

config() {
	keys
	dbs
	msg "generating config file"
	cat > ./examples/ykksm/ykksm.toml <<- EOF
		debug = true

		[[retrievers]]
		name = "hex"

		[sqlite]
		file = "./examples/ykksm/ykksm.db"

		[tls]
		port = 8081
		cert_file = "./examples/ykksm/ykksm.crt"
		key_file = "./examples/ykksm/ykksm.key"
	EOF

}

clean() {
	test -n "$config" && return 0
	rm -f ./examples/ykksm/ykksm.*
}

clean
if ! args=$(getopt -o qh --long quiet,help,only-config -n "$program" -- "$@"); then
	usage
	exit 2
fi
eval set -- "$args"
while true; do
	case $1 in
		--only-config) config=1;;

		-q|--quiet) quiet=1;; # suppresses msg
		-h|--help)  usage; exit;;
		--)         shift; break;;
		*)          exit 1;; # getopt error
	esac
	shift
done

enable_colors
test -n "$config" && config && exit 0
config
make yubiksm || exit 1

msg "starting server"
./yubiksm --config ./examples/ykksm/ykksm.toml &
gopid=$!
sleep 2

msg "testing endpoint"
code=$(curl -k -s -o /dev/stderr -w "%{http_code}" \
	https://localhost:8081/wsapi/decrypt?otp=dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh)
kill $gopid
[ "$code" -eq 200 ] && exit 0 || exit 1
