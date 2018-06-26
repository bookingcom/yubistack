#!/bin/sh

trap clean EXIT
cd "$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)/../.." || exit 1
# shellcheck source=../functions.sh
. ./examples/functions.sh

config=

usage() {
	cat >&2 <<-__EOF__
		${program} ${program_version} - run a ykval standalone server and test it
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
		-keyout ./examples/ykval/ykval.key -out ./examples/ykval/ykval.crt \
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
	sqlite3 ./examples/ykval/ykksm.db

	cat <<- EOF |
		$(cat "./assets/sql/sqlite/ykval.sql")

		-- 1381096070 == "Sun, 06 Oct 2013 21:47:50 GMT"
		-- printf "foo" |  base64
		INSERT INTO clients (id, active, created, secret, email, notes, otp)
		VALUES (1, 1, 1381096070, "Zm9v", "foo@bar.qux", "", "");

		INSERT INTO yubikeys (
			active, created, modified, yk_publicname, yk_counter,
			yk_use, yk_low, yk_high, nonce, notes
		) VALUES (1, 1381096070, 1381096070,"dteffuje", 19, 10, 49710, 0, "", "");

		UPDATE yubikeys SET modified=$(date +%s);
	EOF
	sqlite3 ./examples/ykval/ykval.db
}

config() {
	keys
	dbs
	msg "generating config file"
	cat > ./examples/ykval/ykval.toml <<- EOF
		debug = true

		[[ykksm.retrievers]]
		name = "hex"

		[ykksm.sqlite]
		file = "./examples/ykval/ykksm.db"

		[ykval.sqlite]
		file = "./examples/ykval/ykval.db"

		[tls]
		port = 8081
		cert_file = "./examples/ykval/ykval.crt"
		key_file = "./examples/ykval/ykval.key"
	EOF

}

clean() {
	test -n "$config" && return 0
	rm -f ./examples/ykval/ykksm.*  ./examples/ykval/ykval.*
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
make yubival || exit 1

msg "starting server"
./yubival --config ./examples/ykval/ykval.toml &
gopid=$!
sleep 2

msg "testing endpoint"
# echo -n "id=1&nonce=gsgiiftz8lc8lxaa&otp=dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh&timestamp=1" \
#      | openssl dgst -sha256 -hmac "foo" -binary | base64
code=$(curl -k -s -o /dev/stderr -w "%{http_code}" \
	"https://localhost:8081/wsapi/verify?otp=dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh&id=1&nonce=gsgiiftz8lc8lxaa&timestamp=1&hash=4qh8RI0V2gsUSRXdBKQSmcMzivzCPJ8gc1iYdwIpx78=")

kill $gopid
[ "$code" -eq 200 ] && exit 0 || exit 1
