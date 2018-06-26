#!/bin/sh
trap clean EXIT
cd "$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)/../.." || exit 1
# shellcheck source=../functions.sh
. ./examples/functions.sh

usage() {
	cat >&2 <<-__EOF__
		${program} ${program_version} - run a ykstack 2 nodes cluster and test it
		Usage: ${program} [-qhe]
		Options:
		  -q, --quiet    Disable the messages
		  -h, --help     Show this help
	__EOF__
}

keys() {
	msg "generating keys"
	openssl req \
		-newkey rsa:2048 -nodes -x509 -days 365 \
		-keyout ./examples/ykstack/ykstack.key -out ./examples/ykstack/ykstack.crt \
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
	sqlite3 -echo ./examples/ykstack/ykksm.1.db | sqlite3 ./examples/ykstack/ykksm.2.db

	cat <<- EOF |
		$(cat "./assets/sql/sqlite/ykval.sql")

		-- 1381096070 == "Sun, 06 Oct 2013 21:47:50 GMT"
		INSERT INTO clients (id, active, created, secret, email, notes, otp)
		VALUES (1, 1, 1381096070, "Zm9vYmFyYmF6cXV4", "foo@bar.qux", "", "");

		INSERT INTO yubikeys (
			active, created, modified, yk_publicname, yk_counter, yk_use, yk_low,
			yk_high, nonce, notes
		) VALUES (1, 1381096070, 1381096070,"dteffuje", 19, 10, 49710, 0, "", "");

		UPDATE yubikeys SET modified=$(date +%s);
	EOF
	sqlite3 -echo ./examples/ykstack/ykval.1.db | sqlite3 ./examples/ykstack/ykval.2.db

	cat <<- EOF |
		$(cat "./assets/sql/sqlite/ykauth.sql")

		INSERT INTO users (id, name, auth)
		VALUES (1, "foo", "\$5\$1b/ajASUCW80P5df\$4oFYMblvPos5droMikkC8c.HZvKhHBwtsi9xYeyP.y5");

		INSERT INTO yubikeys (id, prefix, enabled) VALUES (1, "dteffuje", 1);

		INSERT INTO user_yubikeys (user_id, yubikey_id) VALUES (1, 1);
	EOF
	sqlite3 -echo ./examples/ykstack/ykauth.1.db | sqlite3 ./examples/ykstack/ykauth.2.db
}

config() {
	keys
	dbs
	msg "generating config file"
	cat > ./examples/ykstack/ykstack.1.toml <<- EOF
		debug = true

		[tls]
		port = 8443
		cert_file = "./examples/ykstack/ykstack.crt"
		key_file = "./examples/ykstack/ykstack.key"

		[[ykksm.retrievers]]
		name = "hex"

		[ykksm.sqlite]
		file = "./examples/ykstack/ykksm.1.db"

		[ykval]
		servers = [
		    "http://localhost:8081/wsapi/sync"
		]

		[ykval.sqlite]
		file = "./examples/ykstack/ykval.1.db"

		[ykauth]
		client_id = 1
		timeout = 5
		sync_level = "100%"

		[ykauth.sqlite]
		file = "./examples/ykstack/ykauth.1.db"
	EOF

	cat > ./examples/ykstack/ykstack.2.toml <<- EOF
		debug = true
		port = 8081

		[[ykksm.retrievers]]
		name = "hex"

		[ykksm.sqlite]
		file = "./examples/ykstack/ykksm.2.db"

		[ykval]
		servers = [
		"https://localhost:8443/wsapi/sync"
		]

		[ykval.sqlite]
		file = "./examples/ykstack/ykval.2.db"

		[ykauth]
		client_id = 1

		[ykauth.sqlite]
		file = "./examples/ykstack/ykauth.2.db"
	EOF
}

clean() {
	rm -f ./examples/ykstack/ykksm.*  ./examples/ykstack/ykval.* \
		./examples/ykstack/ykauth.* ./examples/ykstack/ykstack.*
}

clean
if ! args=$(getopt -o qh --long quiet,help -n "$program" -- "$@"); then
	usage
	exit 2
fi
eval set -- "$args"
while true; do
	case $1 in
		-q|--quiet) quiet=1;; # suppresses msg
		-h|--help)  usage; exit;;
		--)         shift; break;;
		*)          exit 1;; # getopt error
	esac
	shift
done

enable_colors
config
make || exit 1

msg "starting server"
./yubistack --config ./examples/ykstack/ykstack.1.toml &
pid_1=$!

./yubistack --config ./examples/ykstack/ykstack.2.toml &
pid_2=$!
sleep 2

code=$(curl -k -s -w "%{http_code}" -o /dev/stderr -H "Accept:application/json" \
	"https://localhost:8443/wsapi/authenticate?otp=dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh&username=foo&password=bar" )

# Clean up
kill ${pid_1} ${pid_2}

[ "$code" -eq 200 ] && exit 0 || exit 1
