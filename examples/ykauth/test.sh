#!/bin/sh
trap clean EXIT
cd "$(CDPATH="" cd -- "$(dirname -- "$0")" && pwd)/../.." || exit 1
# shellcheck source=../functions.sh
. ./examples/functions.sh


keys() {
	msg "generating keys"
	openssl req \
		-newkey rsa:2048 -nodes -x509 -days 365 \
		-keyout ./examples/ykauth/ykauth.key -out ./examples/ykauth/ykauth.crt \
		-subj "/C=NL/ST=Randstad/L=Amsterdam/O=Booking/CN=yubistack.booking.com"

}

dbs() {
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
	sqlite3 ./examples/ykauth/ykksm.db

	cat <<- EOF |
		$(cat "./assets/sql/sqlite/ykval.sql")

		-- 1381096070 == "Sun, 06 Oct 2013 21:47:50 GMT"
		INSERT INTO clients (id, active, created, secret, email, notes, otp)
		VALUES (1, 1, 1381096070, "Zm9vYmFyYmF6cXV4", "foo@bar.qux", "", "");

		INSERT INTO yubikeys (
			active, created, modified, yk_publicname, yk_counter,
			yk_use, yk_low, yk_high, nonce, notes
		) VALUES (1, 1381096070, 1381096070,"dteffuje", 19, 10, 49710, 0, "", "");

		UPDATE yubikeys SET modified=$(date +%s);
	EOF
	sqlite3 ./examples/ykauth/ykval.db

	cat <<- EOF |
		$(cat "./assets/sql/sqlite/ykauth.sql")

		INSERT INTO users (id, name, auth)
		VALUES (1, "foo", "\$5\$1b/ajASUCW80P5df\$4oFYMblvPos5droMikkC8c.HZvKhHBwtsi9xYeyP.y5");

		INSERT INTO yubikeys (id, prefix, enabled) VALUES (1, "dteffuje", 1);

		INSERT INTO user_yubikeys (user_id, yubikey_id) VALUES (1, 1);
	EOF
	sqlite3 ./examples/ykauth/ykauth.db
}

config() {
	keys
	dbs
	msg "generating config file"
	cat > ./examples/ykauth/ykauth.toml <<- EOF
		debug = true

		[[ykksm.retrievers]]
		name = "hex"

		[ykksm.sqlite]
		file = "./examples/ykauth/ykksm.db"

		[ykval.sqlite]
		file = "./examples/ykauth/ykval.db"

		[ykauth]
		client_id = 1

		[ykauth.sqlite]
		file = "./examples/ykauth/ykauth.db"

		[tls]
		port = 8081
		cert_file = "./examples/ykauth/ykauth.crt"
		key_file = "./examples/ykauth/ykauth.key"
	EOF

}

clean() {
	rm -f ./examples/ykauth/ykksm.*  ./examples/ykauth/ykval.* ./examples/ykauth/ykauth.*
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
./yubistack --config ./examples/ykauth/ykauth.toml &
gopid=$!
sleep 2

msg "testing endpoint"
code=$(curl -k -s -o /dev/stderr -w "%{http_code}" \
	"https://localhost:8081/wsapi/authenticate?otp=dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh&username=foo&password=bar")

kill $gopid
[ "$code" -eq 200 ] && exit 0 || exit 1
