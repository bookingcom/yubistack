Testing Yubistack
=================

__All commands are launched from current directory!__

__Setup a list of servers:__

```bash
SERVERS="$(cat <<EOF
server-1.foo.bar
server-2.foo.bar
EOF
)"
```

__Compile and send:__ 

```bash
CGO_ENABLED=0 make -C .. && \
	echo "$SERVERS" | while read -r server; do scp "${GOBIN}/yubistack" "${server}:" ; done
```

__Start tunneling:__

```bash
go run cmd/tunnel/tunnel.go -c "$(echo "$SERVERS" | sed -ne 's|$|:3306&|p' | sed ':a;N;$!ba;s|\n|,|g')"
```


__Sending config:__

```bash
echo "$SERVERS" | while read -r server; do 
	cat <<- EOF | ssh "${server}" dd of=config.toml
		debug = true

		servers = [
			$(echo "$SERVERS" | sed "/$server/d" | sed -ne 's|$|:8080/wsapi/sync",&|p' | sed -ne 's|^|&    "http://|p')
		]

		[ksm.mysql]
		host = "0.0.0.0"
		port = 3306
		name = "ykksm"
		user = "root"
		password = "some_password"

		[ykval.mysql]
		host = "0.0.0.0"
		port = 3306
		name = "ykval"
		user = "root"
		password = "some_password"
	EOF
done
```


__Benchmarking:__

```bash
go run cmd/populate/populate.go -w 50 -c $(echo "${SERVERS}" | wc -l) -k 1000 | \
	go run cmd/benchmark/benchmark.go -c "$(echo "${SERVERS}" | sed -ne 's|$|:8080&|p' | sed ':a;N;$!ba;s|\n|,|g')"
```

