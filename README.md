Yubistack
=========

This is a Golang implementation of the Yubico second factor authentication stack.
Yubistack aimed to perform Yubikey (see [wiki](https://en.wikipedia.org/wiki/YubiKey)) token validation.

You can check [Yubico website](https://www.yubico.com) for information about what is a
[Yubikey](https://www.yubico.com/getstarted/meet-the-yubikey/) or
[how to get one](https://www.yubico.com/support/shipping-and-buying-information/).

Getting started
---------------

In order to be able to develop on this project and run the various examples you
need to have the following tool installed in your environment:

- [git](https://git-scm.com/)
- [go toolchain](https://golang.org/doc/install), starting from version 1.11
as the project is using the newly introduced
[modules feature](https://github.com/golang/go/wiki/Modules).
- [make](https://www.gnu.org/software/make/)

In order to run the examples you will additionally require:

- [sqlite](https://www.gnu.org/software/make/)
- [curl](https://curl.haxx.se/)

Due to the fact that this program manipulate sensible data (yubikeys aes key)
it is highly recommended to use the samples data provided in order to avoid
potential leaks.

A good way to start using this project is to run the examples from the
[examples](./examples) directory. There is a make target `make examples` which
will run those in proper order.

Another entrypoint would be to check the [test](./test) directory, which contains
programs to benchmark the yubistack authentication flow.

Build and run
--------------

You can run a simple development server by issuing the following commands:

- clone this repository: `git clone gitlab.booking.com/pps/yubistack`
- build the YK-Val module: `make ykval`
- generate a proper configuration: `./examples/ykval/run.sh --only-config`
- run it with `./ykval --config=./examples/ykval/ykval.toml`

Once this is running you can test if it works using this `curl` example:
`curl -k -s https://localhost:8081/wsapi/verify?otp=dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh&id=1&nonce=gsgiiftz8lc8lxaa&timestamp=1&hash=4qh8RI0V2gsUSRXdBKQSmcMzivzCPJ8gc1iYdwIpx78=`


```bash
# First create and populate a sqlite3 databases
cat assets/sql/sqlite/ykksm.sql examples/ykval/ykksm.sql | sqlite3 ykksm.db
cat assets/sql/sqlite/ykval.sql examples/ykval/ykval.sql | sqlite3 ykval.db
echo "UPDATE yubikeys SET modified=$(date +%s)" | sqlite3 ykval.db

# You can now start the server
go run cmd/yubistack/main.go --config examples/ykval/config.toml

# Once this is done you can try to authenticate
http -vv "http://localhost:8080/wsapi/verify?otp=dteffujehknhfjbrjnlnldnhcujvddbikngjrtgh&id=1&nonce=gsgiiftz8lc8lxaa&timestamp=1"
```

Modular components
-------------------

Following Yubico implementation the Yubistack project is built around three
components:

- ykksm: is the Yubikey Key Storage Module (YK-KSM), it holds the AES keys of
	the yubikeys and is responsible for the crypto part of the authentication protocol.
- ykval: is the Yubikey Validation module (YK-VAL), this module is responsible
	for validating tokens and handle the consensus flow.
- ykauth: is the last module responsible for authentication of the user.
	it supports adding a PIN in front of a token and validating it against a
	database, it then delegates token  validation to the ykval module.

For more information about the architecture design, the protocol and how
everything is plug together in Yubistack, check out the [design documentation](./docs/design.md).


Background and Yubico API differences
-------------------------------------

Yubistack project was started in an attempt to bring reliability and security to our
critical infrastructure. At Booking.com we are enhancing security by requiring  second
factor authentication. Employees can use Yubikeys to issue a token we then validate to
provide access.

Yubico is already providing a reference implementation on their GitHub. However,
we did not consider it suitable for various reasons: the setup was not clear,
we could not easily discern how things fit together, it was not easy to integrate
it within our infrastructure (metrics, logs, and packaging), the
documentation was lacking, and we needed a more capable API.

You can see a more detailed description of the choices we made in
[the design documentation](./docs/design.md)

Licence
-------

Apache-2.0 License, see [LICENSE](./LICENSE)

Acknowledgment
--------------

This software was originally developed at [Booking.com](http://www.booking.com).
With approval from [Booking.com](http://www.booking.com), this software was released
