Documentation table of content
==============================

This directory contains more in-depth documentation of Booking Yubistack
implementation.

Here is what you can find here:

- [The swagger file](./swagger.yaml) describing the API
- Some [SQL requests examples](./requests.md) to query the databases.
	This could help you administrate and extract information from the cluster.
- [The algorithm](./delayed.md) of how token time expirity is computed.
	__DISCLAIMER:__ For reliability reason this feature has been unplugged,
	check the doc for an explanation.
- [The design of Yubistack service](./design.md), it explains how component
	are discussing together, where the code lives and what is the flow of a request.
