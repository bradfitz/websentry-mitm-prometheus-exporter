# WebSentry Protocol description

As part of building my [WebSentry Prometheus Exporter](https://github.com/bradfitz/websentry-mitm-prometheus-exporter), I've been trying to figure out what protocol my Seresco NE unit is speaking out to its WebSentry cloud service.

The following is what I've been able to figure out from looking at the traffic
in different ways and changing settings and seeing what happens.

I've also been keeping logs of its traffic on & off for years so I can compare historical data.

**This is not an official protocol description**, clearly. It probably
differs by unit/board version, but I only have my unit to analyze, my NE-004 Board Version 7.0 running 5.15.12. That said, it's probably a similar protocol between the various https://dehumidifiedairsolutions.com brands that all speak WebSentry.

## Protocol flow

The dehumidifier unit connects to TCP port `websentry.seresco.net:1030` once a minute. Different brands might have different hostnames. There seems to only be one IP address and runs on AWS. It's probably an [NLB](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/introduction.html).

## Protocol message framing

All messages from client to server or server to client have a 7 byte header. The header is:

* 3 bytes: `x70 x83 x9e` (the only frame header I've ever seen)
* 2 byte checksum (TODO: which checksum?)
* 2 byte length (big endian) of the following payload

## Message types

The first byte of frame's payload is its type. Types seen are:

* `0x00`, "Init": Client-to-server initial message upon connect. Contains the unit's MAC address at least. Not sure hwat else.
* `0x02`, "Query": Server sends this to client to query a list of properties. Client also replies with this message type to reply.
* `0x03`, "Set": Server sends this to client to change a parameter when set from the https://apps.dehumidifiedairsolutions.com cloud control panel.
* `0x08`, unknown. Server sends a dozen of these after the queries and the client replies, but not sure what they are yet. TODO: figure these out.


## Client `Init` message

The protocol starts with the client sending a `0x00` init message. The message
contains the unit's MAC address but that's the only field I've recognized. It
probably also contains the version number of the software or at least some
indicator of the client's capabilities. It doesn't seem to contain the serial
number.

## Exchanges after init

After the client sends an init, the server can then send `Query`, `Set`, or `0x08` messages, each of which the client then replies to, with the same type.

## Server `Query` message

The server send `Query` (`0x02` prefixed) messages to ask the client unit about
a list of properties.

The payload, after the `0x02` byte, is repeated list of property IDs that the server is asking about it. Each property ID is a 16-bit number, followed by an `0x0f` byte. (So the total payload length is always a factor of 3)

For example, the server typically sends at start:

```
02 01 00 0f 01 01 0f 01 0e 0f 01 16 0f 02 81 0f 0c 01 0f 10 03 0f 10 0c 0f 10 10 0f 12 20 0f 01 02 0f 01 07 0f 01 08 0f 01 0b 0f 01 25 0f 01 36 0f
```

That's a query (type `0x02`) of properties `0x0100`, `0x0101`, `0x010e`, etc.

## Client `Query` response

To response to a server's `Query` request, the client sends a `0x02` message back, but instead of `0xf` replaced with a typed value.

That is, the format is:

```
0x02 ( [property_id] [typed_value] )*
```

From what I've seen, the replied values are always exactly the same order & count as the query; none are omitted and they're in the same order.

## Typed values

A typed value is a type byte, followed by a number of bytes, specific to the type.

The type bytes I've seen are:

### Variable width typed values

* `0x07`: variable length string. Followed by one byte of length, then that many length bytes of string. Usually strings like `Off`, `Disabled`, `Ready`, or version number or serial numbers.

### Fixed width typed values

* `0x01`: 1 byte
* `0x02`: 1 byte
* `0x03`: 2 byte
* `0x05`: 4 bytes of four numbers? used for verion number at least
* `0x06`: uint16 scaled by 10. Divide the uint16 by 10 to get the value (used for temperatures, humidity percent, ...)
* `0x08`: 7 bytes; often a stored setting of a few bytes and then ... something else
* `0x09`: 2 bytes
* `0x0a`: date: 4 bytes: year-1900, month, day, zero.
* `0x0b`: time: 4 bytes: hour, minute, seconds * 4, 0
* `0x0c`: 4 byte IP address (used for gateway, DNS server, resolved server IP, netmask, ...)
* `0x12`: 4 byte uint32. Used for serial number.

## Server `Set` message

The server can set properties on the client by sending a `Set` (`0x03`-prefixed) message containing a repeated list of property IDs and typed values.

The client replies with the property IDs and `0x00` for success. (Not sure what failure would look like.)

## List of properties

For now, see the `var propName` map at https://github.com/bradfitz/websentry-mitm-prometheus-exporter/blob/main/wmpe.go

TODO: generate docs here from one unified map of property IDs/names/types/enum vaues.

