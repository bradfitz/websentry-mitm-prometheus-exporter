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

* 3 bytes: `0x70 0x83 0x9e` (the only frame header I've ever seen)
* 2 byte checksum (TODO: which checksum?)
* 2 byte length (big endian) of the following payload

## Message function codes

The first byte of frame's payload is its function code. Codes seen are:

* `0x00`, "Init": Client-to-server initial message upon connect. Contains the unit's MAC address at least. Not sure hwat else.
* `0x02`, "Query": Server sends this to client to query a list of properties. Client also replies with this message function code to reply.
* `0x03`, "Set": Server sends this to client to change a parameter when set from the https://apps.dehumidifiedairsolutions.com cloud control panel.
* `0x08`, unknown. Server sends a dozen of these after the queries and the client replies, but not sure what they are yet. TODO: figure these out.


## Client `Init` message

The protocol starts with the client sending a `0x00` init message. The message
contains the unit's MAC address but that's the only field I've recognized. It
probably also contains the version number of the software or at least some
indicator of the client's capabilities. It doesn't seem to contain the serial
number.

## Exchanges after init

After the client sends an init, the server can then send `Query`, `Set`, or `0x08` messages, each of which the client then replies to. The reply message has the same function code.

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
* `0x08`: 7 bytes; seems to be three uint16 values: the current value, minimum acceptable value, maximum acceptable value, and then 1 byte of the allowed granularity of the value. If the current value is zero (and less than the minimum value), that seems to mean unset or unsupport or not applicable. Or something.
* `0x0a`: date: 4 bytes: year-1900, month, day, zero.
* `0x0b`: time: 4 bytes: hour, minute, seconds * 4, 0
* `0x0c`: 4 byte IP address (used for gateway, DNS server, resolved server IP, netmask, ...)
* `0x12`: 4 byte uint32. Used for serial number.

## Server `Set` message

The server can set properties on the client by sending a `Set` (`0x03`-prefixed) message containing a repeated list of property IDs and typed values.

The client replies with the property IDs and `0x00` for success. (Not sure what failure would look like.)

## List of properties

| Code | Name | Type | Sample Value | Sample, Decoded | 
| -----| ---- | ---- | ------------ | --------------- | 
| 0x0100 | version | `0x05` | <nobr>`00 05 0f 0c`</nobr> | 0.5.15.12 |
| 0x0101 | version_string | `0x07` | <nobr>`07 35 2e 31 35 2e 31 32`</nobr> | "5.15.12" |
| 0x0102 |  | `0x09` | <nobr>`1b 10`</nobr> |  |
| 0x0103 | serial_number | `0x12` | <nobr>`07 5b cd 15`</nobr> | 123456789 |
| 0x0107 | date | `0x0a` | <nobr>`7c 01 10 00`</nobr> | 2024-01-16 |
| 0x0108 | time | `0x0b` | <nobr>`14 22 08 00`</nobr> | 20:34:02 |
| 0x010b | time_zone | `0x09` | <nobr>`0b 06`</nobr> | 0x00 for GMT, 0x06 for PST (GMT, -03:30, AST -4, EST -5, CST -6, MST -7, PST -8, -9, -10) |
| 0x010e | temp_unit | `0x09` | <nobr>`2d 04`</nobr> | 0x03 for C, 0x04 for F; affects misc other properties? |
| 0x010f |  | `0x09` | <nobr>`03 01`</nobr> |  |
| 0x0110 | serial_number_string | `0x07` | <nobr>`09 31 32 33 34 35 36 37 38 39`</nobr> | "123456789" |
| 0x0111 |  | `0x02` | <nobr>`01`</nobr> |  |
| 0x0112 |  | `0x05` | <nobr>`70 83 9e 01`</nobr> | 112.131.158.1 |
| 0x0116 |  | `0x03` | <nobr>`00 11`</nobr> |  |
| 0x0117 |  | `0x02` | <nobr>`01`</nobr> |  |
| 0x0124 |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x0125 |  | `0x09` | <nobr>`00 01`</nobr> |  |
| 0x0126 |  | `0x09` | <nobr>`00 01`</nobr> |  |
| 0x0128 |  | `0x09` | <nobr>`01 00`</nobr> |  |
| 0x0129 |  | `0x09` | <nobr>`01 00`</nobr> |  |
| 0x012a |  | `0x09` | <nobr>`01 01`</nobr> |  |
| 0x012b |  | `0x09` | <nobr>`01 01`</nobr> |  |
| 0x0136 |  | `0x01` | <nobr>`05`</nobr> |  |
| 0x0281 |  | `0x02` | <nobr>`00`</nobr> |  |
| 0x0300 |  | `0x08` | <nobr>`00 78 00 01 02 58 05`</nobr> |  |
| 0x0301 |  | `0x08` | <nobr>`00 3c 00 0a 01 2c 0a`</nobr> |  |
| 0x0303 |  | `0x08` | <nobr>`00 3c 00 01 02 58 0a`</nobr> |  |
| 0x0304 |  | `0x08` | <nobr>`00 0a 00 01 00 3c 01`</nobr> |  |
| 0x0305 |  | `0x08` | <nobr>`00 3c 00 01 00 78 05`</nobr> |  |
| 0x0307 |  | `0x08` | <nobr>`00 3c 00 01 01 2c 05`</nobr> |  |
| 0x0308 |  | `0x08` | <nobr>`00 5a 00 00 01 2c 05`</nobr> |  |
| 0x0309 |  | `0x08` | <nobr>`00 3c 00 0a 02 58 0a`</nobr> |  |
| 0x030a |  | `0x08` | <nobr>`00 00 00 05 01 2c 05`</nobr> |  |
| 0x030b |  | `0x08` | <nobr>`00 0a 00 01 00 3c 01`</nobr> |  |
| 0x030c |  | `0x08` | <nobr>`00 0a 00 00 01 2c 05`</nobr> |  |
| 0x030d | set_purge_time_minutes | `0x08` | <nobr>`00 11 00 00 00 3c 05`</nobr> |  |
| 0x030e |  | `0x08` | <nobr>`00 0a 00 05 01 2c 05`</nobr> |  |
| 0x030f |  | `0x08` | <nobr>`00 0a 00 05 01 2c 05`</nobr> |  |
| 0x0310 |  | `0x08` | <nobr>`00 0f 00 05 00 78 05`</nobr> |  |
| 0x0311 | set_event_time_hours | `0x08` | <nobr>`00 01 00 00 00 18 01`</nobr> |  |
| 0x0313 |  | `0x08` | <nobr>`00 78 00 0a 02 58 0a`</nobr> |  |
| 0x0316 |  | `0x08` | <nobr>`00 0f 00 01 00 3c 01`</nobr> |  |
| 0x0317 |  | `0x08` | <nobr>`00 78 00 05 02 58 05`</nobr> |  |
| 0x0318 |  | `0x08` | <nobr>`00 05 00 01 00 1e 01`</nobr> |  |
| 0x031b |  | `0x08` | <nobr>`00 3c 00 01 01 2c 05`</nobr> |  |
| 0x031c |  | `0x08` | <nobr>`00 0a 00 02 00 78 02`</nobr> |  |
| 0x031d |  | `0x08` | <nobr>`00 03 00 01 00 1e 01`</nobr> |  |
| 0x031e |  | `0x08` | <nobr>`00 05 00 01 00 3c 01`</nobr> |  |
| 0x0320 |  | `0x08` | <nobr>`00 14 00 05 00 78 05`</nobr> |  |
| 0x0321 |  | `0x08` | <nobr>`00 3c 00 05 02 58 05`</nobr> |  |
| 0x0322 |  | `0x08` | <nobr>`00 14 00 05 00 78 05`</nobr> |  |
| 0x0323 |  | `0x08` | <nobr>`00 0f 00 02 00 78 02`</nobr> |  |
| 0x0324 |  | `0x08` | <nobr>`00 3c 00 0a 02 58 0a`</nobr> |  |
| 0x0325 |  | `0x08` | <nobr>`00 18 00 02 00 a8 02`</nobr> |  |
| 0x0333 |  | `0x08` | <nobr>`00 3c 00 05 02 58 05`</nobr> |  |
| 0x0335 |  | `0x08` | <nobr>`00 1e 00 05 01 2c 05`</nobr> |  |
| 0x033f |  | `0x08` | <nobr>`00 00 00 00 00 0a 01`</nobr> |  |
| 0x0340 |  | `0x08` | <nobr>`00 3c 00 01 01 2c 05`</nobr> |  |
| 0x0341 |  | `0x08` | <nobr>`00 02 00 01 00 0a 01`</nobr> |  |
| 0x0342 |  | `0x08` | <nobr>`00 3c 00 01 01 2c 05`</nobr> |  |
| 0x0343 |  | `0x08` | <nobr>`00 3c 00 01 02 58 05`</nobr> |  |
| 0x0344 |  | `0x08` | <nobr>`00 0a 00 00 00 0f 01`</nobr> |  |
| 0x0345 |  | `0x08` | <nobr>`00 0a 00 00 00 1e 01`</nobr> |  |
| 0x0346 |  | `0x08` | <nobr>`00 0a 00 00 00 1e 01`</nobr> |  |
| 0x034a |  | `0x08` | <nobr>`00 3c 00 0a 02 58 0a`</nobr> |  |
| 0x034b |  | `0x08` | <nobr>`00 3c 00 05 01 2c 05`</nobr> |  |
| 0x0400 |  | `0x09` | <nobr>`00 01`</nobr> |  |
| 0x0402 | ip_address | `0x0c` | <nobr>`0a 0f 19 22`</nobr> | 10.15.25.34 |
| 0x0403 | subnet_mask | `0x0c` | <nobr>`ff ff ff 00`</nobr> | 255.255.255.0 |
| 0x0404 | gateway | `0x0c` | <nobr>`0a 0f 19 02`</nobr> | 10.15.25.2 |
| 0x0405 | dns_server | `0x0c` | <nobr>`0a 0f 19 02`</nobr> | 10.15.25.2 |
| 0x0520 |  | `0x09` | <nobr>`0d 06`</nobr> |  |
| 0x0521 |  | `0x09` | <nobr>`0e 00`</nobr> |  |
| 0x0522 |  | `0x09` | <nobr>`0f 00`</nobr> |  |
| 0x0525 |  | `0x09` | <nobr>`10 01`</nobr> |  |
| 0x0527 |  | `0x08` | <nobr>`02 ee 00 32 03 e8 19`</nobr> |  |
| 0x0528 |  | `0x08` | <nobr>`03 e8 00 64 13 88 64`</nobr> |  |
| 0x0540 |  | `0x09` | <nobr>`0d 06`</nobr> |  |
| 0x0541 |  | `0x09` | <nobr>`0e 00`</nobr> |  |
| 0x0542 |  | `0x09` | <nobr>`0f 00`</nobr> |  |
| 0x0545 |  | `0x09` | <nobr>`10 01`</nobr> |  |
| 0x0547 |  | `0x08` | <nobr>`02 ee 00 32 03 e8 19`</nobr> |  |
| 0x0548 |  | `0x08` | <nobr>`03 e8 00 64 13 88 64`</nobr> |  |
| 0x0560 |  | `0x09` | <nobr>`0d 06`</nobr> |  |
| 0x0561 |  | `0x09` | <nobr>`0e 00`</nobr> |  |
| 0x0562 |  | `0x09` | <nobr>`0f 00`</nobr> |  |
| 0x0565 |  | `0x09` | <nobr>`10 01`</nobr> |  |
| 0x0567 |  | `0x08` | <nobr>`02 ee 00 32 03 e8 19`</nobr> |  |
| 0x0568 |  | `0x08` | <nobr>`03 e8 00 64 13 88 64`</nobr> |  |
| 0x0600 | humidity_percent | `0x06` | <nobr>`02 16`</nobr> | 53.4 |
| 0x0601 | room_temp_f | `0x06` | <nobr>`02 75`</nobr> | 62.9 |
| 0x0602 | supply_air_f | `0x06` | <nobr>`02 7d`</nobr> | 63.7 |
| 0x0603 | outside_air_f | `0x06` | <nobr>`02 50`</nobr> | 59.2 |
| 0x0604 | pool_temp_f | `0x06` | <nobr>`02 93`</nobr> | 65.9 |
| 0x0605 | pool_temp_out_f | `0x06` | <nobr>`02 95`</nobr> | 66.1 |
| 0x0606 | high_pressure_psi | `0x06` | <nobr>`06 be`</nobr> | 172.6 |
| 0x0607 | low_pressure_psi | `0x06` | <nobr>`06 ec`</nobr> | 177.2 |
| 0x0608 | evaporator_temp_f | `0x06` | <nobr>`02 43`</nobr> | 57.9 |
| 0x0609 | suction_temp_f | `0x06` | <nobr>`03 0b`</nobr> | 77.9 |
| 0x060a | superheat_temp_f | `0x06` | <nobr>`00 a2`</nobr> | 16.2 |
| 0x0610 | discharge_temp_f | `0x06` | <nobr>`02 be`</nobr> | 70.2 |
| 0x0701 |  | `0x08` | <nobr>`00 5a 00 00 00 64 05`</nobr> |  |
| 0x0702 |  | `0x08` | <nobr>`00 00 00 00 00 64 05`</nobr> |  |
| 0x0704 |  | `0x08` | <nobr>`00 00 00 00 00 64 05`</nobr> |  |
| 0x0705 |  | `0x08` | <nobr>`00 00 00 00 00 64 05`</nobr> |  |
| 0x0708 |  | `0x08` | <nobr>`00 00 00 00 00 64 05`</nobr> |  |
| 0x0709 |  | `0x08` | <nobr>`00 00 00 00 00 64 05`</nobr> |  |
| 0x0800 |  | `0x09` | <nobr>`2e 02`</nobr> |  |
| 0x0801 |  | `0x09` | <nobr>`2e 00`</nobr> |  |
| 0x0802 |  | `0x09` | <nobr>`2e 00`</nobr> |  |
| 0x0804 |  | `0x09` | <nobr>`2e 00`</nobr> |  |
| 0x0805 |  | `0x09` | <nobr>`2e 00`</nobr> |  |
| 0x0806 |  | `0x09` | <nobr>`2e 00`</nobr> |  |
| 0x080b |  | `0x09` | <nobr>`2e 02`</nobr> |  |
| 0x080d |  | `0x09` | <nobr>`2e 00`</nobr> |  |
| 0x080f |  | `0x09` | <nobr>`2e 02`</nobr> |  |
| 0x0813 |  | `0x09` | <nobr>`2e 02`</nobr> |  |
| 0x0900 |  | `0x09` | <nobr>`01 01`</nobr> |  |
| 0x0901 |  | `0x09` | <nobr>`01 00`</nobr> |  |
| 0x0904 |  | `0x09` | <nobr>`01 00`</nobr> |  |
| 0x0905 |  | `0x09` | <nobr>`01 00`</nobr> |  |
| 0x090b |  | `0x09` | <nobr>`01 00`</nobr> |  |
| 0x090c |  | `0x09` | <nobr>`01 00`</nobr> |  |
| 0x090d |  | `0x09` | <nobr>`01 00`</nobr> |  |
| 0x090e |  | `0x09` | <nobr>`01 01`</nobr> |  |
| 0x0911 |  | `0x09` | <nobr>`01 00`</nobr> |  |
| 0x0912 |  | `0x09` | <nobr>`01 00`</nobr> |  |
| 0x0915 |  | `0x09` | <nobr>`01 01`</nobr> |  |
| 0x091e |  | `0x09` | <nobr>`01 00`</nobr> |  |
| 0x091f |  | `0x09` | <nobr>`01 00`</nobr> |  |
| 0x0921 |  | `0x09` | <nobr>`01 00`</nobr> |  |
| 0x0925 |  | `0x09` | <nobr>`01 00`</nobr> |  |
| 0x0926 |  | `0x09` | <nobr>`01 00`</nobr> |  |
| 0x0a00 |  | `0x08` | <nobr>`00 0a 00 01 00 32 01`</nobr> |  |
| 0x0a01 |  | `0x08` | <nobr>`00 64 00 32 03 e8 32`</nobr> |  |
| 0x0a05 |  | `0x08` | <nobr>`00 05 00 01 00 0a 01`</nobr> |  |
| 0x0a06 |  | `0x08` | <nobr>`00 64 00 32 03 e8 32`</nobr> |  |
| 0x0a07 |  | `0x08` | <nobr>`00 06 00 01 00 32 01`</nobr> |  |
| 0x0c01 |  | `0x09` | <nobr>`01 01`</nobr> |  |
| 0x0c03 |  | `0x02` | <nobr>`02`</nobr> |  |
| 0x0c04 |  | `0x08` | <nobr>`00 5a 00 0a 00 64 05`</nobr> |  |
| 0x0c05 |  | `0x08` | <nobr>`00 3c 00 0a 00 64 05`</nobr> |  |
| 0x0c09 |  | `0x01` | <nobr>`05`</nobr> |  |
| 0x0e00 |  | `0x09` | <nobr>`00 01`</nobr> |  |
| 0x0e02 |  | `0x02` | <nobr>`03`</nobr> |  |
| 0x0e03 |  | `0x08` | <nobr>`00 03 00 01 00 28 01`</nobr> |  |
| 0x0e04 |  | `0x08` | <nobr>`00 06 00 01 00 28 01`</nobr> |  |
| 0x0e05 |  | `0x08` | <nobr>`00 06 00 01 00 28 01`</nobr> |  |
| 0x0e06 |  | `0x08` | <nobr>`00 03 00 01 00 28 01`</nobr> |  |
| 0x0e07 |  | `0x09` | <nobr>`28 01`</nobr> |  |
| 0x0e08 |  | `0x09` | <nobr>`28 01`</nobr> |  |
| 0x0e09 |  | `0x08` | <nobr>`00 01 00 01 00 0a 01`</nobr> |  |
| 0x0e0a |  | `0x03` | <nobr>`00 00`</nobr> |  |
| 0x0e0b |  | `0x03` | <nobr>`00 00`</nobr> |  |
| 0x0e0c |  | `0x03` | <nobr>`00 00`</nobr> |  |
| 0x0e0d |  | `0x03` | <nobr>`00 00`</nobr> |  |
| 0x1000 | change_filter_date | `0x0a` | <nobr>`7c 01 09 00`</nobr> | 2024-01-09 |
| 0x1001 | change_filter_months | `0x08` | <nobr>`00 06 00 00 00 0c 01`</nobr> |  |
| 0x1003 |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x1004 |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x1005 |  | `0x08` | <nobr>`00 02 00 00 00 0a 01`</nobr> |  |
| 0x1007 |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x100a |  | `0x08` | <nobr>`00 03 00 00 00 0a 01`</nobr> |  |
| 0x100b |  | `0x09` | <nobr>`31 00`</nobr> |  |
| 0x100c |  | `0x03` | <nobr>`00 00`</nobr> |  |
| 0x100f |  | `0x02` | <nobr>`03`</nobr> |  |
| 0x1010 |  | `0x02` | <nobr>`00`</nobr> |  |
| 0x1014 |  | `0x01` | <nobr>`05`</nobr> |  |
| 0x1016 |  | `0x08` | <nobr>`00 00 00 00 00 64 01`</nobr> |  |
| 0x1017 |  | `0x08` | <nobr>`00 63 00 01 00 64 01`</nobr> |  |
| 0x1018 |  | `0x08` | <nobr>`00 63 00 05 00 64 01`</nobr> |  |
| 0x1019 |  | `0x08` | <nobr>`00 01 00 01 00 64 01`</nobr> |  |
| 0x101b |  | `0x08` | <nobr>`00 63 00 01 00 c8 01`</nobr> |  |
| 0x101d |  | `0x07` | <nobr>`03 4f 66 66`</nobr> | "Off" |
| 0x1122 | sched1_days | `0x09` | <nobr>`08 00`</nobr> | 0=none, 1=all, 2=m-f, 3=sat/sun, 4=sun, 5=mon, ..., 0x0a=sat |
| 0x1123 | sched1_occuped_time_on | `0x0b` | <nobr>`08 00 00 00`</nobr> | 08:00:00 |
| 0x1124 | sched1_occuped_time_off | `0x0b` | <nobr>`14 00 00 00`</nobr> | 20:00:00 |
| 0x1142 | sched2_days | `0x09` | <nobr>`08 00`</nobr> | 0=none, 1=all, 2=m-f, 3=sat/sun, 4=sun, 5=mon, ..., 0x0a=sat |
| 0x1143 | sched2_occuped_time_on | `0x0b` | <nobr>`00 00 00 00`</nobr> | 00:00:00 |
| 0x1144 | sched2_occuped_time_off | `0x0b` | <nobr>`00 0f 00 00`</nobr> | 00:15:00 |
| 0x1162 | sched3_days | `0x09` | <nobr>`08 0a`</nobr> | 0=none, 1=all, 2=m-f, 3=sat/sun, 4=sun, 5=mon, ..., 0x0a=sat |
| 0x1163 | sched3_occuped_time_on | `0x0b` | <nobr>`0a 0f 00 00`</nobr> | 10:15:00 |
| 0x1164 | sched3_occuped_time_off | `0x0b` | <nobr>`0a 1e 00 00`</nobr> | 10:30:00 |
| 0x1200 |  | `0x09` | <nobr>`2f 01`</nobr> |  |
| 0x1201 |  | `0x09` | <nobr>`00 01`</nobr> |  |
| 0x1202 |  | `0x09` | <nobr>`12 02`</nobr> |  |
| 0x1203 |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x1204 |  | `0x01` | <nobr>`05`</nobr> |  |
| 0x1206 |  | `0x08` | <nobr>`00 77 00 28 00 96 01`</nobr> |  |
| 0x1207 |  | `0x08` | <nobr>`02 3f 01 2c 02 58 05`</nobr> |  |
| 0x1208 |  | `0x02` | <nobr>`00`</nobr> |  |
| 0x120d | blower_state_string | `0x07` | <nobr>`05 52 65 61 64 79`</nobr> | "Ready" |
| 0x120e | blower_state | `0x02` | <nobr>`02`</nobr> |  |
| 0x1210 |  | `0x09` | <nobr>`00 01`</nobr> |  |
| 0x1211 |  | `0x09` | <nobr>`2a 02`</nobr> |  |
| 0x1212 |  | `0x09` | <nobr>`00 01`</nobr> |  |
| 0x1213 |  | `0x08` | <nobr>`00 0f 00 05 00 23 01`</nobr> |  |
| 0x1214 |  | `0x08` | <nobr>`00 4b 00 14 00 5a 02`</nobr> |  |
| 0x1215 |  | `0x08` | <nobr>`00 78 00 28 00 96 02`</nobr> |  |
| 0x1216 |  | `0x08` | <nobr>`00 aa 00 50 00 c8 02`</nobr> |  |
| 0x1217 |  | `0x09` | <nobr>`00 01`</nobr> |  |
| 0x1218 |  | `0x08` | <nobr>`00 f0 00 8c 01 5e 05`</nobr> |  |
| 0x1219 |  | `0x08` | <nobr>`01 68 00 be 01 90 05`</nobr> |  |
| 0x121a |  | `0x08` | <nobr>`00 28 00 02 00 46 02`</nobr> |  |
| 0x121b |  | `0x08` | <nobr>`01 a4 00 dc 01 f4 05`</nobr> |  |
| 0x121c |  | `0x08` | <nobr>`00 03 00 01 00 3c 01`</nobr> |  |
| 0x121d |  | `0x08` | <nobr>`01 f4 00 fa 02 58 0a`</nobr> |  |
| 0x121e |  | `0x08` | <nobr>`00 5a 00 0a 01 2c 05`</nobr> |  |
| 0x121f |  | `0x08` | <nobr>`00 05 00 02 00 32 01`</nobr> |  |
| 0x1220 |  | `0x03` | <nobr>`00 64`</nobr> |  |
| 0x1223 |  | `0x08` | <nobr>`00 0a 00 05 01 2c 05`</nobr> |  |
| 0x1224 |  | `0x08` | <nobr>`00 08 00 01 00 28 01`</nobr> |  |
| 0x1225 |  | `0x08` | <nobr>`00 05 00 01 00 1e 01`</nobr> |  |
| 0x1226 |  | `0x08` | <nobr>`00 1e 00 01 00 50 01`</nobr> |  |
| 0x1227 |  | `0x02` | <nobr>`02`</nobr> |  |
| 0x1228 |  | `0x01` | <nobr>`05`</nobr> |  |
| 0x1229 |  | `0x09` | <nobr>`30 00`</nobr> |  |
| 0x122a |  | `0x09` | <nobr>`21 00`</nobr> |  |
| 0x122b |  | `0x08` | <nobr>`00 1e 00 00 00 64 02`</nobr> |  |
| 0x122c |  | `0x08` | <nobr>`00 05 00 01 00 32 01`</nobr> |  |
| 0x122e |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x1234 |  | `0x01` | <nobr>`05`</nobr> |  |
| 0x123d |  | `0x01` | <nobr>`05`</nobr> |  |
| 0x1326 |  | `0x09` | <nobr>`00 01`</nobr> |  |
| 0x1327 |  | `0x08` | <nobr>`00 01 00 01 00 02 01`</nobr> |  |
| 0x1336 |  | `0x02` | <nobr>`02`</nobr> |  |
| 0x1346 |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x1347 |  | `0x08` | <nobr>`00 02 00 01 00 02 01`</nobr> |  |
| 0x1366 |  | `0x01` | <nobr>`05`</nobr> |  |
| 0x1386 |  | `0x01` | <nobr>`05`</nobr> |  |
| 0x13a6 |  | `0x01` | <nobr>`05`</nobr> |  |
| 0x13c6 |  | `0x01` | <nobr>`05`</nobr> |  |
| 0x1400 |  | `0x01` | <nobr>`04`</nobr> |  |
| 0x1411 |  | `0x01` | <nobr>`04`</nobr> |  |
| 0x1420 |  | `0x01` | <nobr>`04`</nobr> |  |
| 0x1600 |  | `0x09` | <nobr>`13 00`</nobr> |  |
| 0x1607 |  | `0x08` | <nobr>`00 32 00 05 00 64 05`</nobr> |  |
| 0x160b |  | `0x08` | <nobr>`00 05 00 01 00 64 01`</nobr> |  |
| 0x1612 |  | `0x02` | <nobr>`01`</nobr> |  |
| 0x1905 |  | `0x08` | <nobr>`00 64 00 05 00 f0 05`</nobr> |  |
| 0x1906 |  | `0x08` | <nobr>`00 64 00 05 00 f0 05`</nobr> |  |
| 0x1907 |  | `0x08` | <nobr>`00 14 00 00 00 14 01`</nobr> |  |
| 0x190a |  | `0x02` | <nobr>`01`</nobr> |  |
| 0x190f |  | `0x03` | <nobr>`00 00`</nobr> |  |
| 0x1910 |  | `0x03` | <nobr>`00 00`</nobr> |  |
| 0x1912 |  | `0x08` | <nobr>`00 1e 00 05 00 1e 05`</nobr> |  |
| 0x1913 |  | `0x09` | <nobr>`00 01`</nobr> |  |
| 0x1a04 |  | `0x02` | <nobr>`03`</nobr> |  |
| 0x1a0f |  | `0x08` | <nobr>`00 14 00 02 00 78 02`</nobr> |  |
| 0x1a10 |  | `0x08` | <nobr>`00 14 00 02 00 78 02`</nobr> |  |
| 0x1a18 |  | `0x03` | <nobr>`00 0f`</nobr> |  |
| 0x1a19 |  | `0x03` | <nobr>`00 00`</nobr> |  |
| 0x1a1e |  | `0x09` | <nobr>`00 01`</nobr> |  |
| 0x1b00 |  | `0x01` | <nobr>`05`</nobr> |  |
| 0x1b02 |  | `0x09` | <nobr>`29 03`</nobr> |  |
| 0x1b03 |  | `0x09` | <nobr>`29 00`</nobr> |  |
| 0x1b07 |  | `0x08` | <nobr>`00 02 00 00 00 0a 01`</nobr> |  |
| 0x1b2b |  | `0x02` | <nobr>`03`</nobr> |  |
| 0x2003 | resolved_websentry_ip | `0x0c` | <nobr>`36 d0 01 0b`</nobr> | 54.208.1.11 |
| 0x2100 |  | `0x01` | <nobr>`04`</nobr> |  |
| 0x2101 |  | `0x01` | <nobr>`04`</nobr> |  |
| 0x2103 |  | `0x01` | <nobr>`04`</nobr> |  |
| 0x2200 |  | `0x04` | <nobr>`00 03`</nobr> |  |
| 0x2201 |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x2300 |  | `0x09` | <nobr>`2c 00`</nobr> |  |
| 0x2301 |  | `0x01` | <nobr>`05`</nobr> |  |
| 0x2303 |  | `0x02` | <nobr>`00`</nobr> |  |
| 0x2304 |  | `0x09` | <nobr>`2b 06`</nobr> |  |
| 0x2306 |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x2500 | set_room_temp_f | `0x08` | <nobr>`00 53 00 37 00 5f 01`</nobr> |  |
| 0x2501 | set_humidity_percent | `0x08` | <nobr>`00 37 00 23 00 55 01`</nobr> |  |
| 0x2502 | set_pool_temp_f | `0x08` | <nobr>`00 51 00 3c 00 6c 01`</nobr> |  |
| 0x2503 | set_economizer_min_temp_f | `0x08` | <nobr>`00 59 00 28 00 5a 01`</nobr> |  |
| 0x2504 | set_freezestat_f | `0x08` | <nobr>`00 2c 00 14 00 37 01`</nobr> |  |
| 0x2505 | set_purge_shutoff_f | `0x08` | <nobr>`00 37 00 28 00 46 01`</nobr> |  |
| 0x2506 | set_heat_recovery_f | `0x08` | <nobr>`00 40 00 28 00 46 01`</nobr> |  |
| 0x2508 |  | `0x08` | <nobr>`00 54 00 23 00 96 01`</nobr> |  |
| 0x250c | set_disable_ac_at_f | `0x08` | <nobr>`00 3d 00 28 00 46 01`</nobr> |  |
| 0x250d |  | `0x08` | <nobr>`00 37 00 23 00 55 01`</nobr> |  |
| 0x2520 |  | `0x08` | <nobr>`00 04 00 00 00 1e 01`</nobr> |  |
| 0x2521 |  | `0x08` | <nobr>`00 05 00 00 00 0a 01`</nobr> |  |
| 0x2522 |  | `0x08` | <nobr>`00 03 00 00 00 1e 01`</nobr> |  |
| 0x2528 |  | `0x08` | <nobr>`00 1e 00 00 00 32 01`</nobr> |  |
| 0x2540 |  | `0x08` | <nobr>`00 04 00 00 00 1e 01`</nobr> |  |
| 0x2541 |  | `0x08` | <nobr>`00 05 00 00 00 0a 01`</nobr> |  |
| 0x2542 |  | `0x08` | <nobr>`00 03 00 00 00 1e 01`</nobr> |  |
| 0x2546 |  | `0x08` | <nobr>`00 05 00 00 00 0a 01`</nobr> |  |
| 0x2548 |  | `0x08` | <nobr>`00 1e 00 00 00 32 01`</nobr> |  |
| 0x254c |  | `0x08` | <nobr>`00 32 00 00 00 0a 01`</nobr> |  |
| 0x2600 |  | `0x01` | <nobr>`04`</nobr> |  |
| 0x2700 |  | `0x09` | <nobr>`26 00`</nobr> |  |
| 0x2701 |  | `0x09` | <nobr>`26 03`</nobr> |  |
| 0x2702 |  | `0x09` | <nobr>`26 04`</nobr> |  |
| 0x2703 |  | `0x09` | <nobr>`26 05`</nobr> |  |
| 0x2704 |  | `0x09` | <nobr>`26 06`</nobr> |  |
| 0x2705 |  | `0x09` | <nobr>`26 07`</nobr> |  |
| 0x2706 |  | `0x09` | <nobr>`26 08`</nobr> |  |
| 0x2707 |  | `0x09` | <nobr>`26 0c`</nobr> |  |
| 0x270b |  | `0x09` | <nobr>`26 00`</nobr> |  |
| 0x270c |  | `0x09` | <nobr>`26 0e`</nobr> |  |
| 0x270d |  | `0x09` | <nobr>`26 0f`</nobr> |  |
| 0x270e |  | `0x09` | <nobr>`26 00`</nobr> |  |
| 0x270f |  | `0x09` | <nobr>`26 00`</nobr> |  |
| 0x2710 |  | `0x09` | <nobr>`26 00`</nobr> |  |
| 0x2711 |  | `0x09` | <nobr>`26 00`</nobr> |  |
| 0x2712 |  | `0x09` | <nobr>`26 00`</nobr> |  |
| 0x2713 |  | `0x09` | <nobr>`26 00`</nobr> |  |
| 0x2715 |  | `0x09` | <nobr>`26 00`</nobr> |  |
| 0x2716 |  | `0x09` | <nobr>`26 00`</nobr> |  |
| 0x271a |  | `0x09` | <nobr>`26 02`</nobr> |  |
| 0x271b |  | `0x09` | <nobr>`26 01`</nobr> |  |
| 0x271c |  | `0x09` | <nobr>`26 11`</nobr> |  |
| 0x271d |  | `0x09` | <nobr>`26 12`</nobr> |  |
| 0x271e |  | `0x09` | <nobr>`26 13`</nobr> |  |
| 0x271f |  | `0x09` | <nobr>`26 00`</nobr> |  |
| 0x2720 |  | `0x09` | <nobr>`26 00`</nobr> |  |
| 0x2800 |  | `0x09` | <nobr>`27 02`</nobr> |  |
| 0x2801 |  | `0x09` | <nobr>`27 03`</nobr> |  |
| 0x2802 |  | `0x09` | <nobr>`27 00`</nobr> |  |
| 0x2803 |  | `0x09` | <nobr>`27 00`</nobr> |  |
| 0x2804 |  | `0x09` | <nobr>`27 06`</nobr> |  |
| 0x2805 |  | `0x09` | <nobr>`27 07`</nobr> |  |
| 0x280b |  | `0x09` | <nobr>`27 0d`</nobr> |  |
| 0x280c |  | `0x09` | <nobr>`27 0e`</nobr> |  |
| 0x280d |  | `0x09` | <nobr>`27 0f`</nobr> |  |
| 0x280e |  | `0x09` | <nobr>`27 10`</nobr> |  |
| 0x280f |  | `0x09` | <nobr>`27 12`</nobr> |  |
| 0x2810 |  | `0x09` | <nobr>`27 00`</nobr> |  |
| 0x2811 |  | `0x09` | <nobr>`27 13`</nobr> |  |
| 0x2812 |  | `0x09` | <nobr>`27 14`</nobr> |  |
| 0x2815 |  | `0x09` | <nobr>`27 17`</nobr> |  |
| 0x2816 |  | `0x09` | <nobr>`27 18`</nobr> |  |
| 0x2819 |  | `0x09` | <nobr>`27 00`</nobr> |  |
| 0x281e |  | `0x09` | <nobr>`27 04`</nobr> |  |
| 0x281f |  | `0x09` | <nobr>`27 05`</nobr> |  |
| 0x2821 |  | `0x09` | <nobr>`27 15`</nobr> |  |
| 0x2825 |  | `0x09` | <nobr>`27 16`</nobr> |  |
| 0x2826 |  | `0x09` | <nobr>`27 01`</nobr> |  |
| 0x2827 |  | `0x09` | <nobr>`27 00`</nobr> |  |
| 0x2828 |  | `0x09` | <nobr>`27 00`</nobr> |  |
| 0x2900 |  | `0x09` | <nobr>`00 01`</nobr> |  |
| 0x2901 |  | `0x09` | <nobr>`00 01`</nobr> |  |
| 0x2902 |  | `0x09` | <nobr>`00 01`</nobr> |  |
| 0x2903 |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x2904 |  | `0x09` | <nobr>`00 01`</nobr> |  |
| 0x2905 |  | `0x09` | <nobr>`00 01`</nobr> |  |
| 0x2906 |  | `0x09` | <nobr>`00 01`</nobr> |  |
| 0x2907 |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x290b |  | `0x09` | <nobr>`00 01`</nobr> |  |
| 0x290c |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x290d |  | `0x09` | <nobr>`00 01`</nobr> |  |
| 0x290e |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x290f |  | `0x09` | <nobr>`00 01`</nobr> |  |
| 0x2910 |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x2911 |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x2913 |  | `0x09` | <nobr>`00 01`</nobr> |  |
| 0x2915 |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x2916 |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x291a |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x291b |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x291c |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x291d |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x291e |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x291f |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x2920 |  | `0x09` | <nobr>`00 00`</nobr> |  |
| 0x2a00 |  | `0x09` | <nobr>`32 01`</nobr> |  |
| 0x2a01 |  | `0x09` | <nobr>`32 00`</nobr> |  |
| 0x2a02 |  | `0x09` | <nobr>`32 00`</nobr> |  |
| 0x2a03 |  | `0x09` | <nobr>`32 00`</nobr> |  |
| 0x2a04 |  | `0x09` | <nobr>`32 01`</nobr> |  |
| 0x2a05 |  | `0x09` | <nobr>`32 00`</nobr> |  |
| 0x2a06 |  | `0x09` | <nobr>`32 00`</nobr> |  |
| 0x2a07 |  | `0x09` | <nobr>`32 00`</nobr> |  |
| 0x2a0b |  | `0x09` | <nobr>`32 01`</nobr> |  |
| 0x2a0c |  | `0x09` | <nobr>`32 00`</nobr> |  |
| 0x2a0d |  | `0x09` | <nobr>`32 00`</nobr> |  |
| 0x2a0e |  | `0x09` | <nobr>`32 01`</nobr> |  |
| 0x2a0f |  | `0x09` | <nobr>`32 01`</nobr> |  |
| 0x2a10 |  | `0x09` | <nobr>`32 01`</nobr> |  |
| 0x2a11 |  | `0x09` | <nobr>`32 01`</nobr> |  |
| 0x2a13 |  | `0x09` | <nobr>`32 01`</nobr> |  |
| 0x2a15 |  | `0x09` | <nobr>`32 01`</nobr> |  |
| 0x2a16 |  | `0x09` | <nobr>`32 01`</nobr> |  |
| 0x2a1a |  | `0x09` | <nobr>`32 00`</nobr> |  |
| 0x2a1b |  | `0x09` | <nobr>`32 00`</nobr> |  |
| 0x2a1c |  | `0x09` | <nobr>`32 00`</nobr> |  |
| 0x2a1d |  | `0x09` | <nobr>`32 00`</nobr> |  |
| 0x2a1e |  | `0x09` | <nobr>`32 00`</nobr> |  |
| 0x2a1f |  | `0x09` | <nobr>`32 01`</nobr> |  |
| 0x2a20 |  | `0x09` | <nobr>`32 01`</nobr> |  |
| 0x2b00 |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b01 |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b02 |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b03 |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b04 |  | `0x08` | <nobr>`ff fe ff ce 00 32 01`</nobr> |  |
| 0x2b05 |  | `0x08` | <nobr>`ff fe ff ce 00 32 01`</nobr> |  |
| 0x2b06 |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b07 |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b08 |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b09 |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b0a |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b10 |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b12 |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b13 |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b16 |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b17 |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b18 |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b1c |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b1d |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b1e |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b1f |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b20 |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b21 |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b26 |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b27 |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b28 |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b29 |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2b2a |  | `0x08` | <nobr>`00 00 ff ce 00 32 01`</nobr> |  |
| 0x2c00 |  | `0x09` | <nobr>`1c 07`</nobr> |  |
| 0x2c01 |  | `0x09` | <nobr>`1c 02`</nobr> |  |
| 0x2c02 |  | `0x09` | <nobr>`1c 02`</nobr> |  |
| 0x2c03 |  | `0x09` | <nobr>`1c 02`</nobr> |  |
| 0x2c04 |  | `0x09` | <nobr>`1c 02`</nobr> |  |
| 0x2c05 |  | `0x09` | <nobr>`1c 02`</nobr> |  |
| 0x2c06 |  | `0x09` | <nobr>`1c 0e`</nobr> |  |
| 0x2c07 |  | `0x09` | <nobr>`1c 0c`</nobr> |  |
| 0x2c08 |  | `0x09` | <nobr>`1c 02`</nobr> |  |
| 0x2c09 |  | `0x09` | <nobr>`1c 02`</nobr> |  |
| 0x2c0a |  | `0x09` | <nobr>`1c 0b`</nobr> |  |
| 0x2c10 |  | `0x09` | <nobr>`1c 02`</nobr> |  |
| 0x2c12 |  | `0x09` | <nobr>`1c 02`</nobr> |  |
| 0x2c13 |  | `0x09` | <nobr>`1c 02`</nobr> |  |
| 0x2c16 |  | `0x09` | <nobr>`1c 0b`</nobr> |  |
| 0x2c17 |  | `0x09` | <nobr>`1c 07`</nobr> |  |
| 0x2c18 |  | `0x09` | <nobr>`1c 0b`</nobr> |  |
| 0x2c1c |  | `0x09` | <nobr>`1c 03`</nobr> |  |
| 0x2c1d |  | `0x09` | <nobr>`1c 0f`</nobr> |  |
| 0x2c1e |  | `0x09` | <nobr>`1c 10`</nobr> |  |
| 0x2c1f |  | `0x09` | <nobr>`1c 10`</nobr> |  |
| 0x2c20 |  | `0x09` | <nobr>`1c 02`</nobr> |  |
| 0x2c21 |  | `0x09` | <nobr>`1c 02`</nobr> |  |
| 0x2c26 |  | `0x09` | <nobr>`1c 02`</nobr> |  |
| 0x2c27 |  | `0x09` | <nobr>`1c 02`</nobr> |  |
| 0x2c28 |  | `0x09` | <nobr>`1c 02`</nobr> |  |
| 0x2c29 |  | `0x09` | <nobr>`1c 02`</nobr> |  |
| 0x2c2a |  | `0x09` | <nobr>`1c 02`</nobr> |  |
| 0x2d00 |  | `0x09` | <nobr>`23 01`</nobr> |  |
| 0x2d01 |  | `0x09` | <nobr>`23 01`</nobr> |  |
| 0x2d02 |  | `0x09` | <nobr>`23 01`</nobr> |  |
| 0x2d03 |  | `0x09` | <nobr>`23 01`</nobr> |  |
| 0x2d04 |  | `0x09` | <nobr>`23 01`</nobr> |  |
| 0x2d05 |  | `0x09` | <nobr>`23 01`</nobr> |  |
| 0x2d06 |  | `0x09` | <nobr>`23 01`</nobr> |  |
| 0x2d07 |  | `0x09` | <nobr>`23 01`</nobr> |  |
| 0x2d08 |  | `0x09` | <nobr>`23 01`</nobr> |  |
| 0x2d09 |  | `0x09` | <nobr>`23 01`</nobr> |  |
| 0x2d0a |  | `0x09` | <nobr>`23 01`</nobr> |  |
| 0x2d10 |  | `0x09` | <nobr>`23 01`</nobr> |  |
| 0x2d12 |  | `0x09` | <nobr>`23 00`</nobr> |  |
| 0x2d13 |  | `0x09` | <nobr>`23 00`</nobr> |  |
| 0x2d16 |  | `0x09` | <nobr>`23 00`</nobr> |  |
| 0x2d17 |  | `0x09` | <nobr>`23 00`</nobr> |  |
| 0x2d18 |  | `0x09` | <nobr>`23 00`</nobr> |  |
| 0x2d1c |  | `0x09` | <nobr>`23 00`</nobr> |  |
| 0x2d1d |  | `0x09` | <nobr>`23 00`</nobr> |  |
| 0x2d1e |  | `0x09` | <nobr>`23 00`</nobr> |  |
| 0x2d1f |  | `0x09` | <nobr>`23 00`</nobr> |  |
| 0x2d20 |  | `0x09` | <nobr>`23 00`</nobr> |  |
| 0x2d21 |  | `0x09` | <nobr>`23 00`</nobr> |  |
| 0x2d26 |  | `0x09` | <nobr>`23 00`</nobr> |  |
| 0x2d27 |  | `0x09` | <nobr>`23 00`</nobr> |  |
| 0x2d28 |  | `0x09` | <nobr>`23 00`</nobr> |  |
| 0x2d29 |  | `0x09` | <nobr>`23 00`</nobr> |  |
| 0x2d2a |  | `0x09` | <nobr>`23 00`</nobr> |  |
| 0x2d32 |  | `0x01` | <nobr>`05`</nobr> |  |
| 0x2d3d |  | `0x01` | <nobr>`05`</nobr> |  |
| 0x2d3e |  | `0x01` | <nobr>`05`</nobr> |  |
| 0x2d46 |  | `0x01` | <nobr>`05`</nobr> |  |
| 0x2d69 |  | `0x01` | <nobr>`05`</nobr> |  |
| 0x2d6a |  | `0x01` | <nobr>`05`</nobr> |  |
| 0x2d6e |  | `0x01` | <nobr>`05`</nobr> |  |
| 0x2e00 |  | `0x09` | <nobr>`24 0e`</nobr> |  |
| 0x2e01 |  | `0x09` | <nobr>`24 06`</nobr> |  |
| 0x2e02 |  | `0x09` | <nobr>`24 11`</nobr> |  |
| 0x2e03 |  | `0x09` | <nobr>`24 08`</nobr> |  |
| 0x2e04 |  | `0x09` | <nobr>`24 09`</nobr> |  |
| 0x2e05 |  | `0x09` | <nobr>`24 0a`</nobr> |  |
| 0x2e06 |  | `0x09` | <nobr>`24 01`</nobr> |  |
| 0x2e07 |  | `0x09` | <nobr>`24 02`</nobr> |  |
| 0x2e08 |  | `0x09` | <nobr>`24 0f`</nobr> |  |
| 0x2e09 |  | `0x09` | <nobr>`24 12`</nobr> |  |
| 0x2e0a |  | `0x09` | <nobr>`24 00`</nobr> |  |
| 0x2e10 |  | `0x09` | <nobr>`24 07`</nobr> |  |
| 0x2e12 |  | `0x09` | <nobr>`24 14`</nobr> |  |
| 0x2e13 |  | `0x09` | <nobr>`24 04`</nobr> |  |
| 0x2e16 |  | `0x09` | <nobr>`24 00`</nobr> |  |
| 0x2e17 |  | `0x09` | <nobr>`24 00`</nobr> |  |
| 0x2e18 |  | `0x09` | <nobr>`24 00`</nobr> |  |
| 0x2e1c |  | `0x09` | <nobr>`24 00`</nobr> |  |
| 0x2e1d |  | `0x09` | <nobr>`24 00`</nobr> |  |
| 0x2e1e |  | `0x09` | <nobr>`24 00`</nobr> |  |
| 0x2e1f |  | `0x09` | <nobr>`24 00`</nobr> |  |
| 0x2e20 |  | `0x09` | <nobr>`24 00`</nobr> |  |
| 0x2e21 |  | `0x09` | <nobr>`24 00`</nobr> |  |
| 0x2e26 |  | `0x09` | <nobr>`24 00`</nobr> |  |
| 0x2e27 |  | `0x09` | <nobr>`24 00`</nobr> |  |
| 0x2e28 |  | `0x09` | <nobr>`24 00`</nobr> |  |
| 0x2e29 |  | `0x09` | <nobr>`24 00`</nobr> |  |
| 0x2e2a |  | `0x09` | <nobr>`24 00`</nobr> |  |
| 0x2f01 |  | `0x09` | <nobr>`06 00`</nobr> |  |
| 0x2f02 |  | `0x09` | <nobr>`06 00`</nobr> |  |
| 0x2f04 |  | `0x09` | <nobr>`06 00`</nobr> |  |
| 0x2f05 |  | `0x09` | <nobr>`06 00`</nobr> |  |
| 0x2f08 |  | `0x09` | <nobr>`06 00`</nobr> |  |
| 0x2f09 |  | `0x09` | <nobr>`06 00`</nobr> |  |
| 0x3000 |  | `0x09` | <nobr>`25 01`</nobr> |  |
| 0x3001 |  | `0x09` | <nobr>`25 02`</nobr> |  |
| 0x3002 |  | `0x09` | <nobr>`25 04`</nobr> |  |
| 0x3004 |  | `0x09` | <nobr>`25 05`</nobr> |  |
| 0x3005 |  | `0x09` | <nobr>`25 07`</nobr> |  |
| 0x3008 |  | `0x09` | <nobr>`25 03`</nobr> |  |
| 0x3009 |  | `0x09` | <nobr>`25 06`</nobr> |  |
| 0x3101 |  | `0x08` | <nobr>`00 00 00 00 00 64 05`</nobr> |  |
| 0x3102 |  | `0x08` | <nobr>`00 00 00 00 00 64 05`</nobr> |  |
| 0x3104 |  | `0x08` | <nobr>`00 00 00 00 00 64 05`</nobr> |  |
| 0x3105 |  | `0x08` | <nobr>`00 00 00 00 00 64 05`</nobr> |  |
| 0x3108 |  | `0x08` | <nobr>`00 00 00 00 00 64 05`</nobr> |  |
| 0x3109 |  | `0x08` | <nobr>`00 00 00 00 00 64 05`</nobr> |  |
| 0x3201 |  | `0x08` | <nobr>`00 64 00 00 00 64 05`</nobr> |  |
| 0x3202 |  | `0x08` | <nobr>`00 64 00 00 00 64 05`</nobr> |  |
| 0x3204 |  | `0x08` | <nobr>`00 64 00 00 00 64 05`</nobr> |  |
| 0x3205 |  | `0x08` | <nobr>`00 64 00 00 00 64 05`</nobr> |  |
| 0x3208 |  | `0x08` | <nobr>`00 64 00 00 00 64 05`</nobr> |  |
| 0x3209 |  | `0x08` | <nobr>`00 64 00 00 00 64 05`</nobr> |  |
| 0x3d00 |  | `0x01` | <nobr>`04`</nobr> |  |
