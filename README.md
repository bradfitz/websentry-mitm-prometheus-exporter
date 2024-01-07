# WebSentry MITM Prometheus Exporter

This is a server that intercepts traffic from a [WebSentry](https://serescodehumidifiers.com/websentry/) dehumidifier (as supported by the various https://dehumidifiedairsolutions.com/ brands) and parses the traffic while proxying it upstream to its cloud service.

It then exports [Prometheus](https://prometheus.io/) metrics so I can see things more detailed in [Grafana](https://grafana.com/) than I can
on the official cloud portal.

## Protocol

See the [protocol details page](https://github.com/bradfitz/websentry-mitm-prometheus-exporter/blob/main/websentry-protocol.md) for what I've figured out so far. If you figure out more, file an issue with details! (Or let me know if this is an existing protocol you recognize.)

## Using

To use this server, you have two main options:

* If you control your LAN's DNS server, add a fake entry for `websentry.seresco.net` (or whatever brand DNS name your unit queries) and point it at the IP address where you're running this code.

* If you control your LAN's DHCP server, send the dehumifier unit (e.g. `10.15.25.34`) a router address to a Linux box running this code (e.g. `10.15.25.2`) with an iptables rule like `iptables -t nat -I PREROUTING 1 -s 10.15.25.34 -p tcp -m multiport --dports 1030 -j DNAT --to-destination 10.15.25.2:1030`. With `dnsmasq`, you can do something like: 

```
dhcp-host=00:90:c2:XX:XX:XX,10.15.25.34,set:usemitm
dhcp-option=tag:usemitm,option:router,10.15.25.2
```

## Unofficial

This is all just my personal contraption and by no means official. The Dehumidified Air Solutions folk are unlikely to support this

The official way to get these metrics is via MODBUS or LON or BACNET or something, but I didn't want to wire those up. I preferred to use its existing Ethernet connection.
