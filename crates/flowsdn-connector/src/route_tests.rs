use super::*;
use rtnetlink::packet_route::AddressFamily;

fn message(v6: bool) -> RouteMessage {
    let mut value = RouteMessage::default();
    value.header.address_family = if v6 { AddressFamily::Inet6 } else { AddressFamily::Inet };
    value.header.table = 254;
    value.header.kind = RouteType::Unicast;
    value.attributes.push(RouteAttribute::Oif(7));
    value
}

#[test]
fn only_requested_interface_main_table_unicast_routes_are_returned() {
    for v6 in [false, true] {
        let value = message(v6);
        assert!(route_info(value.clone(), 8).is_none());
        let route = route_info(value.clone(), 7).expect("route");
        assert!(route.destination.is_unspecified());
        assert_eq!(route.destination.is_ipv6(), v6);
        assert_eq!(route.prefix, 0);
        let mut wrong = value.clone();
        wrong.header.table = 100;
        assert!(route_info(wrong, 7).is_none());
        let mut wrong = value.clone();
        wrong.attributes.push(RouteAttribute::Table(100));
        assert!(route_info(wrong, 7).is_none());
        let mut wrong = value;
        wrong.header.kind = RouteType::BlackHole;
        assert!(route_info(wrong, 7).is_none());
    }
}

#[test]
fn route_dump_preserves_gateway_host_prefix_and_mtu() {
    for gateway in ["198.18.0.254", "2001:db8::ffff"] {
        let gateway: IpAddr = gateway.parse().expect("gateway");
        let mut value = message(gateway.is_ipv6());
        value.attributes.push(RouteAttribute::Gateway(gateway.into()));
        value.attributes.push(RouteAttribute::Metrics(vec![RouteMetric::Mtu(1450)]));
        let route = route_info(value, 7).expect("default");
        assert_eq!(route.gateway, Some(gateway));
        assert_eq!(route.mtu, Some(1450));
        let mut host = message(gateway.is_ipv6());
        host.header.destination_prefix_length = if gateway.is_ipv6() {128} else {32};
        host.attributes.push(RouteAttribute::Destination(gateway.into()));
        let route = route_info(host, 7).expect("host route");
        assert_eq!(route.destination, gateway);
        assert_eq!(route.prefix, if gateway.is_ipv6() {128} else {32});
        assert_eq!(route.gateway, None);
    }
}
