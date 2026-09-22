//! Exporter node-name projection from spec 11 §3.19.2. No JSON writer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventNode<'a> {
    Flow(&'a str),
    Lost,
    Agent,
    Debug,
}
/// Flow names are copied verbatim from the flow; other export events use the
/// bare node name. This deliberately differs from Observer stream envelopes.
pub const fn node_name<'a>(event: EventNode<'a>, bare_node: &'a str) -> &'a str {
    match event {
        EventNode::Flow(name) => name,
        _ => bare_node,
    }
}
