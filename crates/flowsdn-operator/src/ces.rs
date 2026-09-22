//! Validated CES stepped rate configuration; no token bucket or work queue.
use serde_json::Value;
// Preserve object keys until duplicate validation has run: Value alone would
// silently discard an earlier identical key before the table sees it.
struct Fields(serde_json::Map<String, Value>);
impl<'de> serde::Deserialize<'de> for Fields {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FieldsVisitor;
        impl<'de> serde::de::Visitor<'de> for FieldsVisitor {
            type Value = Fields;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a CES rate step with unique fields")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut input: M,
            ) -> Result<Fields, M::Error> {
                let mut fields = serde_json::Map::new();
                while let Some((name, value)) = input.next_entry::<String, Value>()? {
                    if fields.insert(name, value).is_some() {
                        return Err(serde::de::Error::custom("duplicate CES rate field"));
                    }
                }
                Ok(Fields(fields))
            }
        }
        deserializer.deserialize_map(FieldsVisitor)
    }
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Step {
    pub nodes: u64,
    pub limit: f64,
    pub burst: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Json,
    Empty,
    Object,
    UnknownField(String),
    DuplicateField(String),
    MissingField(&'static str),
    Nodes,
    Limit,
    Burst,
    DuplicateThreshold,
}
#[derive(Clone, Debug)]
pub struct RateTable {
    first: Step,
    rest: Vec<Step>,
}
impl Default for RateTable {
    fn default() -> Self {
        Self {
            first: Step {
                nodes: 0,
                limit: 10.0,
                burst: 20,
            },
            rest: Vec::new(),
        }
    }
}
impl RateTable {
    pub fn parse(input: &str) -> Result<Self, Error> {
        let rows: Vec<Fields> = serde_json::from_str(input).map_err(|_| Error::Json)?;
        let mut steps = Vec::new();
        for row in rows {
            let fields = &row.0;
            let (mut nodes, mut limit, mut burst) = (None, None, None);
            for (name, value) in fields {
                let slot = match name.to_ascii_lowercase().as_str() {
                    "nodes" => &mut nodes,
                    "limit" => &mut limit,
                    "burst" => &mut burst,
                    _ => return Err(Error::UnknownField(name.clone())),
                };
                if slot.replace(value).is_some() {
                    return Err(Error::DuplicateField(name.clone()));
                }
            }
            let nodes = nodes
                .ok_or(Error::MissingField("nodes"))?
                .as_u64()
                .ok_or(Error::Nodes)?;
            let limit = limit
                .ok_or(Error::MissingField("limit"))?
                .as_f64()
                .filter(|v| v.is_finite() && *v > 0.0)
                .ok_or(Error::Limit)?;
            let burst = burst
                .ok_or(Error::MissingField("burst"))?
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .filter(|v| *v > 0)
                .ok_or(Error::Burst)?;
            steps.push(Step {
                nodes,
                limit,
                burst,
            });
        }
        steps.sort_by_key(|step| step.nodes);
        let mut steps = steps.into_iter();
        let first = steps.next().ok_or(Error::Empty)?;
        let mut previous = first.nodes;
        let mut rest = Vec::new();
        for step in steps {
            if step.nodes == previous {
                return Err(Error::DuplicateThreshold);
            }
            previous = step.nodes;
            rest.push(step);
        }
        Ok(Self { first, rest })
    }
    /// Below the smallest configured threshold, select the first entry.
    pub fn select(&self, nodes: u64) -> Step {
        self.rest
            .iter()
            .take_while(|step| step.nodes <= nodes)
            .last()
            .copied()
            .unwrap_or(self.first)
    }
}
#[derive(Debug)]
pub struct Selection {
    table: RateTable,
    current: Step,
}
impl Selection {
    pub fn new(table: RateTable) -> Self {
        let current = table.select(0);
        Self { table, current }
    }
    pub fn current(&self) -> Step {
        self.current
    }
    /// A change instructs the caller to reconfigure its existing limiter, keeping
    /// queue/reservation state. This object neither holds nor resets tokens.
    pub fn update(&mut self, nodes: u64) -> Option<Step> {
        let next = self.table.select(nodes);
        if next == self.current {
            return None;
        }
        self.current = next;
        Some(next)
    }
}
