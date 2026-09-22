//! Typed field separation for force-HTTPS route planning. This is not an Envoy
//! full translator; the bounded Envoy JSON projection preserves field ownership.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StringMatch {
    Exact(String),
    Prefix(String),
    Regex(String),
    Any,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderMatch {
    pub name: String,
    pub value: StringMatch,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryMatch {
    pub name: String,
    pub value: StringMatch,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RouteMatches {
    pub headers: Vec<HeaderMatch>,
    pub query_parameters: Vec<QueryMatch>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpsRedirect {
    pub matches: RouteMatches,
    pub status_code: u16,
}
/// Named fields and distinct element types prevent swapping headers/queries
/// through two positional lists with identical types (#281).
pub fn force_https(matches: RouteMatches) -> HttpsRedirect {
    HttpsRedirect {
        matches,
        status_code: 301,
    }
}

impl HttpsRedirect {
    /// Project this bounded route to Envoy's protobuf-JSON field names. Host
    /// authority and method matchers can be supplied as explicit headers;
    /// caller supplies spec21 matcher ordering; virtual-host aggregation and protobuf/xDS transport remain caller work.
    pub fn envoy_route(&self, path: &StringMatch) -> Result<serde_json::Value, &'static str> {
        use serde_json::{Value, json};
        if self.status_code != 301 {
            return Err("force HTTPS requires status301");
        }
        if let StringMatch::Exact(value) | StringMatch::Prefix(value) = path
            && !value.is_empty()
            && !value.starts_with('/')
        {
            return Err("route path must start with slash");
        }
        let mut matched = serde_json::Map::new();
        match path {
            StringMatch::Exact(value) if !value.is_empty() => {
                matched.insert("path".into(), json!(value));
            }
            StringMatch::Prefix(value) if !value.trim_end_matches('/').is_empty() => {
                matched.insert(
                    "pathSeparatedPrefix".into(),
                    json!(value.trim_end_matches('/')),
                );
            }
            StringMatch::Regex(value) if !value.is_empty() => {
                matched.insert("safeRegex".into(), json!({"regex":value}));
            }
            _ => {
                matched.insert("prefix".into(), json!("/"));
            }
        }
        let headers = self
            .matches
            .headers
            .iter()
            .map(|m| {
                if m.name.is_empty() {
                    return Err("empty header matcher name");
                }
                let mut entry = serde_json::Map::from_iter([("name".into(), json!(m.name))]);
                let (field, value) = project_string(&m.value);
                entry.insert(field.into(), value);
                Ok(Value::Object(entry))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let queries = self
            .matches
            .query_parameters
            .iter()
            .map(|m| {
                if m.name.is_empty() {
                    return Err("empty query matcher name");
                }
                let mut entry = serde_json::Map::from_iter([("name".into(), json!(m.name))]);
                let (field, value) = project_string(&m.value);
                entry.insert(field.into(), value);
                Ok(Value::Object(entry))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if !headers.is_empty() {
            matched.insert("headers".into(), Value::Array(headers));
        }
        if !queries.is_empty() {
            matched.insert("queryParameters".into(), Value::Array(queries));
        }
        // Omitting responseCode preserves Envoy's MOVED_PERMANENTLY default.
        Ok(json!({"match":matched,"redirect":{"httpsRedirect":true}}))
    }
}
fn project_string(value: &StringMatch) -> (&'static str, serde_json::Value) {
    use serde_json::json;
    match value {
        StringMatch::Exact(v) => ("stringMatch", json!({"exact":v})),
        StringMatch::Prefix(v) => ("stringMatch", json!({"prefix":v})),
        StringMatch::Regex(v) => ("stringMatch", json!({"safeRegex":{"regex":v}})),
        StringMatch::Any => ("presentMatch", json!(true)),
    }
}
