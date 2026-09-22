//! Typed field separation for force-HTTPS route planning. This is not an Envoy
//! encoder; the eventual translator must retain these fields independently.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StringMatch { Exact(String), Prefix(String), Regex(String), Any }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderMatch { pub name: String, pub value: StringMatch }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryMatch { pub name: String, pub value: StringMatch }
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RouteMatches { pub headers: Vec<HeaderMatch>, pub query_parameters: Vec<QueryMatch> }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpsRedirect { pub matches: RouteMatches, pub status_code: u16 }
/// Named fields and distinct element types prevent swapping headers/queries
/// through two positional lists with identical types (#281).
pub fn force_https(matches: RouteMatches) -> HttpsRedirect { HttpsRedirect { matches, status_code: 301 } }
