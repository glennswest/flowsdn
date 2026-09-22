//! Transport-independent ARM request and recoverable LRO contracts. No live client.
use serde_json::Value;

pub const NETWORK_API: &str = "2024-03-01";
pub const COMPUTE_API: &str = "2024-07-01";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cloud {
    Public,
    Government,
    China,
}
impl Cloud {
    pub fn endpoint(self) -> &'static str {
        match self {
            Self::Public => "https://management.azure.com",
            Self::Government => "https://management.usgovcloudapi.net",
            Self::China => "https://management.chinacloudapi.cn",
        }
    }
    /// A deliberately narrow URL policy: same cloud authority, absolute HTTPS,
    /// no credentials, fragments, escapes in the path, or dot path segments.
    pub fn validate_url(self, url: &str) -> Result<(), &'static str> {
        let rest = url
            .strip_prefix(self.endpoint())
            .and_then(|s| s.strip_prefix('/'))
            .ok_or("foreign ARM authority")?;
        if rest.is_empty()
            || url
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || b == b'\\' || b == b'#')
        {
            return Err("invalid ARM URL");
        }
        let path = rest.split('?').next().ok_or("missing path")?;
        if path.contains('%') || path.split('/').any(|s| s == "." || s == "..") {
            return Err("ambiguous ARM path");
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation<'a> {
    ListNics,
    GetNic(&'a str),
    PutNic(&'a str),
    ListScaleSets,
    ListScaleSetNics(&'a str),
    ListVmNics(&'a str, &'a str),
    GetVm(&'a str, &'a str),
    UpdateVm(&'a str, &'a str),
    GetStandaloneVm(&'a str),
    GetSubnet(&'a str, &'a str),
    ListPublicPrefixes,
    GetPublicIp(&'a str),
    ListVmPublicIps(&'a str, &'a str, &'a str, &'a str),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub method: &'static str,
    pub url: String,
    pub long_running: bool,
}
fn segment(s: &str) -> Result<&str, &'static str> {
    if s.is_empty()
        || s == "."
        || s == ".."
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err("unsupported resource name");
    }
    Ok(s)
}
pub fn request(
    cloud: Cloud,
    subscription: &str,
    group: &str,
    operation: Operation<'_>,
) -> Result<Request, &'static str> {
    let base = format!(
        "{}/subscriptions/{}/resourceGroups/{}/providers",
        cloud.endpoint(),
        segment(subscription)?,
        segment(group)?
    );
    let (provider, path, method, expand) = match operation {
        Operation::ListNics => ("Network", "networkInterfaces".to_owned(), "GET", false),
        Operation::GetNic(n) => (
            "Network",
            format!("networkInterfaces/{}", segment(n)?),
            "GET",
            false,
        ),
        Operation::PutNic(n) => (
            "Network",
            format!("networkInterfaces/{}", segment(n)?),
            "PUT",
            false,
        ),
        Operation::ListScaleSets => (
            "Compute",
            "virtualMachineScaleSets".to_owned(),
            "GET",
            false,
        ),
        Operation::ListScaleSetNics(s) => (
            "Compute",
            format!("virtualMachineScaleSets/{}/networkInterfaces", segment(s)?),
            "GET",
            false,
        ),
        Operation::ListVmNics(s, v) => (
            "Compute",
            format!(
                "virtualMachineScaleSets/{}/virtualMachines/{}/networkInterfaces",
                segment(s)?,
                segment(v)?
            ),
            "GET",
            false,
        ),
        Operation::GetVm(s, v) => (
            "Compute",
            format!(
                "virtualMachineScaleSets/{}/virtualMachines/{}",
                segment(s)?,
                segment(v)?
            ),
            "GET",
            true,
        ),
        Operation::UpdateVm(s, v) => (
            "Compute",
            format!(
                "virtualMachineScaleSets/{}/virtualMachines/{}",
                segment(s)?,
                segment(v)?
            ),
            "PUT",
            false,
        ),
        Operation::GetStandaloneVm(v) => (
            "Compute",
            format!("virtualMachines/{}", segment(v)?),
            "GET",
            false,
        ),
        Operation::GetSubnet(v, s) => (
            "Network",
            format!("virtualNetworks/{}/subnets/{}", segment(v)?, segment(s)?),
            "GET",
            false,
        ),
        Operation::ListPublicPrefixes => ("Network", "publicIPPrefixes".to_owned(), "GET", false),
        Operation::GetPublicIp(n) => (
            "Network",
            format!("publicIPAddresses/{}", segment(n)?),
            "GET",
            false,
        ),
        Operation::ListVmPublicIps(s, v, n, i) => (
            "Compute",
            format!(
                "virtualMachineScaleSets/{}/virtualMachines/{}/networkInterfaces/{}/ipConfigurations/{}/publicIPAddresses",
                segment(s)?,
                segment(v)?,
                segment(n)?,
                segment(i)?
            ),
            "GET",
            false,
        ),
    };
    // Network operations nested under Microsoft.Compute still use Network's API.
    let network = provider == "Network"
        || path.ends_with("networkInterfaces")
        || path.ends_with("publicIPAddresses");
    let api = if network { NETWORK_API } else { COMPUTE_API };
    Ok(Request {
        method,
        url: format!(
            "{base}/Microsoft.{provider}/{path}?api-version={api}{}",
            if expand { "&$expand=instanceView" } else { "" }
        ),
        long_running: method != "GET",
    })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Monitor {
    AsyncOperation,
    Location,
    Resource,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Waiting {
        url: String,
        monitor: Monitor,
        delay_seconds: u64,
    },
    FetchResource,
    Succeeded,
    Failed,
    Canceled,
}
/// Store this object durably after each accepted response before releasing any
/// local ownership. Transport errors never mutate it or imply remote completion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poller {
    cloud: Cloud,
    resource: String,
    state: State,
}
#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Value,
}
impl Response {
    fn header(&self, name: &str) -> Result<Option<&str>, &'static str> {
        let mut matches = self
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name));
        let value = matches.next().map(|(_, v)| v.as_str());
        if matches.next().is_some() {
            return Err("duplicate control header");
        }
        Ok(value)
    }
    fn delay(&self) -> Result<u64, &'static str> {
        self.header("Retry-After")?.map_or(Ok(5), |v| {
            v.parse().map_err(|_| "Retry-After must be seconds")
        })
    }
}
fn terminal(value: &str) -> Option<State> {
    if value.eq_ignore_ascii_case("Succeeded") {
        Some(State::Succeeded)
    } else if value.eq_ignore_ascii_case("Failed") {
        Some(State::Failed)
    } else if value.eq_ignore_ascii_case("Canceled") {
        Some(State::Canceled)
    } else {
        None
    }
}
// Absence means success only for a well-formed resource object. An explicit
// null/non-string state is a malformed response, never completion evidence.
fn provisioning_state(body: &Value) -> Result<Option<&str>, &'static str> {
    let object = body
        .as_object()
        .ok_or("resource response must be an object")?;
    let Some(properties) = object.get("properties") else {
        return Ok(None);
    };
    let properties = properties
        .as_object()
        .ok_or("resource properties must be an object")?;
    match properties.get("provisioningState") {
        None => Ok(None),
        Some(Value::String(state)) if !state.is_empty() => Ok(Some(state)),
        Some(_) => Err("provisioningState must be a nonempty string"),
    }
}
impl Poller {
    pub fn begin(
        cloud: Cloud,
        resource: String,
        response: &Response,
    ) -> Result<Self, &'static str> {
        cloud.validate_url(&resource)?;
        if !matches!(response.status, 200 | 201 | 202) {
            return Err("mutation not accepted");
        }
        let state = if let Some(url) = response.header("Azure-AsyncOperation")? {
            cloud.validate_url(url)?;
            State::Waiting {
                url: url.to_owned(),
                monitor: Monitor::AsyncOperation,
                delay_seconds: response.delay()?,
            }
        } else if let Some(url) = response.header("Location")? {
            cloud.validate_url(url)?;
            State::Waiting {
                url: url.to_owned(),
                monitor: Monitor::Location,
                delay_seconds: response.delay()?,
            }
        } else if let Some(status) = provisioning_state(&response.body)? {
            terminal(status).unwrap_or(State::Waiting {
                url: resource.clone(),
                monitor: Monitor::Resource,
                delay_seconds: response.delay()?,
            })
        } else if response.status == 202 {
            return Err("accepted operation missing monitor");
        } else {
            State::Succeeded
        };
        Ok(Self {
            cloud,
            resource,
            state,
        })
    }
    pub fn state(&self) -> &State {
        &self.state
    }
    pub fn resource_url(&self) -> &str {
        &self.resource
    }
    /// Neither a cancelled waiter nor timeout changes the remote operation state.
    pub fn may_release_ownership(&self) -> bool {
        matches!(
            self.state,
            State::Succeeded | State::Failed | State::Canceled
        )
    }
    pub fn observe(&mut self, response: &Response) -> Result<(), &'static str> {
        let next = match &self.state {
            State::Waiting { url, monitor, .. } => {
                if response.status == 429 || (500..=599).contains(&response.status) {
                    State::Waiting {
                        url: url.clone(),
                        monitor: *monitor,
                        delay_seconds: response.delay()?,
                    }
                } else {
                    if !matches!(response.status, 200 | 201 | 202 | 204) {
                        return Err("poll HTTP error; ownership retained");
                    }
                    let status = match monitor {
                        Monitor::AsyncOperation => response
                            .body
                            .get("status")
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty()),
                        // A Location monitor may have no body while pending or
                        // on204 completion. Neither directly releases ownership.
                        Monitor::Location
                            if matches!(response.status, 202 | 204) && response.body.is_null() =>
                        {
                            None
                        }
                        _ => provisioning_state(&response.body)?,
                    };
                    if *monitor == Monitor::AsyncOperation && status.is_none() {
                        return Err("missing operation status");
                    }
                    match status.and_then(terminal) {
                        Some(State::Succeeded) => State::FetchResource,
                        Some(state) => state,
                        None if status.is_some() || response.status == 202 => State::Waiting {
                            url: url.clone(),
                            monitor: *monitor,
                            delay_seconds: response.delay()?,
                        },
                        None => State::FetchResource,
                    }
                }
            }
            State::FetchResource => {
                if response.status != 200 {
                    return Err("final resource GET failed; ownership retained");
                }
                match provisioning_state(&response.body)? {
                    Some(status) => terminal(status).ok_or("final resource still provisioning")?,
                    None => State::Succeeded,
                }
            }
            _ => return Err("operation already terminal"),
        };
        self.state = next;
        Ok(())
    }
    pub fn checkpoint(&self) -> Value {
        let (kind, url, delay) = match &self.state {
            State::Waiting {
                url,
                monitor,
                delay_seconds,
            } => (
                match monitor {
                    Monitor::AsyncOperation => "async",
                    Monitor::Location => "location",
                    Monitor::Resource => "resource",
                },
                url.as_str(),
                *delay_seconds,
            ),
            State::FetchResource => ("fetch", "", 0),
            State::Succeeded => ("succeeded", "", 0),
            State::Failed => ("failed", "", 0),
            State::Canceled => ("canceled", "", 0),
        };
        serde_json::json!({"version":1,"endpoint":self.cloud.endpoint(),"resource":self.resource,"state":kind,"url":url,"delay":delay})
    }
    pub fn restore(value: &Value) -> Result<Self, &'static str> {
        if value.get("version").and_then(Value::as_u64) != Some(1) {
            return Err("checkpoint version");
        }
        let cloud = [Cloud::Public, Cloud::Government, Cloud::China]
            .into_iter()
            .find(|c| value.get("endpoint").and_then(Value::as_str) == Some(c.endpoint()))
            .ok_or("checkpoint cloud")?;
        let resource = value
            .get("resource")
            .and_then(Value::as_str)
            .ok_or("checkpoint resource")?
            .to_owned();
        cloud.validate_url(&resource)?;
        let state = match value
            .get("state")
            .and_then(Value::as_str)
            .ok_or("checkpoint state")?
        {
            "async" | "location" | "resource" => {
                let url = value
                    .get("url")
                    .and_then(Value::as_str)
                    .ok_or("checkpoint URL")?
                    .to_owned();
                cloud.validate_url(&url)?;
                let monitor = match value.get("state").and_then(Value::as_str) {
                    Some("async") => Monitor::AsyncOperation,
                    Some("location") => Monitor::Location,
                    _ => Monitor::Resource,
                };
                State::Waiting {
                    url,
                    monitor,
                    delay_seconds: value
                        .get("delay")
                        .and_then(Value::as_u64)
                        .ok_or("checkpoint delay")?,
                }
            }
            "fetch" => State::FetchResource,
            "succeeded" => State::Succeeded,
            "failed" => State::Failed,
            "canceled" => State::Canceled,
            _ => return Err("checkpoint state"),
        };
        Ok(Self {
            cloud,
            resource,
            state,
        })
    }
}
/// Validate every page URL before attaching a bearer token. The transport owns
/// cycle detection and page budgets; API version on continuation URLs is opaque.
pub fn next_page(cloud: Cloud, body: &Value) -> Result<Option<String>, &'static str> {
    match body.get("nextLink") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(url)) if url.is_empty() => Ok(None),
        Some(Value::String(url)) => {
            cloud.validate_url(url)?;
            Ok(Some(url.clone()))
        }
        _ => Err("invalid nextLink"),
    }
}
/// Preserve unknown model fields while omitting the immutable image reference
/// before a VMSS VM update. IP configuration allocation remains allocator work.
pub fn prepare_vm_update(mut model: Value) -> Result<Value, &'static str> {
    if !model.is_object() {
        return Err("VM model must be an object");
    }
    if let Some(storage) = model.pointer_mut("/properties/storageProfile") {
        storage
            .as_object_mut()
            .ok_or("storageProfile must be an object")?
            .remove("imageReference");
    }
    Ok(model)
}
