//! The suite's Kubernetes API use: this pod and its node, the cluster's
//! nodes (a declared cluster read), and pods, Services and NetworkPolicies in
//! the run's own namespace, each labelled with the run id. Blocking calls
//! over flowsdn-k8s's JSON client (Fedora OpenSSL).
use flowsdn_k8s::client::{JsonClient, TransportLimits};
use http::Method;
use serde_json::{Value, json};
use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

pub type Result<T> = std::result::Result<T, String>;

pub struct Kube {
    runtime: tokio::runtime::Runtime,
    client: JsonClient,
    pub namespace: String,
    pub run_id: String,
}

/// Where a server pod runs and how to reach it.
#[derive(Clone, Debug)]
pub struct Placed {
    pub name: String,
    pub node: String,
    pub ip: IpAddr,
    /// Create to `status.podIP` (the pod's network is set up).
    pub ip_after: Duration,
}

impl Kube {
    /// In-cluster credentials. The runner passes `STORM_API`; when the
    /// kubelet set no `KUBERNETES_SERVICE_HOST`, it is taken from there.
    pub fn connect(namespace: String, run_id: String) -> Result<Self> {
        if std::env::var_os("KUBERNETES_SERVICE_HOST").is_none()
            && let Ok(api) = std::env::var("STORM_API")
            && let Some((host, port)) = api
                .trim_start_matches("https://")
                .trim_end_matches('/')
                .rsplit_once(':')
        {
            #[allow(unsafe_code)]
            // SAFETY: called before the runtime or any other thread exists.
            unsafe {
                std::env::set_var("KUBERNETES_SERVICE_HOST", host.trim_matches(['[', ']']));
                std::env::set_var("KUBERNETES_SERVICE_PORT", port);
            }
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let client = runtime
            .block_on(JsonClient::load(None, TransportLimits::default()))
            .map_err(|e| format!("{e} ({})", in_cluster_inputs()))?;
        Ok(Self {
            runtime,
            client,
            namespace,
            run_id,
        })
    }

    pub fn call(&self, method: Method, path: &str, body: Option<&Value>) -> Result<(u16, Value)> {
        self.runtime
            .block_on(self.client.send_json(method.clone(), path, body))
            .map_err(|e| format!("{method} {path}: {e}"))
    }
    fn ok(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
        let (status, value) = self.call(method.clone(), path, body)?;
        if (200..300).contains(&status) {
            Ok(value)
        } else {
            let message = value
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or_default();
            Err(format!("{method} {path}: HTTP {status} {message}"))
        }
    }
    pub fn get(&self, path: &str) -> Result<Value> {
        self.ok(Method::GET, path, None)
    }
    pub fn create(&self, path: &str, body: &Value) -> Result<Value> {
        self.ok(Method::POST, path, Some(body))
    }
    /// Delete, treating "already gone" as done.
    pub fn delete(&self, path: &str) -> Result<()> {
        let body = json!({"kind":"DeleteOptions","apiVersion":"v1","gracePeriodSeconds":0});
        let (status, value) = self.call(Method::DELETE, path, Some(&body))?;
        if (200..300).contains(&status) || status == 404 {
            Ok(())
        } else {
            Err(format!("DELETE {path}: HTTP {status} {value}"))
        }
    }
    pub fn pods_path(&self) -> String {
        format!("/api/v1/namespaces/{}/pods", self.namespace)
    }
    pub fn services_path(&self) -> String {
        format!("/api/v1/namespaces/{}/services", self.namespace)
    }
    pub fn policies_path(&self) -> String {
        format!(
            "/apis/networking.k8s.io/v1/namespaces/{}/networkpolicies",
            self.namespace
        )
    }
    pub fn slices_path(&self, service: &str) -> String {
        format!(
            "/apis/discovery.k8s.io/v1/namespaces/{}/endpointslices?labelSelector=kubernetes.io%2Fservice-name%3D{service}",
            self.namespace
        )
    }

    /// The labels every object of this run carries, plus `app`.
    pub fn labels(&self, app: &str) -> Value {
        json!({"storm.io/test-run": self.run_id, "app": app})
    }

    /// A pod pinned to `node` (nodeName, so no scheduler round trip) running
    /// `args` of this image.
    pub fn pod(&self, name: &str, app: &str, node: &str, image: &Image, args: &[&str]) -> Value {
        let mut command = vec![json!("/opt/flowsdn/bin/flowsdn-perf")];
        command.extend(args.iter().map(|a| json!(a)));
        json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "labels": self.labels(app)},
            "spec": {
                "nodeName": node,
                "restartPolicy": "Never",
                "terminationGracePeriodSeconds": 0,
                "automountServiceAccountToken": false,
                "tolerations": [{"operator": "Exists"}],
                "containers": [{
                    "name": "perf", "image": image.name, "imagePullPolicy": image.pull_policy,
                    "command": command,
                }],
            },
        })
    }

    /// Poll a pod until it has a pod IP and is Running; returns the IP and the
    /// time from `created`.
    pub fn wait_ip(
        &self,
        name: &str,
        created: Instant,
        timeout: Duration,
    ) -> Result<(IpAddr, Duration)> {
        let path = format!("{}/{name}", self.pods_path());
        loop {
            let pod = self.get(&path)?;
            let phase = pod
                .pointer("/status/phase")
                .and_then(Value::as_str)
                .unwrap_or("");
            if let Some(ip) = pod
                .pointer("/status/podIP")
                .and_then(Value::as_str)
                .and_then(|ip| ip.parse::<IpAddr>().ok())
                && phase == "Running"
            {
                return Ok((ip, created.elapsed()));
            }
            if matches!(phase, "Failed" | "Succeeded") {
                return Err(format!("pod {name} ended: {phase}"));
            }
            if created.elapsed() > timeout {
                return Err(format!(
                    "pod {name} has no pod IP after {timeout:?} (phase {phase:?})"
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Create a server pod on `node` and wait for its pod IP.
    pub fn place_server(&self, name: &str, app: &str, node: &str, image: &Image) -> Result<Placed> {
        let created = Instant::now();
        self.create(
            &self.pods_path(),
            &self.pod(name, app, node, image, &["server"]),
        )?;
        let (ip, ip_after) = self.wait_ip(name, created, Duration::from_secs(180))?;
        Ok(Placed {
            name: name.into(),
            node: node.into(),
            ip,
            ip_after,
        })
    }
}

/// This pod's image, so worker pods run the same build.
#[derive(Clone, Debug)]
pub struct Image {
    pub name: String,
    pub pull_policy: String,
}

/// This pod: its node and image, from its own Pod object (HOSTNAME is the
/// pod name).
pub fn own_pod(kube: &Kube) -> Result<(String, Image, Option<IpAddr>)> {
    let name = std::env::var("HOSTNAME").map_err(|_| "HOSTNAME is not set".to_string())?;
    let pod = kube.get(&format!("{}/{name}", kube.pods_path()))?;
    let node = pod
        .pointer("/spec/nodeName")
        .and_then(Value::as_str)
        .ok_or("own pod has no nodeName")?
        .to_owned();
    let container = pod
        .pointer("/spec/containers/0")
        .ok_or("own pod has no container")?;
    let image = Image {
        name: container
            .get("image")
            .and_then(Value::as_str)
            .ok_or("own container has no image")?
            .to_owned(),
        pull_policy: container
            .get("imagePullPolicy")
            .and_then(Value::as_str)
            .unwrap_or("IfNotPresent")
            .to_owned(),
    };
    let ip = pod
        .pointer("/status/podIP")
        .and_then(Value::as_str)
        .and_then(|ip| ip.parse().ok());
    Ok((node, image, ip))
}

/// Ready, schedulable nodes: (name, allocatable pods).
pub fn nodes(kube: &Kube) -> Result<Vec<(String, u64)>> {
    let list = kube.get("/api/v1/nodes")?;
    Ok(ready_nodes(&list))
}
pub fn ready_nodes(list: &Value) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    for node in list
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let ready = node
            .pointer("/status/conditions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|c| {
                c.get("type") == Some(&json!("Ready")) && c.get("status") == Some(&json!("True"))
            });
        let unschedulable = node.pointer("/spec/unschedulable") == Some(&json!(true));
        let pods = node
            .pointer("/status/allocatable/pods")
            .and_then(Value::as_str)
            .and_then(|p| p.parse().ok())
            .unwrap_or(110);
        if let Some(name) = node.pointer("/metadata/name").and_then(Value::as_str)
            && ready
            && !unschedulable
        {
            out.push((name.to_owned(), pods));
        }
    }
    out
}

/// Ready endpoint addresses of a Service's EndpointSlices.
pub fn ready_endpoints(slices: &Value) -> usize {
    slices
        .get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|s| {
            s.get("endpoints")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter(|e| e.pointer("/conditions/ready") != Some(&json!(false)))
        .map(|e| {
            e.get("addresses")
                .and_then(Value::as_array)
                .map_or(0, Vec::len)
        })
        .sum()
}

/// What in-cluster configuration needs and this pod has, for a failure
/// report: the service variables, the service-account files, and whether
/// `/var/run` leads to `/run` (#321, stormpump#102).
pub fn in_cluster_inputs() -> String {
    const ACCOUNT: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
    let variable = |name: &str| match std::env::var(name) {
        Ok(value) => format!("{name}={value}"),
        Err(_) => format!("{name} unset"),
    };
    let files: Vec<String> = ["token", "ca.crt", "namespace"]
        .iter()
        .map(|f| {
            let present = std::path::Path::new(ACCOUNT).join(f).is_file();
            format!("{f}:{}", if present { "yes" } else { "no" })
        })
        .collect();
    let var_run = match std::fs::read_link("/var/run") {
        Ok(target) => format!("/var/run -> {}", target.display()),
        Err(_) => "/var/run is a directory".into(),
    };
    let secrets = std::fs::read_dir("/run/secrets").map_or_else(
        |e| format!("/run/secrets: {e}"),
        |list| {
            let names: Vec<String> = list
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            format!("/run/secrets: [{}]", names.join(","))
        },
    );
    format!(
        "{}, {}, {ACCOUNT} {}, {var_run}, {secrets}",
        variable("KUBERNETES_SERVICE_HOST"),
        variable("KUBERNETES_SERVICE_PORT"),
        files.join(" ")
    )
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ready_nodes_and_endpoints() {
        let list = json!({"items":[
            {"metadata":{"name":"a"},"status":{"allocatable":{"pods":"250"},
                "conditions":[{"type":"Ready","status":"True"}]}},
            {"metadata":{"name":"b"},"spec":{"unschedulable":true},
                "status":{"conditions":[{"type":"Ready","status":"True"}]}},
            {"metadata":{"name":"c"},"status":{"conditions":[{"type":"Ready","status":"False"}]}},
            {"metadata":{"name":"d"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}
        ]});
        assert_eq!(
            ready_nodes(&list),
            vec![("a".to_owned(), 250), ("d".to_owned(), 110)]
        );
        let slices = json!({"items":[
            {"endpoints":[{"addresses":["10.0.0.1"]},{"addresses":["10.0.0.2"],"conditions":{"ready":false}}]},
            {"endpoints":[{"addresses":["10.0.0.3"],"conditions":{"ready":true}}]}
        ]});
        assert_eq!(ready_endpoints(&slices), 2);
        assert_eq!(ready_endpoints(&json!({})), 0);
    }
}

