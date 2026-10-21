//! Minimal read-only wire shapes from containerd API services/tasks/v1,
//! services/containers/v1, services/version/v1 and Kubernetes CRI runtime/v1.
//! Unknown protobuf fields are not interpreted as authority.

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Empty {}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Version {
    #[prost(string, tag = "1")]
    pub version: String,
    #[prost(string, tag = "2")]
    pub revision: String,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Task {
    #[prost(string, tag = "1")]
    pub container_id: String,
    #[prost(string, tag = "2")]
    pub id: String,
    #[prost(uint32, tag = "3")]
    pub pid: u32,
    #[prost(int32, tag = "4")]
    pub status: i32,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Tasks {
    #[prost(message, repeated, tag = "1")]
    pub tasks: Vec<Task>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct GetTask {
    #[prost(string, tag = "1")]
    pub container_id: String,
    #[prost(string, tag = "2")]
    pub exec_id: String,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct TaskReply {
    #[prost(message, optional, tag = "1")]
    pub process: Option<Task>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct GetContainer {
    #[prost(string, tag = "1")]
    pub id: String,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct ContainerReply {
    #[prost(message, optional, tag = "1")]
    pub container: Option<Container>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Container {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(btree_map = "string, string", tag = "2")]
    pub labels: std::collections::BTreeMap<String, String>,
    #[prost(string, tag = "3")]
    pub image: String,
    #[prost(message, optional, tag = "4")]
    pub runtime: Option<Runtime>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Runtime {
    #[prost(string, tag = "1")]
    pub name: String,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct CriVersionRequest {
    #[prost(string, tag = "1")]
    pub version: String,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct CriVersion {
    #[prost(string, tag = "1")]
    pub version: String,
    #[prost(string, tag = "2")]
    pub runtime_name: String,
    #[prost(string, tag = "3")]
    pub runtime_version: String,
    #[prost(string, tag = "4")]
    pub runtime_api_version: String,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct CriStatusRequest {
    #[prost(string, tag = "1")]
    pub container_id: String,
    #[prost(bool, tag = "2")]
    pub verbose: bool,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct CriStatusReply {
    #[prost(message, optional, tag = "1")]
    pub status: Option<CriStatus>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct CriStatus {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(message, optional, tag = "2")]
    pub metadata: Option<CriMetadata>,
    #[prost(int32, tag = "3")]
    pub state: i32,
    #[prost(string, tag = "9")]
    pub image_ref: String,
    #[prost(btree_map = "string, string", tag = "12")]
    pub labels: std::collections::BTreeMap<String, String>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct CriMetadata {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(uint32, tag = "2")]
    pub attempt: u32,
}
