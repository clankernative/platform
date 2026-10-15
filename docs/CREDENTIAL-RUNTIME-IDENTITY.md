# Native runtime identity observations

The credential bootstrap path needs a current native runtime identity before it can authorize an initial epoch write. Kubernetes response data does not establish which Pod contains the calling process.

This slice adds the first native observation primitive and bounded response codecs. It does not expose a runtime binding or a production bootstrap execution factory.

## Retained native observation

`NativeNamespaceObservation` retains the actual proc root, kernel self-task directory, task stat/status files, time namespace offsets file, and six namespace descriptors. Acquisition starts under the existing original Linux BOOTTIME deadline. Every fixed open is bracketed by checks against that same acquisition.

Revalidation checks the actual process and Rust thread, original acquisition domain, a freshly opened fixed `/proc/thread-self` path, exact proc device/inode/mount ID, full task identity, retained and freshly opened namespace identities, and complete unchanged zero time offsets. Missing procfs/nsfs support, mount ID, namespace, bounds or current facts refuses the observation and acquisition permanently.

The owning handle cannot clone, serialize, send between threads or be reconstructed from its serializable data. Consuming it into `NamespaceFacts` discards the descriptors and produces historical data.

Mappings are read completely within explicit byte, entry and path bounds. Mapping addresses, file identity and permissions are data; they do not certify image membership or immutable executed memory.

## Selected container data

The response codec joins the selected container to the exact TokenReview Pod UID and existing role/lifecycle checks. It requires the supported containerd identifier and both configured image and current image status to match the selected immutable SHA256 image digest. A running container may be unready because readiness can depend on bootstrap completion.

These joins remain response data. They cannot mint a role capability or reconstruct a native observation.

## Remaining runtime join

Production enrollment still requires a qualified trusted native issuer that joins the current process incarnation, actual container/sandbox/Pod, image and node initial time namespace. Projected Pod UID, cgroup text, Kubernetes status, zero offsets, historical receipts or a peer PID alone do not establish that join. The endpoint, kernel process handle, issuer/runtime profile and deployment must be implemented and qualified before the production factory can become available.
