import Effects
import Observe
import Resource
import Api

# Any S3-compatible store: real S3, Google Cloud Storage through its XML API,
# Cloudflare R2, MinIO. The instance chooses the vendor; an application writes the
# same thing either way.
#
# **An application never holds an object's bytes.** It asks for an authorization
# and hands that to whoever is transferring — a browser, a worker, a provider — and
# the transfer happens directly between that client and the store. Two things
# follow, and both are the point rather than a limitation:
#
# A 300-MiB video never has to fit through a 64-KiB observation, so size stops
# being the platform's problem. And an application that cannot hold the bytes
# cannot leak them: the worst a compromised handler can do is authorize an object
# its grant already covers.
#
# The grant is the whole of the authority. A resource names a bucket and a key
# prefix, and an authorization is refused for any key outside it — before anything
# is signed, because a presigned URL cannot be recalled once it has been given out.
ObjectStore :: [].{
	upload_effect = Api.external("object_store.grant_upload.v1")

	# What a client needs to perform one transfer, and nothing else.
	Authorization : {
		# Valid for this one object and this one method. The signature covers the
		# key, the method and the expiry, so a holder cannot retarget it.
		url : Str,
		# Seconds from issue. Short by design: an authorization is a bearer
		# capability, and its window is the whole of its containment.
		expires_in : U64,
		# The object this authorization actually names.
		#
		# For an upload it is not the key that was asked for: the host inserts a
		# segment of its own, so two uploads never land on one object and an
		# upload can never overwrite what is already there. Store it — it is how
		# the object is found again.
		key : Str,
	}

	# Authorize a client to upload one object.
	#
	# A write, though it changes nothing in the store yet: it admits new bytes into
	# a bucket, and that is the act worth budgeting and auditing. The object exists
	# once the client finishes; ask `head` if the application needs to know.
	# The key is a request, not the final name: the object lands under it with a
	# host-assigned segment inserted, and the authorization says where. That is
	# what makes overwriting inexpressible rather than merely discouraged — an
	# application cannot name an object that already exists.
	grant_upload : Resource, Str -> Effects(Authorization)
	grant_upload = |resource, key| Effects.capability(
		"object_store.grant_upload.v1",
		Json.to_str({ handle: Resource.token(resource), key }),
	).and_then(
		|raw| {
			parsed : Try(Authorization, _)
			parsed = Json.parse(raw)
			Effects.from_host(parsed.map_err(|_| "invalid_object_authorization"))
		},
	)

	# What the store reports about one object. No bytes, by construction.
	Metadata : {
		exists : Bool,
		size : U64,
		etag : Str,
		last_modified : Str,
	}

	# Whether an object is there, and how big it is.
	#
	# Absence is an answer rather than a failure: asking "is this there?" is
	# answered as truthfully by no as by yes, and an application that had to catch
	# an error to learn the object is missing would treat a correct answer as a
	# fault.
	head : Resource, Str -> Observe(Metadata)
	head = |resource, key| Observe.capability(
		"object_store.head.v1",
		Json.to_str({ handle: Resource.token(resource), key }),
	).and_then(
		|raw| {
			parsed : Try(Metadata, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_object_metadata"))
		},
	)

	# **There is no delete here.** An application cannot remove an object, the
	# same way it cannot remove a row: it soft-deletes the record that refers to
	# the object, and the bytes stay until an operator's retention policy removes
	# them. A granted application that could destroy bytes would destroy them by
	# accident eventually, and unlike a row there is no version history to
	# recover from. See docs/DELETION.md.

	# Authorize a client to download one object.
	#
	# A read, and prepared rather than effectful: it makes no request to the store,
	# so it can be resolved before a decision the way any other observation is.
	grant_download : Resource, Str -> Observe(Authorization)
	grant_download = |resource, key| Observe.capability(
		"object_store.grant_download.v1",
		Json.to_str({ handle: Resource.token(resource), key }),
	).and_then(
		|raw| {
			parsed : Try(Authorization, _)
			parsed = Json.parse(raw)
			Observe.from_host(parsed.map_err(|_| "invalid_object_authorization"))
		},
	)
}
