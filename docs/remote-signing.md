# Remote JWT Signing

UAA normally holds JWT signing private keys on the VM in plaintext, either in
the BOSH manifest or in a CredHub-interpolated secret that is written to
`config/uaa.yml` at deploy time. Remote signing eliminates that: the private
key never exists on the UAA VM. Instead, UAA sends the token payload to a
signing plugin colocated on the same instance group, receives the signature,
and assembles the final JWT — without ever having access to the raw private key
material.

The feature is activated by setting `signingKeyRef` on a JWT policy key instead
of `signingKey`. The plugin resolves the reference and performs the signing
operation.

---

## How it works

1. A signing plugin is colocated as a BOSH job on the `uaa` instance group.
2. The plugin listens on a Unix domain socket at the fixed path:

   ```
   /var/vcap/sys/run/uaa/remote-signer.sock
   ```

   This path is not configurable. UAA and the plugin must agree on it, and
   independently versioned releases use this fixed path as the contract between
   them. A mismatch (e.g. plugin listening elsewhere) shows up immediately as a
   connection-refused error at token-issuance time.

3. UAA connects to the socket for every signing operation on a key that carries
   `signingKeyRef`.

4. The plugin is authoritative: if the reference is unknown to the plugin, the
   signing request is rejected. The set of usable signing keys is therefore
   under the operator's control via the plugin's own configuration, independent
   of UAA's manifest.

---

## Configuration

### JWT policy key

In your BOSH manifest, declare a key entry using `signingKeyRef` in place of
`signingKey`:

```yaml
uaa.jwt.policy.keys:
  example-key-1:
    signingKeyRef: vault-key-abc123   # reference resolved by the colocated plugin
    signingAlg: RS256

uaa.jwt.policy.active_key_id: example-key-1
```

`signingKey` and `signingKeyRef` are mutually exclusive on the same key entry.
Setting both is an error.

### Colocating the signing plugin

Add your signing plugin job to the `uaa` instance group with an ops file.
The structure below matches what UAA expects:

```yaml
# ops/colocate-signing-plugin.yml
#
# Colocates a signing plugin job on the UAA instance group and configures
# UAA to resolve JWT signing keys through it.

- type: replace
  path: /instance_groups/name=uaa/jobs/-
  value:
    name: signing-plugin
    release: my-signing-plugin
    properties:
      signing_plugin:
        key_references:
          - name: vault-key-abc123
            # plugin-specific key location properties go here

- type: replace
  path: /instance_groups/name=uaa/jobs/name=uaa/properties/uaa/jwt/policy/active_key_id
  value: example-key-1

- type: replace
  path: /instance_groups/name=uaa/jobs/name=uaa/properties/uaa/jwt/policy/keys
  value:
    example-key-1:
      signingKeyRef: vault-key-abc123
      signingAlg: RS256
```

The `my-signing-plugin` release above is illustrative. Substitute your actual
signing plugin release name and job properties.

> **Note:** The `acceptance-tests` job's built-in `softkey` plugin exists solely
> for end-to-end testing with no external credentials. It holds keys in process
> memory and must not be used in production deployments.

---

## Key rotation

Rotation must preserve verifiability of already-issued tokens throughout the
transition. Follow this order:

1. **Add the new key** — add a new entry under `uaa.jwt.policy.keys` with its
   `signingKeyRef` pointing at the new key material in the plugin, but leave
   `uaa.jwt.policy.active_key_id` unchanged. Deploy.

2. **Verify the new key is published** — call UAA's `/token_keys` endpoint and
   confirm the new key ID appears in the response. This means UAA has loaded it
   and will accept tokens verified with it.

3. **Switch the active key** — set `uaa.jwt.policy.active_key_id` to the new
   key ID and deploy. UAA will sign new tokens with the new key from this point.

4. **Wait for old tokens to expire** — tokens signed with the previous key
   remain verifiable as long as the old key entry stays in `uaa.jwt.policy.keys`.
   Remove the old key entry only after its tokens have expired (or after a forced
   token revocation, if appropriate).

Do not remove the old key entry before step 4 is complete. Doing so will cause
resource servers to reject still-valid tokens signed with that key.

---

## Failure behaviour

When the signing plugin is unavailable or rejects a key reference:

- **Token issuance fails** — UAA cannot sign new tokens and returns an error to
  the requesting client. Existing sessions are interrupted.
- **Token verification continues** — UAA's public key endpoint (`/token_keys`)
  remains available and already-issued tokens can still be verified by resource
  servers, because verification uses the public key only and does not involve
  the plugin.

An unknown `signingKeyRef` (a reference the plugin does not recognise) is
rejected at signing time, not at deploy time. Deploy-time validation confirms
the property is set; runtime validation confirms the plugin can resolve it.
