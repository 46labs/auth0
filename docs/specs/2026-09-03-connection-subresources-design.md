# Per-Connection Management API Subresources

Consumer: `pee:docs/superpowers/specs/2026-09-01-tenant-onboarding-invite-first-admin-design.md`,
phase 6 (`auth0.EnsureConnection` and `POST /platform/tenants/{id}/connections`).

## Why

PEE's primary onboarding path is no longer invitations. A 46labs operator takes a customer's
IdP details, PEE creates the enterprise connection through the Management API, binds it to the
customer's organization with auto-membership, and the customer's directory signs in against it.
Invitations are the secondary path, for an organization that already has a connection.

That makes connection provisioning a first-class flow rather than fixture data, and it has to
be idempotent: re-running it with corrected IdP details must converge, not duplicate.

## What exists at 0.1.32

Probed against the published image booted on PEE's rendered `dev/auth` config.

| Endpoint | Now |
|---|---|
| `POST /api/v2/connections` | 201, and honours `enabled_clients` on create |
| `GET /api/v2/connections` | 200 |
| `GET /api/v2/connections?name=` | 200 |
| `POST /api/v2/organizations/{id}/enabled_connections` | 201, 409 when already bound |
| `GET /api/v2/connections/{id}` | 404 |
| `PATCH /api/v2/connections/{id}` | 404 |
| `DELETE /api/v2/connections/{id}` | 404 |
| `GET /api/v2/connections/{id}/clients` | 404 |
| `PATCH /api/v2/connections/{id}/clients` | 404 |

Create plus name-filtered list is enough for a first `EnsureConnection`, so this is not
blocking. Everything after the first successful create is not.

## Status

Implemented on this branch. The table above is what 0.1.32 shipped; everything below now
exists.

## Needed

1. **`GET /api/v2/connections/{id}`**. Read-back after create, and the natural way to confirm a
   connection's strategy and options before reusing it. `ConnectionManager.Read`.

2. **`PATCH /api/v2/connections/{id}`**. Re-provisioning with corrected IdP details. A customer
   rotating an OIDC client secret, or supplying SAML metadata that was wrong the first time,
   currently has no path that converges: create returns a conflict and nothing can update.
   `ConnectionManager.Update`. Note Auth0's semantics here, `options` is replaced wholesale
   rather than merged, so the mock should overwrite rather than deep-merge.

3. **`GET` and `PATCH /api/v2/connections/{id}/clients`**. This is the one with teeth. An Auth0
   connection must be enabled on **two** things or login fails: the organization, and the
   application that calls `/authorize`. Create accepts `enabled_clients`, so a connection PEE
   creates is fine, but a connection that already exists and needs the SPA client added has no
   route. `ConnectionManager.ReadEnabledClients` / `UpdateEnabledClients`, which hit
   `/connections/{id}/clients`, not `/connections/{id}`.

4. **`DELETE /api/v2/connections/{id}`**. Lower value, listed for symmetry and so tests can
   clean up after themselves rather than leaking connections across runs.

## Shapes

`Connection.Name` is alphanumeric-and-hyphen only, max 128, per the pinned SDK. PEE derives
connection names from the organization and sanitizes them, so the mock does not need to
enforce this, but rejecting an invalid name the way Auth0 does would catch a consumer bug
earlier.

`UpdateEnabledClients` sends a JSON array, not an object:

```json
[{"client_id": "peeredge_web", "status": true}]
```

## Verification

Tests are driven through `go-auth0` v1.42.0 rather than hand-rolled HTTP, since the SDK's
decoding is what actually has to hold. `ReadEnabledClients` returns `clients` as a pointer to
slice, so the payload is an object wrapper, not the bare array `UpdateEnabledClients` sends.

Four behaviours are pinned against the SDK's own recordings rather than the published docs
page, which disagrees with them:

- `DELETE /connections/{id}` answers **202** with a `deleted_at` body, not 204
  (`TestConnectionManager_Delete.yaml`), and removes the connection's users along with it, per
  the SDK's documented contract.
- `GET /connections/{id}/clients` carries `client_id` only
  (`TestConnectionManager_EnabledClients.yaml`). Echoing `status` back would make the SDK's
  `GetStatus()` report true locally and false against Auth0.

`config.Connection` has nowhere to keep connection metadata, so `PATCH` rejects it with 400
rather than accepting a write the next read would lose.

Two behavioural tests were checked against a deliberately broken implementation:

- treating the clients array as a replacement rather than a delta drops
  `mgmt_client_dev`
- skipping the pairing cleanup leaves `org_test` enabling a connection that no longer exists

The remaining consumer check is PEE's `auth0.EnsureConnection` reaching read-or-create and
enabled-clients convergence against a published image carrying this.
