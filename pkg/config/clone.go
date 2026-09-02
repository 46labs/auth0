package config

import (
	"encoding/json"
	"reflect"
)

// Clone helpers exist because the server hands stored records to handlers that
// serialize them outside the storage lock, while update handlers mutate the
// same records under it. Returning a copy at every read boundary is what makes
// that safe: a reader can never observe a half-applied write.
//
// The metadata maps hold arbitrary decoded JSON (app_metadata.org_roles, an
// organization's metadata), so the copy has to recurse through nested maps and
// slices rather than stopping at the top level.

// cloneValue deep-copies a metadata value. The typed cases are the shapes
// encoding/json produces and cover the hot path; anything else (metadata built
// programmatically, or decoded by mapstructure, which yields concrete types
// like []string) falls through to reflection so no mutable collection is
// returned by reference.
//
// Maps, slices and pointers are rebuilt at every depth. Scalars are returned
// as-is, being immutable. Structs and arrays are not traversed: metadata holds
// decoded JSON, and reflection cannot set unexported struct fields anyway.
func cloneValue(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case string, bool, float64, int, int64, json.Number:
		return v
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = cloneValue(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = cloneValue(val)
		}
		return out
	default:
		rv := cloneReflect(reflect.ValueOf(v))
		if !rv.IsValid() {
			return nil
		}
		return rv.Interface()
	}
}

// cloneReflect deep-copies maps, slices and pointers of any concrete type.
// Other kinds are returned unchanged, being either immutable or untraversable.
func cloneReflect(rv reflect.Value) reflect.Value {
	switch rv.Kind() {
	case reflect.Interface:
		if rv.IsNil() {
			return rv
		}
		out := reflect.New(rv.Type()).Elem()
		out.Set(cloneReflect(rv.Elem()))
		return out

	case reflect.Map:
		if rv.IsNil() {
			return rv
		}
		out := reflect.MakeMapWithSize(rv.Type(), rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			// Keys are scalars in every metadata shape we accept.
			out.SetMapIndex(iter.Key(), cloneReflect(iter.Value()))
		}
		return out

	case reflect.Slice:
		if rv.IsNil() {
			return rv
		}
		out := reflect.MakeSlice(rv.Type(), rv.Len(), rv.Len())
		for i := range rv.Len() {
			out.Index(i).Set(cloneReflect(rv.Index(i)))
		}
		return out

	case reflect.Pointer:
		if rv.IsNil() {
			return rv
		}
		out := reflect.New(rv.Type().Elem())
		out.Elem().Set(cloneReflect(rv.Elem()))
		return out

	default:
		return rv
	}
}

// cloneAnyMap deep-copies a map of decoded JSON. Returns nil for a nil map so
// omitempty keys stay absent on re-serialization.
func cloneAnyMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = cloneValue(v)
	}
	return out
}

// Clone returns a deep copy of the metadata, including nested maps such as
// org_roles. Nil-safe.
func (m AppMetadata) Clone() AppMetadata {
	if m == nil {
		return nil
	}
	return AppMetadata(cloneAnyMap(m))
}

// Clone returns a deep copy of the user, sharing no mutable state with the
// receiver. Nil-safe.
func (u *User) Clone() *User {
	if u == nil {
		return nil
	}
	out := *u
	out.AppMetadata = u.AppMetadata.Clone()
	out.UserMetadata = cloneAnyMap(u.UserMetadata)

	if u.Identities != nil {
		out.Identities = make([]UserIdentity, len(u.Identities))
		copy(out.Identities, u.Identities)
	}
	if u.Organizations != nil {
		out.Organizations = make([]string, len(u.Organizations))
		copy(out.Organizations, u.Organizations)
	}
	if u.Blocked != nil {
		blocked := *u.Blocked
		out.Blocked = &blocked
	}
	if u.LastLogin != nil {
		lastLogin := *u.LastLogin
		out.LastLogin = &lastLogin
	}
	return &out
}

// Clone returns a deep copy of the organization. Nil-safe.
func (o *Organization) Clone() *Organization {
	if o == nil {
		return nil
	}
	out := *o
	out.Metadata = cloneAnyMap(o.Metadata)

	if o.Branding != nil {
		branding := *o.Branding
		if o.Branding.Colors != nil {
			branding.Colors = make(map[string]string, len(o.Branding.Colors))
			for k, v := range o.Branding.Colors {
				branding.Colors[k] = v
			}
		}
		out.Branding = &branding
	}
	return &out
}

// Clone returns a deep copy of the connection. Nil-safe.
func (c *Connection) Clone() *Connection {
	if c == nil {
		return nil
	}
	out := *c
	out.Options = cloneAnyMap(c.Options)

	if c.EnabledClients != nil {
		out.EnabledClients = make([]string, len(c.EnabledClients))
		copy(out.EnabledClients, c.EnabledClients)
	}
	if c.Organizations != nil {
		out.Organizations = make([]string, len(c.Organizations))
		copy(out.Organizations, c.Organizations)
	}
	return &out
}

// Clone returns a deep copy of the client. Nil-safe.
func (c *Client) Clone() *Client {
	if c == nil {
		return nil
	}
	out := *c
	out.JWTConfig = cloneAnyMap(c.JWTConfig)

	if c.Callbacks != nil {
		out.Callbacks = make([]string, len(c.Callbacks))
		copy(out.Callbacks, c.Callbacks)
	}
	if c.GrantTypes != nil {
		out.GrantTypes = make([]string, len(c.GrantTypes))
		copy(out.GrantTypes, c.GrantTypes)
	}
	return &out
}
