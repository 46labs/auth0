package config

import (
	"encoding/json"
	"reflect"
)

// Handlers serialize stored records outside the storage lock while update
// handlers mutate them under it, so reads hand back a copy. Metadata holds
// arbitrary decoded JSON, so the copy recurses.

// cloneValue deep-copies a metadata value. The typed cases are what
// encoding/json produces; anything else (mapstructure yields concrete types
// like []string) goes through reflection. Structs and arrays are not
// traversed — metadata holds decoded JSON, and unexported fields cannot be set.
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

// cloneAnyMap returns nil for a nil map, so omitempty keys stay absent.
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

// Clone deep-copies the metadata, including nested maps such as org_roles.
func (m AppMetadata) Clone() AppMetadata {
	if m == nil {
		return nil
	}
	return AppMetadata(cloneAnyMap(m))
}

// Clone returns a deep copy of the user. Nil-safe.
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
