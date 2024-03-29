// Code generated by ent, DO NOT EDIT.

package ent

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/evidenceledger/gosiop2/ent/account"
	"github.com/evidenceledger/gosiop2/ent/privatekey"
)

// PrivateKey is the model entity for the PrivateKey schema.
type PrivateKey struct {
	config `json:"-"`
	// ID of the ent.
	ID string `json:"id,omitempty"`
	// Kty holds the value of the "kty" field.
	Kty string `json:"kty,omitempty"`
	// Alg holds the value of the "alg" field.
	Alg string `json:"alg,omitempty"`
	// Jwk holds the value of the "jwk" field.
	Jwk []uint8 `json:"jwk,omitempty"`
	// CreatedAt holds the value of the "created_at" field.
	CreatedAt time.Time `json:"created_at,omitempty"`
	// UpdatedAt holds the value of the "updated_at" field.
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the PrivateKeyQuery when eager-loading is set.
	Edges        PrivateKeyEdges `json:"edges"`
	account_keys *int
}

// PrivateKeyEdges holds the relations/edges for other nodes in the graph.
type PrivateKeyEdges struct {
	// Account holds the value of the account edge.
	Account *Account `json:"account,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [1]bool
}

// AccountOrErr returns the Account value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e PrivateKeyEdges) AccountOrErr() (*Account, error) {
	if e.loadedTypes[0] {
		if e.Account == nil {
			// The edge account was loaded in eager-loading,
			// but was not found.
			return nil, &NotFoundError{label: account.Label}
		}
		return e.Account, nil
	}
	return nil, &NotLoadedError{edge: "account"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*PrivateKey) scanValues(columns []string) ([]interface{}, error) {
	values := make([]interface{}, len(columns))
	for i := range columns {
		switch columns[i] {
		case privatekey.FieldJwk:
			values[i] = new([]byte)
		case privatekey.FieldID, privatekey.FieldKty, privatekey.FieldAlg:
			values[i] = new(sql.NullString)
		case privatekey.FieldCreatedAt, privatekey.FieldUpdatedAt:
			values[i] = new(sql.NullTime)
		case privatekey.ForeignKeys[0]: // account_keys
			values[i] = new(sql.NullInt64)
		default:
			return nil, fmt.Errorf("unexpected column %q for type PrivateKey", columns[i])
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the PrivateKey fields.
func (pk *PrivateKey) assignValues(columns []string, values []interface{}) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case privatekey.FieldID:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value.Valid {
				pk.ID = value.String
			}
		case privatekey.FieldKty:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field kty", values[i])
			} else if value.Valid {
				pk.Kty = value.String
			}
		case privatekey.FieldAlg:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field alg", values[i])
			} else if value.Valid {
				pk.Alg = value.String
			}
		case privatekey.FieldJwk:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field jwk", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &pk.Jwk); err != nil {
					return fmt.Errorf("unmarshal field jwk: %w", err)
				}
			}
		case privatekey.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				pk.CreatedAt = value.Time
			}
		case privatekey.FieldUpdatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field updated_at", values[i])
			} else if value.Valid {
				pk.UpdatedAt = value.Time
			}
		case privatekey.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for edge-field account_keys", value)
			} else if value.Valid {
				pk.account_keys = new(int)
				*pk.account_keys = int(value.Int64)
			}
		}
	}
	return nil
}

// QueryAccount queries the "account" edge of the PrivateKey entity.
func (pk *PrivateKey) QueryAccount() *AccountQuery {
	return (&PrivateKeyClient{config: pk.config}).QueryAccount(pk)
}

// Update returns a builder for updating this PrivateKey.
// Note that you need to call PrivateKey.Unwrap() before calling this method if this PrivateKey
// was returned from a transaction, and the transaction was committed or rolled back.
func (pk *PrivateKey) Update() *PrivateKeyUpdateOne {
	return (&PrivateKeyClient{config: pk.config}).UpdateOne(pk)
}

// Unwrap unwraps the PrivateKey entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (pk *PrivateKey) Unwrap() *PrivateKey {
	_tx, ok := pk.config.driver.(*txDriver)
	if !ok {
		panic("ent: PrivateKey is not a transactional entity")
	}
	pk.config.driver = _tx.drv
	return pk
}

// String implements the fmt.Stringer.
func (pk *PrivateKey) String() string {
	var builder strings.Builder
	builder.WriteString("PrivateKey(")
	builder.WriteString(fmt.Sprintf("id=%v, ", pk.ID))
	builder.WriteString("kty=")
	builder.WriteString(pk.Kty)
	builder.WriteString(", ")
	builder.WriteString("alg=")
	builder.WriteString(pk.Alg)
	builder.WriteString(", ")
	builder.WriteString("jwk=")
	builder.WriteString(fmt.Sprintf("%v", pk.Jwk))
	builder.WriteString(", ")
	builder.WriteString("created_at=")
	builder.WriteString(pk.CreatedAt.Format(time.ANSIC))
	builder.WriteString(", ")
	builder.WriteString("updated_at=")
	builder.WriteString(pk.UpdatedAt.Format(time.ANSIC))
	builder.WriteByte(')')
	return builder.String()
}

// PrivateKeys is a parsable slice of PrivateKey.
type PrivateKeys []*PrivateKey

func (pk PrivateKeys) config(cfg config) {
	for _i := range pk {
		pk[_i].config = cfg
	}
}
