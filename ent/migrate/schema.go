// Code generated by ent, DO NOT EDIT.

package migrate

import (
	"entgo.io/ent/dialect/sql/schema"
	"entgo.io/ent/schema/field"
)

var (
	// AccountsColumns holds the columns for the "accounts" table.
	AccountsColumns = []*schema.Column{
		{Name: "id", Type: field.TypeInt, Increment: true},
		{Name: "name", Type: field.TypeString, Unique: true},
		{Name: "created_at", Type: field.TypeTime},
		{Name: "updated_at", Type: field.TypeTime},
	}
	// AccountsTable holds the schema information for the "accounts" table.
	AccountsTable = &schema.Table{
		Name:       "accounts",
		Columns:    AccountsColumns,
		PrimaryKey: []*schema.Column{AccountsColumns[0]},
	}
	// PrivateKeysColumns holds the columns for the "private_keys" table.
	PrivateKeysColumns = []*schema.Column{
		{Name: "id", Type: field.TypeString, Unique: true},
		{Name: "kty", Type: field.TypeString},
		{Name: "alg", Type: field.TypeString, Nullable: true},
		{Name: "private", Type: field.TypeBool, Default: false},
		{Name: "jwk", Type: field.TypeJSON},
		{Name: "created_at", Type: field.TypeTime},
		{Name: "updated_at", Type: field.TypeTime},
		{Name: "account_keys", Type: field.TypeInt, Nullable: true},
	}
	// PrivateKeysTable holds the schema information for the "private_keys" table.
	PrivateKeysTable = &schema.Table{
		Name:       "private_keys",
		Columns:    PrivateKeysColumns,
		PrimaryKey: []*schema.Column{PrivateKeysColumns[0]},
		ForeignKeys: []*schema.ForeignKey{
			{
				Symbol:     "private_keys_accounts_keys",
				Columns:    []*schema.Column{PrivateKeysColumns[7]},
				RefColumns: []*schema.Column{AccountsColumns[0]},
				OnDelete:   schema.SetNull,
			},
		},
	}
	// Tables holds all the tables in the schema.
	Tables = []*schema.Table{
		AccountsTable,
		PrivateKeysTable,
	}
)

func init() {
	PrivateKeysTable.ForeignKeys[0].RefTable = AccountsTable
}
