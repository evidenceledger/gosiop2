// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"log"

	"github.com/evidenceledger/gosiop2/ent/migrate"

	"github.com/evidenceledger/gosiop2/ent/account"
	"github.com/evidenceledger/gosiop2/ent/credential"
	"github.com/evidenceledger/gosiop2/ent/privatekey"
	"github.com/evidenceledger/gosiop2/ent/publickey"

	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
)

// Client is the client that holds all ent builders.
type Client struct {
	config
	// Schema is the client for creating, migrating and dropping schema.
	Schema *migrate.Schema
	// Account is the client for interacting with the Account builders.
	Account *AccountClient
	// Credential is the client for interacting with the Credential builders.
	Credential *CredentialClient
	// PrivateKey is the client for interacting with the PrivateKey builders.
	PrivateKey *PrivateKeyClient
	// PublicKey is the client for interacting with the PublicKey builders.
	PublicKey *PublicKeyClient
}

// NewClient creates a new client configured with the given options.
func NewClient(opts ...Option) *Client {
	cfg := config{log: log.Println, hooks: &hooks{}}
	cfg.options(opts...)
	client := &Client{config: cfg}
	client.init()
	return client
}

func (c *Client) init() {
	c.Schema = migrate.NewSchema(c.driver)
	c.Account = NewAccountClient(c.config)
	c.Credential = NewCredentialClient(c.config)
	c.PrivateKey = NewPrivateKeyClient(c.config)
	c.PublicKey = NewPublicKeyClient(c.config)
}

// Open opens a database/sql.DB specified by the driver name and
// the data source name, and returns a new client attached to it.
// Optional parameters can be added for configuring the client.
func Open(driverName, dataSourceName string, options ...Option) (*Client, error) {
	switch driverName {
	case dialect.MySQL, dialect.Postgres, dialect.SQLite:
		drv, err := sql.Open(driverName, dataSourceName)
		if err != nil {
			return nil, err
		}
		return NewClient(append(options, Driver(drv))...), nil
	default:
		return nil, fmt.Errorf("unsupported driver: %q", driverName)
	}
}

// Tx returns a new transactional client. The provided context
// is used until the transaction is committed or rolled back.
func (c *Client) Tx(ctx context.Context) (*Tx, error) {
	if _, ok := c.driver.(*txDriver); ok {
		return nil, fmt.Errorf("ent: cannot start a transaction within a transaction")
	}
	tx, err := newTx(ctx, c.driver)
	if err != nil {
		return nil, fmt.Errorf("ent: starting a transaction: %w", err)
	}
	cfg := c.config
	cfg.driver = tx
	return &Tx{
		ctx:        ctx,
		config:     cfg,
		Account:    NewAccountClient(cfg),
		Credential: NewCredentialClient(cfg),
		PrivateKey: NewPrivateKeyClient(cfg),
		PublicKey:  NewPublicKeyClient(cfg),
	}, nil
}

// BeginTx returns a transactional client with specified options.
func (c *Client) BeginTx(ctx context.Context, opts *sql.TxOptions) (*Tx, error) {
	if _, ok := c.driver.(*txDriver); ok {
		return nil, fmt.Errorf("ent: cannot start a transaction within a transaction")
	}
	tx, err := c.driver.(interface {
		BeginTx(context.Context, *sql.TxOptions) (dialect.Tx, error)
	}).BeginTx(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("ent: starting a transaction: %w", err)
	}
	cfg := c.config
	cfg.driver = &txDriver{tx: tx, drv: c.driver}
	return &Tx{
		ctx:        ctx,
		config:     cfg,
		Account:    NewAccountClient(cfg),
		Credential: NewCredentialClient(cfg),
		PrivateKey: NewPrivateKeyClient(cfg),
		PublicKey:  NewPublicKeyClient(cfg),
	}, nil
}

// Debug returns a new debug-client. It's used to get verbose logging on specific operations.
//
//	client.Debug().
//		Account.
//		Query().
//		Count(ctx)
//
func (c *Client) Debug() *Client {
	if c.debug {
		return c
	}
	cfg := c.config
	cfg.driver = dialect.Debug(c.driver, c.log)
	client := &Client{config: cfg}
	client.init()
	return client
}

// Close closes the database connection and prevents new queries from starting.
func (c *Client) Close() error {
	return c.driver.Close()
}

// Use adds the mutation hooks to all the entity clients.
// In order to add hooks to a specific client, call: `client.Node.Use(...)`.
func (c *Client) Use(hooks ...Hook) {
	c.Account.Use(hooks...)
	c.Credential.Use(hooks...)
	c.PrivateKey.Use(hooks...)
	c.PublicKey.Use(hooks...)
}

// AccountClient is a client for the Account schema.
type AccountClient struct {
	config
}

// NewAccountClient returns a client for the Account from the given config.
func NewAccountClient(c config) *AccountClient {
	return &AccountClient{config: c}
}

// Use adds a list of mutation hooks to the hooks stack.
// A call to `Use(f, g, h)` equals to `account.Hooks(f(g(h())))`.
func (c *AccountClient) Use(hooks ...Hook) {
	c.hooks.Account = append(c.hooks.Account, hooks...)
}

// Create returns a builder for creating a Account entity.
func (c *AccountClient) Create() *AccountCreate {
	mutation := newAccountMutation(c.config, OpCreate)
	return &AccountCreate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// CreateBulk returns a builder for creating a bulk of Account entities.
func (c *AccountClient) CreateBulk(builders ...*AccountCreate) *AccountCreateBulk {
	return &AccountCreateBulk{config: c.config, builders: builders}
}

// Update returns an update builder for Account.
func (c *AccountClient) Update() *AccountUpdate {
	mutation := newAccountMutation(c.config, OpUpdate)
	return &AccountUpdate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOne returns an update builder for the given entity.
func (c *AccountClient) UpdateOne(a *Account) *AccountUpdateOne {
	mutation := newAccountMutation(c.config, OpUpdateOne, withAccount(a))
	return &AccountUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOneID returns an update builder for the given id.
func (c *AccountClient) UpdateOneID(id int) *AccountUpdateOne {
	mutation := newAccountMutation(c.config, OpUpdateOne, withAccountID(id))
	return &AccountUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// Delete returns a delete builder for Account.
func (c *AccountClient) Delete() *AccountDelete {
	mutation := newAccountMutation(c.config, OpDelete)
	return &AccountDelete{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// DeleteOne returns a builder for deleting the given entity.
func (c *AccountClient) DeleteOne(a *Account) *AccountDeleteOne {
	return c.DeleteOneID(a.ID)
}

// DeleteOne returns a builder for deleting the given entity by its id.
func (c *AccountClient) DeleteOneID(id int) *AccountDeleteOne {
	builder := c.Delete().Where(account.ID(id))
	builder.mutation.id = &id
	builder.mutation.op = OpDeleteOne
	return &AccountDeleteOne{builder}
}

// Query returns a query builder for Account.
func (c *AccountClient) Query() *AccountQuery {
	return &AccountQuery{
		config: c.config,
	}
}

// Get returns a Account entity by its id.
func (c *AccountClient) Get(ctx context.Context, id int) (*Account, error) {
	return c.Query().Where(account.ID(id)).Only(ctx)
}

// GetX is like Get, but panics if an error occurs.
func (c *AccountClient) GetX(ctx context.Context, id int) *Account {
	obj, err := c.Get(ctx, id)
	if err != nil {
		panic(err)
	}
	return obj
}

// QueryKeys queries the keys edge of a Account.
func (c *AccountClient) QueryKeys(a *Account) *PrivateKeyQuery {
	query := &PrivateKeyQuery{config: c.config}
	query.path = func(ctx context.Context) (fromV *sql.Selector, _ error) {
		id := a.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(account.Table, account.FieldID, id),
			sqlgraph.To(privatekey.Table, privatekey.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, account.KeysTable, account.KeysColumn),
		)
		fromV = sqlgraph.Neighbors(a.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// QueryCredentials queries the credentials edge of a Account.
func (c *AccountClient) QueryCredentials(a *Account) *CredentialQuery {
	query := &CredentialQuery{config: c.config}
	query.path = func(ctx context.Context) (fromV *sql.Selector, _ error) {
		id := a.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(account.Table, account.FieldID, id),
			sqlgraph.To(credential.Table, credential.FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, account.CredentialsTable, account.CredentialsColumn),
		)
		fromV = sqlgraph.Neighbors(a.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// Hooks returns the client hooks.
func (c *AccountClient) Hooks() []Hook {
	return c.hooks.Account
}

// CredentialClient is a client for the Credential schema.
type CredentialClient struct {
	config
}

// NewCredentialClient returns a client for the Credential from the given config.
func NewCredentialClient(c config) *CredentialClient {
	return &CredentialClient{config: c}
}

// Use adds a list of mutation hooks to the hooks stack.
// A call to `Use(f, g, h)` equals to `credential.Hooks(f(g(h())))`.
func (c *CredentialClient) Use(hooks ...Hook) {
	c.hooks.Credential = append(c.hooks.Credential, hooks...)
}

// Create returns a builder for creating a Credential entity.
func (c *CredentialClient) Create() *CredentialCreate {
	mutation := newCredentialMutation(c.config, OpCreate)
	return &CredentialCreate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// CreateBulk returns a builder for creating a bulk of Credential entities.
func (c *CredentialClient) CreateBulk(builders ...*CredentialCreate) *CredentialCreateBulk {
	return &CredentialCreateBulk{config: c.config, builders: builders}
}

// Update returns an update builder for Credential.
func (c *CredentialClient) Update() *CredentialUpdate {
	mutation := newCredentialMutation(c.config, OpUpdate)
	return &CredentialUpdate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOne returns an update builder for the given entity.
func (c *CredentialClient) UpdateOne(cr *Credential) *CredentialUpdateOne {
	mutation := newCredentialMutation(c.config, OpUpdateOne, withCredential(cr))
	return &CredentialUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOneID returns an update builder for the given id.
func (c *CredentialClient) UpdateOneID(id string) *CredentialUpdateOne {
	mutation := newCredentialMutation(c.config, OpUpdateOne, withCredentialID(id))
	return &CredentialUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// Delete returns a delete builder for Credential.
func (c *CredentialClient) Delete() *CredentialDelete {
	mutation := newCredentialMutation(c.config, OpDelete)
	return &CredentialDelete{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// DeleteOne returns a builder for deleting the given entity.
func (c *CredentialClient) DeleteOne(cr *Credential) *CredentialDeleteOne {
	return c.DeleteOneID(cr.ID)
}

// DeleteOne returns a builder for deleting the given entity by its id.
func (c *CredentialClient) DeleteOneID(id string) *CredentialDeleteOne {
	builder := c.Delete().Where(credential.ID(id))
	builder.mutation.id = &id
	builder.mutation.op = OpDeleteOne
	return &CredentialDeleteOne{builder}
}

// Query returns a query builder for Credential.
func (c *CredentialClient) Query() *CredentialQuery {
	return &CredentialQuery{
		config: c.config,
	}
}

// Get returns a Credential entity by its id.
func (c *CredentialClient) Get(ctx context.Context, id string) (*Credential, error) {
	return c.Query().Where(credential.ID(id)).Only(ctx)
}

// GetX is like Get, but panics if an error occurs.
func (c *CredentialClient) GetX(ctx context.Context, id string) *Credential {
	obj, err := c.Get(ctx, id)
	if err != nil {
		panic(err)
	}
	return obj
}

// QueryAccount queries the account edge of a Credential.
func (c *CredentialClient) QueryAccount(cr *Credential) *AccountQuery {
	query := &AccountQuery{config: c.config}
	query.path = func(ctx context.Context) (fromV *sql.Selector, _ error) {
		id := cr.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(credential.Table, credential.FieldID, id),
			sqlgraph.To(account.Table, account.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, credential.AccountTable, credential.AccountColumn),
		)
		fromV = sqlgraph.Neighbors(cr.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// Hooks returns the client hooks.
func (c *CredentialClient) Hooks() []Hook {
	return c.hooks.Credential
}

// PrivateKeyClient is a client for the PrivateKey schema.
type PrivateKeyClient struct {
	config
}

// NewPrivateKeyClient returns a client for the PrivateKey from the given config.
func NewPrivateKeyClient(c config) *PrivateKeyClient {
	return &PrivateKeyClient{config: c}
}

// Use adds a list of mutation hooks to the hooks stack.
// A call to `Use(f, g, h)` equals to `privatekey.Hooks(f(g(h())))`.
func (c *PrivateKeyClient) Use(hooks ...Hook) {
	c.hooks.PrivateKey = append(c.hooks.PrivateKey, hooks...)
}

// Create returns a builder for creating a PrivateKey entity.
func (c *PrivateKeyClient) Create() *PrivateKeyCreate {
	mutation := newPrivateKeyMutation(c.config, OpCreate)
	return &PrivateKeyCreate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// CreateBulk returns a builder for creating a bulk of PrivateKey entities.
func (c *PrivateKeyClient) CreateBulk(builders ...*PrivateKeyCreate) *PrivateKeyCreateBulk {
	return &PrivateKeyCreateBulk{config: c.config, builders: builders}
}

// Update returns an update builder for PrivateKey.
func (c *PrivateKeyClient) Update() *PrivateKeyUpdate {
	mutation := newPrivateKeyMutation(c.config, OpUpdate)
	return &PrivateKeyUpdate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOne returns an update builder for the given entity.
func (c *PrivateKeyClient) UpdateOne(pk *PrivateKey) *PrivateKeyUpdateOne {
	mutation := newPrivateKeyMutation(c.config, OpUpdateOne, withPrivateKey(pk))
	return &PrivateKeyUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOneID returns an update builder for the given id.
func (c *PrivateKeyClient) UpdateOneID(id string) *PrivateKeyUpdateOne {
	mutation := newPrivateKeyMutation(c.config, OpUpdateOne, withPrivateKeyID(id))
	return &PrivateKeyUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// Delete returns a delete builder for PrivateKey.
func (c *PrivateKeyClient) Delete() *PrivateKeyDelete {
	mutation := newPrivateKeyMutation(c.config, OpDelete)
	return &PrivateKeyDelete{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// DeleteOne returns a builder for deleting the given entity.
func (c *PrivateKeyClient) DeleteOne(pk *PrivateKey) *PrivateKeyDeleteOne {
	return c.DeleteOneID(pk.ID)
}

// DeleteOne returns a builder for deleting the given entity by its id.
func (c *PrivateKeyClient) DeleteOneID(id string) *PrivateKeyDeleteOne {
	builder := c.Delete().Where(privatekey.ID(id))
	builder.mutation.id = &id
	builder.mutation.op = OpDeleteOne
	return &PrivateKeyDeleteOne{builder}
}

// Query returns a query builder for PrivateKey.
func (c *PrivateKeyClient) Query() *PrivateKeyQuery {
	return &PrivateKeyQuery{
		config: c.config,
	}
}

// Get returns a PrivateKey entity by its id.
func (c *PrivateKeyClient) Get(ctx context.Context, id string) (*PrivateKey, error) {
	return c.Query().Where(privatekey.ID(id)).Only(ctx)
}

// GetX is like Get, but panics if an error occurs.
func (c *PrivateKeyClient) GetX(ctx context.Context, id string) *PrivateKey {
	obj, err := c.Get(ctx, id)
	if err != nil {
		panic(err)
	}
	return obj
}

// QueryAccount queries the account edge of a PrivateKey.
func (c *PrivateKeyClient) QueryAccount(pk *PrivateKey) *AccountQuery {
	query := &AccountQuery{config: c.config}
	query.path = func(ctx context.Context) (fromV *sql.Selector, _ error) {
		id := pk.ID
		step := sqlgraph.NewStep(
			sqlgraph.From(privatekey.Table, privatekey.FieldID, id),
			sqlgraph.To(account.Table, account.FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, privatekey.AccountTable, privatekey.AccountColumn),
		)
		fromV = sqlgraph.Neighbors(pk.driver.Dialect(), step)
		return fromV, nil
	}
	return query
}

// Hooks returns the client hooks.
func (c *PrivateKeyClient) Hooks() []Hook {
	return c.hooks.PrivateKey
}

// PublicKeyClient is a client for the PublicKey schema.
type PublicKeyClient struct {
	config
}

// NewPublicKeyClient returns a client for the PublicKey from the given config.
func NewPublicKeyClient(c config) *PublicKeyClient {
	return &PublicKeyClient{config: c}
}

// Use adds a list of mutation hooks to the hooks stack.
// A call to `Use(f, g, h)` equals to `publickey.Hooks(f(g(h())))`.
func (c *PublicKeyClient) Use(hooks ...Hook) {
	c.hooks.PublicKey = append(c.hooks.PublicKey, hooks...)
}

// Create returns a builder for creating a PublicKey entity.
func (c *PublicKeyClient) Create() *PublicKeyCreate {
	mutation := newPublicKeyMutation(c.config, OpCreate)
	return &PublicKeyCreate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// CreateBulk returns a builder for creating a bulk of PublicKey entities.
func (c *PublicKeyClient) CreateBulk(builders ...*PublicKeyCreate) *PublicKeyCreateBulk {
	return &PublicKeyCreateBulk{config: c.config, builders: builders}
}

// Update returns an update builder for PublicKey.
func (c *PublicKeyClient) Update() *PublicKeyUpdate {
	mutation := newPublicKeyMutation(c.config, OpUpdate)
	return &PublicKeyUpdate{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOne returns an update builder for the given entity.
func (c *PublicKeyClient) UpdateOne(pk *PublicKey) *PublicKeyUpdateOne {
	mutation := newPublicKeyMutation(c.config, OpUpdateOne, withPublicKey(pk))
	return &PublicKeyUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// UpdateOneID returns an update builder for the given id.
func (c *PublicKeyClient) UpdateOneID(id string) *PublicKeyUpdateOne {
	mutation := newPublicKeyMutation(c.config, OpUpdateOne, withPublicKeyID(id))
	return &PublicKeyUpdateOne{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// Delete returns a delete builder for PublicKey.
func (c *PublicKeyClient) Delete() *PublicKeyDelete {
	mutation := newPublicKeyMutation(c.config, OpDelete)
	return &PublicKeyDelete{config: c.config, hooks: c.Hooks(), mutation: mutation}
}

// DeleteOne returns a builder for deleting the given entity.
func (c *PublicKeyClient) DeleteOne(pk *PublicKey) *PublicKeyDeleteOne {
	return c.DeleteOneID(pk.ID)
}

// DeleteOne returns a builder for deleting the given entity by its id.
func (c *PublicKeyClient) DeleteOneID(id string) *PublicKeyDeleteOne {
	builder := c.Delete().Where(publickey.ID(id))
	builder.mutation.id = &id
	builder.mutation.op = OpDeleteOne
	return &PublicKeyDeleteOne{builder}
}

// Query returns a query builder for PublicKey.
func (c *PublicKeyClient) Query() *PublicKeyQuery {
	return &PublicKeyQuery{
		config: c.config,
	}
}

// Get returns a PublicKey entity by its id.
func (c *PublicKeyClient) Get(ctx context.Context, id string) (*PublicKey, error) {
	return c.Query().Where(publickey.ID(id)).Only(ctx)
}

// GetX is like Get, but panics if an error occurs.
func (c *PublicKeyClient) GetX(ctx context.Context, id string) *PublicKey {
	obj, err := c.Get(ctx, id)
	if err != nil {
		panic(err)
	}
	return obj
}

// Hooks returns the client hooks.
func (c *PublicKeyClient) Hooks() []Hook {
	return c.hooks.PublicKey
}
