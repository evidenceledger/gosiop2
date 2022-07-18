// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/evidenceledger/gosiop2/ent/predicate"
	"github.com/evidenceledger/gosiop2/ent/privatekey"
)

// PrivateKeyQuery is the builder for querying PrivateKey entities.
type PrivateKeyQuery struct {
	config
	limit      *int
	offset     *int
	unique     *bool
	order      []OrderFunc
	fields     []string
	predicates []predicate.PrivateKey
	withFKs    bool
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the PrivateKeyQuery builder.
func (pkq *PrivateKeyQuery) Where(ps ...predicate.PrivateKey) *PrivateKeyQuery {
	pkq.predicates = append(pkq.predicates, ps...)
	return pkq
}

// Limit adds a limit step to the query.
func (pkq *PrivateKeyQuery) Limit(limit int) *PrivateKeyQuery {
	pkq.limit = &limit
	return pkq
}

// Offset adds an offset step to the query.
func (pkq *PrivateKeyQuery) Offset(offset int) *PrivateKeyQuery {
	pkq.offset = &offset
	return pkq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (pkq *PrivateKeyQuery) Unique(unique bool) *PrivateKeyQuery {
	pkq.unique = &unique
	return pkq
}

// Order adds an order step to the query.
func (pkq *PrivateKeyQuery) Order(o ...OrderFunc) *PrivateKeyQuery {
	pkq.order = append(pkq.order, o...)
	return pkq
}

// First returns the first PrivateKey entity from the query.
// Returns a *NotFoundError when no PrivateKey was found.
func (pkq *PrivateKeyQuery) First(ctx context.Context) (*PrivateKey, error) {
	nodes, err := pkq.Limit(1).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{privatekey.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (pkq *PrivateKeyQuery) FirstX(ctx context.Context) *PrivateKey {
	node, err := pkq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first PrivateKey ID from the query.
// Returns a *NotFoundError when no PrivateKey ID was found.
func (pkq *PrivateKeyQuery) FirstID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = pkq.Limit(1).IDs(ctx); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{privatekey.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (pkq *PrivateKeyQuery) FirstIDX(ctx context.Context) string {
	id, err := pkq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single PrivateKey entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one PrivateKey entity is found.
// Returns a *NotFoundError when no PrivateKey entities are found.
func (pkq *PrivateKeyQuery) Only(ctx context.Context) (*PrivateKey, error) {
	nodes, err := pkq.Limit(2).All(ctx)
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{privatekey.Label}
	default:
		return nil, &NotSingularError{privatekey.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (pkq *PrivateKeyQuery) OnlyX(ctx context.Context) *PrivateKey {
	node, err := pkq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only PrivateKey ID in the query.
// Returns a *NotSingularError when more than one PrivateKey ID is found.
// Returns a *NotFoundError when no entities are found.
func (pkq *PrivateKeyQuery) OnlyID(ctx context.Context) (id string, err error) {
	var ids []string
	if ids, err = pkq.Limit(2).IDs(ctx); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{privatekey.Label}
	default:
		err = &NotSingularError{privatekey.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (pkq *PrivateKeyQuery) OnlyIDX(ctx context.Context) string {
	id, err := pkq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of PrivateKeys.
func (pkq *PrivateKeyQuery) All(ctx context.Context) ([]*PrivateKey, error) {
	if err := pkq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	return pkq.sqlAll(ctx)
}

// AllX is like All, but panics if an error occurs.
func (pkq *PrivateKeyQuery) AllX(ctx context.Context) []*PrivateKey {
	nodes, err := pkq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of PrivateKey IDs.
func (pkq *PrivateKeyQuery) IDs(ctx context.Context) ([]string, error) {
	var ids []string
	if err := pkq.Select(privatekey.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (pkq *PrivateKeyQuery) IDsX(ctx context.Context) []string {
	ids, err := pkq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (pkq *PrivateKeyQuery) Count(ctx context.Context) (int, error) {
	if err := pkq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return pkq.sqlCount(ctx)
}

// CountX is like Count, but panics if an error occurs.
func (pkq *PrivateKeyQuery) CountX(ctx context.Context) int {
	count, err := pkq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (pkq *PrivateKeyQuery) Exist(ctx context.Context) (bool, error) {
	if err := pkq.prepareQuery(ctx); err != nil {
		return false, err
	}
	return pkq.sqlExist(ctx)
}

// ExistX is like Exist, but panics if an error occurs.
func (pkq *PrivateKeyQuery) ExistX(ctx context.Context) bool {
	exist, err := pkq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the PrivateKeyQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (pkq *PrivateKeyQuery) Clone() *PrivateKeyQuery {
	if pkq == nil {
		return nil
	}
	return &PrivateKeyQuery{
		config:     pkq.config,
		limit:      pkq.limit,
		offset:     pkq.offset,
		order:      append([]OrderFunc{}, pkq.order...),
		predicates: append([]predicate.PrivateKey{}, pkq.predicates...),
		// clone intermediate query.
		sql:    pkq.sql.Clone(),
		path:   pkq.path,
		unique: pkq.unique,
	}
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		Kty string `json:"kty,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.PrivateKey.Query().
//		GroupBy(privatekey.FieldKty).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
//
func (pkq *PrivateKeyQuery) GroupBy(field string, fields ...string) *PrivateKeyGroupBy {
	grbuild := &PrivateKeyGroupBy{config: pkq.config}
	grbuild.fields = append([]string{field}, fields...)
	grbuild.path = func(ctx context.Context) (prev *sql.Selector, err error) {
		if err := pkq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		return pkq.sqlQuery(ctx), nil
	}
	grbuild.label = privatekey.Label
	grbuild.flds, grbuild.scan = &grbuild.fields, grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		Kty string `json:"kty,omitempty"`
//	}
//
//	client.PrivateKey.Query().
//		Select(privatekey.FieldKty).
//		Scan(ctx, &v)
//
func (pkq *PrivateKeyQuery) Select(fields ...string) *PrivateKeySelect {
	pkq.fields = append(pkq.fields, fields...)
	selbuild := &PrivateKeySelect{PrivateKeyQuery: pkq}
	selbuild.label = privatekey.Label
	selbuild.flds, selbuild.scan = &pkq.fields, selbuild.Scan
	return selbuild
}

func (pkq *PrivateKeyQuery) prepareQuery(ctx context.Context) error {
	for _, f := range pkq.fields {
		if !privatekey.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if pkq.path != nil {
		prev, err := pkq.path(ctx)
		if err != nil {
			return err
		}
		pkq.sql = prev
	}
	return nil
}

func (pkq *PrivateKeyQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*PrivateKey, error) {
	var (
		nodes   = []*PrivateKey{}
		withFKs = pkq.withFKs
		_spec   = pkq.querySpec()
	)
	if withFKs {
		_spec.Node.Columns = append(_spec.Node.Columns, privatekey.ForeignKeys...)
	}
	_spec.ScanValues = func(columns []string) ([]interface{}, error) {
		return (*PrivateKey).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []interface{}) error {
		node := &PrivateKey{config: pkq.config}
		nodes = append(nodes, node)
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, pkq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	return nodes, nil
}

func (pkq *PrivateKeyQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := pkq.querySpec()
	_spec.Node.Columns = pkq.fields
	if len(pkq.fields) > 0 {
		_spec.Unique = pkq.unique != nil && *pkq.unique
	}
	return sqlgraph.CountNodes(ctx, pkq.driver, _spec)
}

func (pkq *PrivateKeyQuery) sqlExist(ctx context.Context) (bool, error) {
	n, err := pkq.sqlCount(ctx)
	if err != nil {
		return false, fmt.Errorf("ent: check existence: %w", err)
	}
	return n > 0, nil
}

func (pkq *PrivateKeyQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := &sqlgraph.QuerySpec{
		Node: &sqlgraph.NodeSpec{
			Table:   privatekey.Table,
			Columns: privatekey.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeString,
				Column: privatekey.FieldID,
			},
		},
		From:   pkq.sql,
		Unique: true,
	}
	if unique := pkq.unique; unique != nil {
		_spec.Unique = *unique
	}
	if fields := pkq.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, privatekey.FieldID)
		for i := range fields {
			if fields[i] != privatekey.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := pkq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := pkq.limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := pkq.offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := pkq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (pkq *PrivateKeyQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(pkq.driver.Dialect())
	t1 := builder.Table(privatekey.Table)
	columns := pkq.fields
	if len(columns) == 0 {
		columns = privatekey.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if pkq.sql != nil {
		selector = pkq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if pkq.unique != nil && *pkq.unique {
		selector.Distinct()
	}
	for _, p := range pkq.predicates {
		p(selector)
	}
	for _, p := range pkq.order {
		p(selector)
	}
	if offset := pkq.offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := pkq.limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// PrivateKeyGroupBy is the group-by builder for PrivateKey entities.
type PrivateKeyGroupBy struct {
	config
	selector
	fields []string
	fns    []AggregateFunc
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Aggregate adds the given aggregation functions to the group-by query.
func (pkgb *PrivateKeyGroupBy) Aggregate(fns ...AggregateFunc) *PrivateKeyGroupBy {
	pkgb.fns = append(pkgb.fns, fns...)
	return pkgb
}

// Scan applies the group-by query and scans the result into the given value.
func (pkgb *PrivateKeyGroupBy) Scan(ctx context.Context, v interface{}) error {
	query, err := pkgb.path(ctx)
	if err != nil {
		return err
	}
	pkgb.sql = query
	return pkgb.sqlScan(ctx, v)
}

func (pkgb *PrivateKeyGroupBy) sqlScan(ctx context.Context, v interface{}) error {
	for _, f := range pkgb.fields {
		if !privatekey.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("invalid field %q for group-by", f)}
		}
	}
	selector := pkgb.sqlQuery()
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := pkgb.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

func (pkgb *PrivateKeyGroupBy) sqlQuery() *sql.Selector {
	selector := pkgb.sql.Select()
	aggregation := make([]string, 0, len(pkgb.fns))
	for _, fn := range pkgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	// If no columns were selected in a custom aggregation function, the default
	// selection is the fields used for "group-by", and the aggregation functions.
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(pkgb.fields)+len(pkgb.fns))
		for _, f := range pkgb.fields {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	return selector.GroupBy(selector.Columns(pkgb.fields...)...)
}

// PrivateKeySelect is the builder for selecting fields of PrivateKey entities.
type PrivateKeySelect struct {
	*PrivateKeyQuery
	selector
	// intermediate query (i.e. traversal path).
	sql *sql.Selector
}

// Scan applies the selector query and scans the result into the given value.
func (pks *PrivateKeySelect) Scan(ctx context.Context, v interface{}) error {
	if err := pks.prepareQuery(ctx); err != nil {
		return err
	}
	pks.sql = pks.PrivateKeyQuery.sqlQuery(ctx)
	return pks.sqlScan(ctx, v)
}

func (pks *PrivateKeySelect) sqlScan(ctx context.Context, v interface{}) error {
	rows := &sql.Rows{}
	query, args := pks.sql.Query()
	if err := pks.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
