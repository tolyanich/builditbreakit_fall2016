package store

import (
	"errors"
)

var ErrFailed = errors.New("store: failed")
var ErrDenied = errors.New("store: denied")

const adminUsername = "admin"

// Permission type for store permissions
// Use bitmask for this
type Permission uint

const (
	// PermissionRead for read
	PermissionRead Permission = 1 << iota
	// PermissionWrite for write
	PermissionWrite
	// PermissionDelegate for delegate
	PermissionDelegate
	// PermissionAppend for append
	PermissionAppend
)

func (p Permission) IsSet(flag Permission) bool { return p&flag != 0 }
func (p *Permission) Set(flag Permission)       { *p |= flag }
func (p *Permission) Clear(flag Permission)     { *p &= ^flag }

// Global store
type Store struct {
	users map[string]string
	vars  map[string]interface{}
}

// Defered storage per connection
type LocalStore struct {
	global   *Store
	username string
	users    map[string]string
	vars     map[string]interface{}
	locals   map[string]interface{}
}

func NewStore(adminPassword string) *Store {
	return &Store{
		users: map[string]string{adminUsername: adminPassword},
	}
}

// auth and acquire local store for changes
func (s *Store) AsPrincipal(username, password string) (*LocalStore, error) {
	pwd, exists := s.users[username]
	if !exists {
		return nil, ErrFailed
	}
	if pwd != password {
		return nil, ErrDenied
	}
	return &LocalStore{
		global:   s,
		username: username,
		users:    make(map[string]string),
	}, nil
}

func (ls *LocalStore) IsAdmin() bool {
	return ls.username == adminUsername
}

// Commit changes to global store
func (ls *LocalStore) Commit() {
	for u, p := range ls.users {
		ls.global.users[u] = p
	}
	for n, v := range ls.vars {
		ls.global.vars[n] = v
	}
}

func (ls *LocalStore) CreatePrincipal(username, password string) error {
	if !ls.IsAdmin() {
		return ErrDenied
	}
	if _, ok := ls.users[username]; ok { // exists as local user
		return ErrFailed
	}
	if _, ok := ls.global.users[username]; ok { // exists as local user
		return ErrFailed
	}
	ls.users[username] = password
	return nil
}

func (ls *LocalStore) ChangePassword(username, password string) error {
	if !ls.IsAdmin() || username != ls.username {
		return ErrDenied
	}
	if _, ok := ls.users[username]; ok { // change password for local user
		ls.users[username] = password
	} else if _, ok := ls.global.users[username]; ok { // save for pending update
		ls.users[username] = password
	}
	return ErrFailed
}

// set global variable
func (ls *LocalStore) Set(x string, val interface{}) error {
	if _, ok := ls.vars[x]; ok { // pending variable exists
		ls.vars[x] = val
	} else if _, ok := ls.global.vars[x]; ok { // global variable exists
		// TODO: check 'write' permission
		ls.vars[x] = val
	} else { // new global variable
		ls.vars[x] = val
	}
	return nil
}

// set local variable
func (ls *LocalStore) SetLocal(x string, val interface{}) error {
	if _, ok := ls.global.vars[x]; ok { // global variable exists
		return ErrFailed
	}
	if _, ok := ls.vars[x]; ok { // pending variable exists
		return ErrFailed
	}
	if _, ok := ls.locals[x]; ok { // local variable exists
		return ErrFailed
	}
	ls.locals[x] = val
	return nil
}

// get variable (local or global)
func (ls *LocalStore) Get(x string) (interface{}, error) {
	if v, ok := ls.locals[x]; ok { // local variable exists
		return v, nil
	} else if v, ok := ls.vars[x]; ok { // pending variable exists
		return v, nil
	} else if v, ok := ls.global.vars[x]; ok { // global variable exists
		// TODO: check 'read' permission
		return v, nil
	}
	return nil, ErrFailed
}

func (ls *LocalStore) AppendTo(x string, val interface{}) error {
	return ErrFailed
}

// get global variable
func (ls *LocalStore) Foreach(y, x string, val interface{}) error {
	return ErrFailed
}

func (ls *LocalStore) SetDelegation(tgt, q string, right Permission, p string) error {
	return ErrFailed
}

func (ls *LocalStore) DeleteDelegation(tgt, q string, right Permission, p string) error {
	return ErrFailed
}

func (ls *LocalStore) DefaultDelegator(p string) error {
	return ErrFailed
}
