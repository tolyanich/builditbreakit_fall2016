package store

import (
	"errors"
)

var ErrFailed = errors.New("store: failed")
var ErrDenied = errors.New("store: denied")

// global store
type Store struct {
}

// auth and acquire local store for changes
func (s *Store) AsPrincipal(username, password) (*LocalStore, error) {

}

// Copy-on-write storage per connection
type LocalStore struct {
	global *Store
}

// Commit changes to global store
func (ls *LocalStore) Commit() {

}

func (ls *LocalStore) CreatePrincipal(username, password string) error {

}

func (ls *LocalStore) ChangePassword(username, password string) error {

}

// set global variable
func (ls *LocalStore) Set(x string, val interface{}) error {

}

// get global variable
func (ls *LocalStore) Get(x string) (interface{}, error) {

}

func (ls *LocalStore) AppendTo(x string, val interface{}) error {

}

// set local variable
func (ls *LocalStore) SetLocal(x string, val interface{}) error {

}

// get global variable
func (ls *LocalStore) Foreach(y, x string, val interface{}) error {

}

// TODO: replace 'right' with enum
func (ls *LocalStore) SetDelegation(tgt, q, right, p string) error {

}

// TODO: replace 'right' with enum
func (ls *LocalStore) DeleteDelegation(tgt, q, right, p string) error {

}

func (ls *LocalStore) DefaultDelegator(p string) error {

}
