package store

import (
	"errors"
	"math/rand"
	"time"
)

var ErrFailed = errors.New("store: failed")
var ErrDenied = errors.New("store: denied")

const adminUsername = "admin"
const anyoneUsername = "anyone"
const allVars = "all"

type ListVal []interface{}
type RecordVal map[string]string // Record fields may only contain strings, not nested records

/// Permission type for store permissions
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

//string representation of Permission enum
func (p Permission) String() string {
	switch p {
	case PermissionRead:
		return "PermissionRead"
	case PermissionWrite:
		return "PermissionWrite"
	case PermissionDelegate:
		return "PermissionDelegate"
	case PermissionAppend:
		return "PermissionAppend"
	}
	return ""
}

// Assertion to hold all delegation for targetUser(key) PermissionsState
type PermRecords map[string]map[Permission]map[string]bool

type PermCacheKey struct {
	username string
	varname  string
	perm     Permission
}

// PermissionsState main struct to hold permissions
type PermissionsState struct {
	assertions       map[string]PermRecords //key is varname
	permissionCache  map[PermCacheKey]bool
	defaultDelegator string
}

// Global store
type Store struct {
	users            map[string]string // username is key
	vars             map[string]interface{}
	assertions       map[string]PermRecords //key is varname
	defaultDelegator string
}

// Defered storage per connection
type LocalStore struct {
	global           *Store
	users            map[string]string
	vars             map[string]interface{}
	locals           map[string]interface{}
	currUserName     string
	assertions       map[string]PermRecords //key is varname
	permissionCache  map[PermCacheKey]bool
	defaultDelegator string
}

func NewStore(adminPassword string) *Store {
	return &Store{
		users:            map[string]string{adminUsername: adminPassword, anyoneUsername: randPass()},
		vars:             make(map[string]interface{}, 100),
		assertions:       make(map[string]PermRecords, 100),
		defaultDelegator: anyoneUsername,
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
		global:           s,
		currUserName:     username,
		users:            make(map[string]string),
		vars:             make(map[string]interface{}),
		locals:           make(map[string]interface{}),
		assertions:       s.copyAssertionsFromGlobal(),
		permissionCache:  make(map[PermCacheKey]bool, 10000),
		defaultDelegator: s.defaultDelegator,
	}, nil
}

func (ls *LocalStore) IsAdmin() bool {
	return ls.currUserName == adminUsername
}

// type PermRecords map[string]map[Permission]map[string]bool
func (s *Store) copyAssertionsFromGlobal() map[string]PermRecords {
	ls := make(map[string]PermRecords, len(s.assertions))
	for varname, permRec := range s.assertions {
		if _, ok := ls[varname]; !ok {
			ls[varname] = make(PermRecords, len(permRec))
		}
		for targetUser, pPermRec := range permRec {
			if _, ok := ls[varname][targetUser]; !ok {
				ls[varname][targetUser] = make(map[Permission]map[string]bool)
			}
			for perm, pOwnerRec := range pPermRec {
				if _, ok := ls[varname][targetUser][perm]; !ok {
					ls[varname][targetUser][perm] = make(map[string]bool)
				}
				for owner, v := range pOwnerRec {
					ls[varname][targetUser][perm][owner] = v
				}
			}
		}
	}
	return ls
}

// Commit changes to global store
func (ls *LocalStore) Commit() {
	for u, p := range ls.users {
		ls.global.users[u] = p
	}
	for n, v := range ls.vars {
		ls.global.vars[n] = v
	}
	ls.global.assertions = ls.assertions
	ls.global.defaultDelegator = ls.defaultDelegator
}

// create principal p s
// Creates a principal p having password s.
// The system is preconfigured with principal admin whose password is given by the second command-line argument;
// or "admin" if that password is not given. There is also a preconfigured principal anyone whose initial
// password is unspecified, and which has no inherent authority. (See also the description of default delegator,
// below, for more about this command, and see the permissions discussion for more on how principal anyone is used.)
// Failure conditions:
// Fails if p already exists as a principal.
// Security violation if the current principal is not admin.
// Successful status code: CREATE_PRINCIPAL
func (ls *LocalStore) CreatePrincipal(username string, password string) error {
	if !ls.IsAdmin() {
		return ErrDenied
	}

	if ls.userExists(username) {
		return ErrFailed
	}

	ls.users[username] = password
	// From default delegator description
	// This means that when a principal q is created,
	// the system automatically delegates all from p to q. Changing the default delegator does not
	// affect the permissions of existing principals. The initial default delegator is anyone.
	if ls.getDefaultDelegator() != anyoneUsername {
		ls.SetDelegation(allVars, ls.getDefaultDelegator(), PermissionRead, username)
		ls.SetDelegation(allVars, ls.getDefaultDelegator(), PermissionWrite, username)
		ls.SetDelegation(allVars, ls.getDefaultDelegator(), PermissionDelegate, username)
		ls.SetDelegation(allVars, ls.getDefaultDelegator(), PermissionAppend, username)
	}
	return nil
}

// change password p s
// Changes the principal p’s password to s.
// Failure conditions:
// Fails if p does not exist
// Security violation if the current principal is neither admin nor p itself.
// Successful status code: CHANGE_PASSWORD
func (ls *LocalStore) ChangePassword(username string, password string) error {
	if !ls.IsAdmin() && username != ls.currUserName {
		return ErrDenied
	}
	if !ls.userExists(username) {
		return ErrFailed
	}
	if _, ok := ls.users[username]; ok { // change password for local user
		ls.users[username] = password
	} else if _, ok := ls.global.users[username]; ok { // save for pending update
		ls.users[username] = password
	}
	return nil
}

//set x = <expr>
//Sets x’s value to the result of evaluating <expr>, where x is a global variable.
//If x does not exist this command creates it.  If x is created by this command,
//and the current principal is not admin, then the current principal is delegated read, write,
// append, and delegate rights from the admin on x (equivalent to executing set delegation
// x admin read -> p and set delegation x admin write -> p, etc. where p is the current principal).
//Failure conditions:
//Security violation if the current principal does not have write permission on x.
//Successful status code: SET
func (ls *LocalStore) Set(x string, val interface{}) error {
	if _, ok := ls.vars[x]; ok { // pending variable exist
		if !ls.HasPermission(x, ls.currUserName, PermissionWrite) {
			return ErrDenied
		}
		ls.vars[x] = val
	} else if _, ok := ls.global.vars[x]; ok { // global variable exists
		if !ls.HasPermission(x, ls.currUserName, PermissionWrite) {
			return ErrDenied
		}
		ls.vars[x] = val
	} else if _, ok := ls.locals[x]; ok { // local variable exists
		ls.locals[x] = val
	} else { // new global variable
		ls.vars[x] = val
		ls.setPermissionOnNewVariable(x)
	}
	return nil
}

// local x = <expr>
// Creates a local variable x and initializes it to the value of executing <expr>.
// Subsequent updates to x can be made as you would to a global variable, e.g.,
// using set x, append...to x, foreach, etc. as described elsewhere in this section.
// Different from a global variable, local variables are destroyed when the program ends—they
// do not persist across connections.
// Failure conditions:
// Fails if x is already defined as a local or global variable.
// Successful status code: LOCAL
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
		if !ls.HasPermission(x, ls.currUserName, PermissionRead) {
			return nil, ErrDenied
		}
		return v, nil
	} else if v, ok := ls.global.vars[x]; ok { // global variable exists
		if !ls.HasPermission(x, ls.currUserName, PermissionRead) {
			return nil, ErrDenied
		}
		return v, nil
	}
	return nil, ErrFailed
}

// append to x with <expr>
// Adds the <expr>’s result to the end of x.   If <expr> evaluates to a record or a string,
// it is added to the end of x; if <expr> evaluates to a list, then it is concatenated to (the end of) x.
// Failure conditions:
// Fails if x is not defined or is not a list.
// Security violation if the current principal does not have either write or append permission on x.
// Successful status code: APPEND
func (ls *LocalStore) AppendTo(x string, val interface{}) error {
	if !ls.IsVarExist(x) {
		return ErrFailed
	}
	if l, ok := ls.locals[x]; ok { // local variable exists
		toAppend, ok := l.(ListVal)
		if !ok {
			return ErrFailed
		}
		ls.locals[x] = append(toAppend, val)
	} else {
		if !ls.HasPermission(x, ls.currUserName, PermissionWrite) &&
			!ls.HasPermission(x, ls.currUserName, PermissionAppend) {
			return ErrDenied
		}
		if v, ok := ls.vars[x]; ok { // pending variable exist
			toAppend, ok := v.(ListVal)
			if !ok {
				return ErrFailed
			}
			ls.vars[x] = append(toAppend, val)
		} else if g, ok := ls.global.vars[x]; ok { // global variable exists
			toAppend, ok := g.(ListVal)
			if !ok {
				return ErrFailed
			}
			ls.vars[x] = append(toAppend, val)
		}
	}
	return nil
}

// Sets the “default delegator” to p. This means that when a principal q is created,
// the system automatically delegates all from p to q. Changing the default delegator does not affect the
// permissions of existing principals. The initial default delegator is anyone.
// Failure conditions:
// Fails if p does not exist
// Security violation if the current principal is not admin.
// Successful status code: DEFAULT_DELEGATOR
// cmd: default delegator = p
func (ls *LocalStore) SetDefaultDelegator(p string) error {
	if !ls.IsAdmin() {
		return ErrDenied
	}
	if !ls.userExists(p) {
		return ErrFailed
	}
	ls.defaultDelegator = p
	return nil
}

// Return name of current default delegator
// cmd: there are no such cmd in public API.
func (ls *LocalStore) getDefaultDelegator() string {
	return ls.defaultDelegator
}

// When <tgt> is a variable x, Indicates that q delegates <right> to p on x, so that p is given <right>
// whenever q is. If p is anyone, then effectively all principals are given <right> on x (for more detail, see here).
// When <tgt> is the keyword all then q delegates <right> to p for all variables on which q (currently)
// has delegate permission.
// Failure conditions:
// Fails if either p or q does not exist.
// Security violation if the running principal is not admin or q or if q does not have delegate permission on x,
// when <tgt> is a variable x.
// Successful status code: SET_DELEGATION
// cmd: set delegation <tgt> q <right> -> p
// variable mapping: set delegation varname owner right -> targetUser
// TODO check if owner can be "anyone"
func (ls *LocalStore) SetDelegation(varname string, owner string, perm Permission, targetUser string) error {
	//Check permissions to do this operation
	if !ls.IsAdmin() && ls.currUserName != owner {
		return ErrDenied
	}
	// Handle special case
	// When <tgt> is the keyword all then q delegates <right> to p for all
	// variables on which q (currently) has delegate permission.
	if varname == allVars {
		//check that owner exist
		if !ls.userExists(owner) {
			return ErrFailed
		}
		//check that target user exist
		if !ls.userExists(targetUser) {
			return ErrFailed
		}
		// Find all varname where owner has DelegatePermission and issue add delegate cmd for this varname
		// We don't check return value since we already pass all checks and afaik we have delegate Permission
		for v, _ := range ls.assertions {
			if ls.HasPermission(v, owner, PermissionDelegate) {
				ls.SetDelegation(v, owner, perm, targetUser)
			}
		}
		return nil
	}
	if ls.currUserName == owner && !ls.HasPermission(varname, owner, PermissionDelegate) {
		return ErrDenied
	}
	//check that owner exist
	if !ls.userExists(owner) {
		return ErrFailed
	}
	//check that target user exist
	if !ls.userExists(targetUser) {
		return ErrFailed
	}
	//do not allow set delegation on local vars
	if !ls.isGlobalVarExist(varname) {
		return ErrFailed
	}
	ls.addAssertion(varname, owner, perm, targetUser)
	//invalidate permission cache
	ls.permissionCache = make(map[PermCacheKey]bool)
	return nil
}

// When <tgt> is a variable x, indicates that q revokes a delegation assertion of <right> to p on x.
// In effect, this command revokes a previous command set delegation x q <right> -> p; see below for the precise
// semantics of what this means. If <tgt> is the keyword all then q revokes delegation of <right> to p for all
// variables on which q has delegate permission.
// Failure conditions:
// Fails if either p or q does not exist.
// Security violation unless the current principal is admin, p, or q; if the principal is q and <tgt>
// is a variable x, then it must have delegate permission on x (no special permission is needed if the
// current principal is p: any non-admin principal can always deny himself rights).
// Successful status code: DELETE_DELEGATION
// cmd: delete delegation <tgt> q <right> -> p
func (ls *LocalStore) DeleteDelegation(varname string, owner string, perm Permission, targetUser string) error {
	//can't remove permission from admin
	if targetUser == adminUsername {
		return ErrFailed
	}
	//Check permissions to do this operation (current principal is admin, p, or q)
	if !ls.IsAdmin() && ls.currUserName != owner && ls.currUserName != targetUser {
		return ErrDenied
	}
	// Handle special case.
	// If <tgt> is the keyword all then q revokes delegation of <right> to p for all
	// variables on which q has delegate permission
	if varname == allVars {
		//check that owner exist
		if !ls.userExists(owner) {
			return ErrFailed
		}
		//check that target user exist
		if !ls.userExists(targetUser) {
			return ErrFailed
		}
		// Find all varname where owner has DelegatePermission and issue delete cmd for this varname
		// We don't check return value since we already pass all checks and afaik we have delegate Permission
		for v, _ := range ls.assertions {
			if ls.HasPermission(v, owner, PermissionDelegate) {
				ls.DeleteDelegation(v, owner, perm, targetUser)
			}
		}
		return nil
	}
	//if the principal is q and <tgt>
	// is a variable x, then it must have delegate permission on x
	if ls.currUserName == owner && !ls.HasPermission(varname, owner, PermissionDelegate) {
		return ErrDenied
	}
	//check that owner exist
	if !ls.userExists(owner) {
		return ErrFailed
	}
	//check that target user exist
	if !ls.userExists(targetUser) {
		return ErrFailed
	}
	ls.deleteAssertion(varname, owner, perm, targetUser)
	//invalidate permission cache
	ls.permissionCache = make(map[PermCacheKey]bool)
	return nil
}

func (ls *LocalStore) HasPermission(varname string, username string, perm Permission) bool {
	//admin always have all permissions
	if username == adminUsername {
		return true
	}
	//check in cache
	if res, ok := ls.CheckPermInCache(varname, username, perm); ok {
		return res
	}

	// We look for record with delegate varname someone permission -> username (or anyone)
	// if someone is admin => return true
	r1, ok := ls.assertions[varname][username]
	if ok {
		r2, ok := r1[perm]
		if ok {
			for owner, _ := range r2 {
				if owner == adminUsername || ls.HasPermission(varname, owner, perm) {
					return ls.AddToPermCacheReturn(varname, username, perm, true)
				}
			}
		}
	}
	r1, ok = ls.assertions[varname][anyoneUsername]
	if ok { //anyoneUser
		r2, ok := r1[perm]
		if ok {
			for owner, _ := range r2 {
				if owner == adminUsername || ls.HasPermission(varname, owner, perm) {
					return ls.AddToPermCacheReturn(varname, username, perm, true)
				}
			}
		}
	}
	return ls.AddToPermCacheReturn(varname, username, perm, false)
}

func (ls *LocalStore) CheckPermInCache(varname string, username string, perm Permission) (bool, bool) {
	if res, ok := ls.permissionCache[PermCacheKey{username: username, varname: varname, perm: perm}]; ok {
		return res, ok
	}
	return false, false
}

func (ls *LocalStore) AddToPermCacheReturn(varname string, username string, perm Permission, res bool) bool {
	ls.permissionCache[PermCacheKey{username: username, varname: varname, perm: perm}] = res
	return res
}

func (ls *LocalStore) addAssertion(varname string, owner string, perm Permission, targetUser string) {
	_, ok := ls.assertions[varname][targetUser]
	if !ok {
		v := make(map[Permission]map[string]bool)
		v[perm] = make(map[string]bool)
		v[perm][owner] = true
		ls.assertions[varname][targetUser] = v
		return
	}
	_, ok = ls.assertions[varname][targetUser][perm]
	if !ok {
		v := make(map[string]bool)
		v[owner] = true
		ls.assertions[varname][targetUser][perm] = v
		return
	}
	_, ok = ls.assertions[varname][targetUser][perm][owner]
	if !ok {
		ls.assertions[varname][targetUser][perm][owner] = true
	}
}

func (ls *LocalStore) deleteAssertion(varname string, owner string, perm Permission, targetUser string) {
	_, ok := ls.assertions[varname][targetUser]
	if !ok {
		return
	}
	_, ok = ls.assertions[varname][targetUser][perm]
	if !ok {
		return
	}
	_, ok = ls.assertions[varname][targetUser][perm][owner]
	if !ok {
		return
	}
	delete(ls.assertions[varname][targetUser][perm], owner)
}

// Should be called after creating variable. From set cmd description
// If x is created set command, and the current principal is not admin, then the current principal is
// delegated read, write, append, and delegate rights from the admin on x (equivalent to executing set
// delegation x admin read -> p and set delegation x admin write -> p, etc. where p is the current principal).
func (ls *LocalStore) setPermissionOnNewVariable(varname string) {
	ls.assertions[varname] = PermRecords{}
	if ls.IsAdmin() {
		return
	}
	ls.addAssertion(varname, adminUsername, PermissionRead, ls.currUserName)
	ls.addAssertion(varname, adminUsername, PermissionWrite, ls.currUserName)
	ls.addAssertion(varname, adminUsername, PermissionAppend, ls.currUserName)
	ls.addAssertion(varname, adminUsername, PermissionDelegate, ls.currUserName)
}

func (ls *LocalStore) userExists(username string) bool {
	if _, ok := ls.users[username]; ok { // exists as local user
		return true
	}
	if _, ok := ls.global.users[username]; ok { // exists user
		return true
	}
	return false
}

func (ls *LocalStore) isGlobalVarExist(varname string) bool {
	if _, ok := ls.global.vars[varname]; ok { // global variable exists
		return true
	}
	if _, ok := ls.vars[varname]; ok { // pending variable exists
		return true
	}
	return false
}

func (ls *LocalStore) IsVarExist(varname string) bool {
	if ls.isGlobalVarExist(varname) {
		return true
	}

	if _, ok := ls.locals[varname]; ok { // local variable exists
		return true
	}
	return false
}

func randPass() string {
	letterRunes := []rune("1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_!,.?")
	rand.Seed(time.Now().UnixNano())
	b := make([]rune, 20)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
