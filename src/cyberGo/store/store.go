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

// Assertion to hold single line of delegation in PermissionsState
type Assertion struct {
	owner      string
	permission Permission
	targetUser string
}

func (p Assertion) compare(owner string, permission Permission, targetUser string) bool {
	return p.owner == owner && p.permission == permission && p.targetUser == targetUser
}

// PermissionsState main struct to hold permissions
type PermissionsState struct {
	assertions       map[string][]Assertion
	defaultDelegator string
}

// Global store
type Store struct {
	users     map[string]string
	vars      map[string]interface{}
	permState PermissionsState
}

// Defered storage per connection
type LocalStore struct {
	global       *Store
	users        map[string]string
	vars         map[string]interface{}
	locals       map[string]interface{}
	currUserName string
	permState    PermissionsState
}

func NewStore(adminPassword string) *Store {
	return &Store{
		users:     map[string]string{adminUsername: adminPassword, anyoneUsername: randPass()},
		vars:      make(map[string]interface{}),
		permState: PermissionsState{defaultDelegator: anyoneUsername, assertions: make(map[string][]Assertion)},
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
		global:       s,
		currUserName: username,
		users:        make(map[string]string),
		vars:         make(map[string]interface{}),
		locals:       make(map[string]interface{}),
		permState:    s.permState,
	}, nil
}

func (ls *LocalStore) IsAdmin() bool {
	return ls.currUserName == adminUsername
}

// Commit changes to global store
func (ls *LocalStore) Commit() {
	for u, p := range ls.users {
		ls.global.users[u] = p
	}
	for n, v := range ls.vars {
		ls.global.vars[n] = v
	}
	ls.global.permState = ls.permState
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
	//TODO there are no PermissionDescription threre. keyword "all" is for variable name
	if ls.getDefaultDelegator() != anyoneUsername {
		ls.SetDelegation(allVars, ls.getDefaultDelegator(), PermissionRead, username)
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
	if _, ok := ls.locals[x]; ok { // local variable exists
		toAppend, ok := ls.locals[x].(ListVal)
		if !ok {
			return ErrFailed
		}
		ls.locals[x] = appendListVal(toAppend, val)
	} else {
		if !ls.HasPermission(x, ls.currUserName, PermissionWrite) ||
			!ls.HasPermission(x, ls.currUserName, PermissionAppend) {
			return ErrDenied
		}
		if _, ok := ls.vars[x]; ok { // pending variable exist
			toAppend, ok := ls.vars[x].(ListVal)
			if !ok {
				return ErrFailed
			}
			ls.vars[x] = appendListVal(toAppend, val)
		} else if _, ok := ls.global.vars[x]; ok { // global variable exists
			toAppend, ok := ls.global.vars[x].(ListVal)
			if !ok {
				return ErrFailed
			}
			ls.vars[x] = appendListVal(toAppend, val)
		}
	}
	return nil
}

func appendListVal(x ListVal, val interface{}) ListVal {
	if v, ok := val.(ListVal); ok {
		return append(x, v...)
	} else {
		return append(x, val)
	}
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
	ls.permState.defaultDelegator = p
	return nil
}

// Return name of current default delegator
// cmd: there are no such cmd in public API.
func (ls *LocalStore) getDefaultDelegator() string {
	return ls.permState.defaultDelegator
}

// // get global variable
// func (ls *LocalStore) Foreach(y, x string, val interface{}) error {
// 	return ErrFailed
// }

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
func (ls *LocalStore) SetDelegation(varname string, owner string, right Permission, targetUser string) error {
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
		for varname, assertions := range ls.permState.assertions {
			for _, ass := range assertions {
				if (ass.targetUser == owner || ass.targetUser == anyoneUsername) && ass.permission == PermissionDelegate {
					ls.SetDelegation(varname, owner, right, targetUser)
				}
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
	asserion := Assertion{owner: owner, permission: right, targetUser: targetUser}
	ls.permState.assertions[varname] = append(ls.permState.assertions[varname], asserion)

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
func (ls *LocalStore) DeleteDelegation(varname string, owner string, right Permission, targetUser string) error {
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
		for varname, assertions := range ls.permState.assertions {
			for _, ass := range assertions {
				if (ass.targetUser == owner || ass.targetUser == anyoneUsername) && ass.permission == PermissionDelegate {
					ls.DeleteDelegation(varname, owner, right, targetUser)
				}
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
	// TODO good name for holder
	// TODO may be break cycle when delete one delegation since no duplicates allowed
	// delete delegation
	holder := ls.permState.assertions[varname][:0]
	for _, ass := range ls.permState.assertions[varname] {
		if !ass.compare(owner, right, targetUser) {
			holder = append(holder, ass)
		}
	}
	ls.permState.assertions[varname] = holder
	return nil
}

func (ls *LocalStore) HasPermission(varname string, username string, perm Permission) bool {
	//admin always have all permissions
	if username == adminUsername {
		return true
	}
	// We look for record with delegate varname someone permission -> username
	// if someone is admin => return true
	// or remove current record and check if someone have permission on varname
	assertions := ls.permState.assertions[varname]
	for i, ass := range assertions {
		if (ass.targetUser == username || ass.targetUser == anyoneUsername) && ass.permission == perm {
			if ass.owner == adminUsername {
				return true
			}
			reduced_assertions := assertions[:i+copy(assertions[i:], assertions[i+1:])]
			return ls.reducedHasPermission(varname, ass.owner, perm, reduced_assertions)
		}
	}
	return false
}

//internal check if username has permission on varname on reduced assertions array for 1 variable
func (ls *LocalStore) reducedHasPermission(varname string, username string, permission Permission, assertions []Assertion) bool {
	for i, ass := range assertions {
		if (ass.targetUser == username || ass.targetUser == anyoneUsername) && ass.permission == permission {
			if ass.owner == adminUsername {
				return true
			}
			reduced_assertions := assertions[:i+copy(assertions[i:], assertions[i+1:])]
			return ls.reducedHasPermission(varname, ass.owner, permission, reduced_assertions)
		}
	}
	return false
}

// Should be called after creating variable. From set cmd description
// If x is created set command, and the current principal is not admin, then the current principal is
// delegated read, write, append, and delegate rights from the admin on x (equivalent to executing set
// delegation x admin read -> p and set delegation x admin write -> p, etc. where p is the current principal).
func (ls *LocalStore) setPermissionOnNewVariable(varname string) {
	if ls.IsAdmin() {
		return
	}
	asserion := Assertion{owner: adminUsername, permission: PermissionRead, targetUser: ls.currUserName}
	ls.permState.assertions[varname] = append(ls.permState.assertions[varname], asserion)
	asserion = Assertion{owner: adminUsername, permission: PermissionWrite, targetUser: ls.currUserName}
	ls.permState.assertions[varname] = append(ls.permState.assertions[varname], asserion)
	asserion = Assertion{owner: adminUsername, permission: PermissionAppend, targetUser: ls.currUserName}
	ls.permState.assertions[varname] = append(ls.permState.assertions[varname], asserion)
	asserion = Assertion{owner: adminUsername, permission: PermissionDelegate, targetUser: ls.currUserName}
	ls.permState.assertions[varname] = append(ls.permState.assertions[varname], asserion)
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
