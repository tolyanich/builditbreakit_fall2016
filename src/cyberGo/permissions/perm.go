package perm

type Permission int

const (
	PermissionRead Permission = iota + 1
	PermissionWrite
	PermissionDelegate
	PermissionAppend
)

type Assertion struct {
	owner      string
	permission Permission
	targetUser string
}

func (p Assertion) compare(owner string, permission Permission, targetUser string) bool {
	return p.owner == owner && p.permission == permission && p.targetUser == targetUser
}

type PermissionsState struct {
	assertions       map[string][]Assertion
	defaultDelegator string
}

//TODO Dependency:
// need currUser
// need variable array of local and global variables
var currUsername = "admin"

type Variable struct {
	stringValue string
	arrayValue  []Variable
}
type Store struct {
	users            map[string]string //username is key, password - value
	globalVariables  map[string]Variable
	defaultDelegator string
	adminPassword    string
	//	permState        perm.PermissionsState
}

//TODO: use local var for now, change this when "data store model" will be complete
var permState PermissionsState
var store Store

const (
	setDelegationSuccessful       = "{\"status\": \"SET_DELEGATION\"}"
	DeleteDelegationSuccessful    = "{\"status\": \"DELETE_DELEGATION\"}"
	setDefaultDelegatorSuccessful = "{\"status\": \"DEFAULT_DELEGATOR\"}"
	addUserSuccessful             = "{\"status\": \"CREATE_PRINCIPAL\"}"
	changeUserPasswordSuccessful  = "{\"status\": \"CHANGE_PASSWORD\"}"
	accessDenied                  = "{\"status\": \"DENIED\"}"
	funcFailed                    = "{\"status\": \"FAILED\"}"
)

// When <tgt> is a variable x, Indicates that q delegates <right> to p on x, so that p is given <right>
// whenever q is. If p is anyone, then effectively all principals are given <right> on x (for more detail, see here). When <tgt> is the keyword all then q delegates <right> to p for all variables on which q (currently) has delegate permission.
// Failure conditions:
// Fails if either p or q does not exist.
// Security violation if the running principal is not admin or q or if q does not have delegate permission on x,
// when <tgt> is a variable x.
// Successful status code: SET_DELEGATION
// variable mapping: set delegation varname owner permission -> targetUser
// cmd: set delegation <tgt> q <right> -> p
// TODO check if owner can be "anyone"
func SetDelegation(varname string, owner string, permission Permission, targetUser string) (string, bool) {
	//Check permissions to do this operation
	if currUsername != "admin" || currUsername != owner {
		return accessDenied, false
	}
	if currUsername == owner && !CheckPermission(varname, owner, PermissionDelegate) {
		return accessDenied, false
	}
	//check that owner exist
	_, exist := store.users[owner]
	if !exist {
		return funcFailed, false
	}
	//check that target user exist
	_, exist = store.users[targetUser]
	if !exist {
		return funcFailed, false
	}
	//check that varname variable exist
	// TODO: check Oracle can we set delegation on local variable. If so we need to check them in different way
	// of globals
	_, exist = store.globalVariables[varname]
	if !exist {
		return funcFailed, false
	}
	asserion := Assertion{owner: owner, permission: permission, targetUser: targetUser}
	permState.assertions[varname] = append(permState.assertions[varname], asserion)

	return setDelegationSuccessful, true
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
func DeleteDelegation(varname string, owner string, permission Permission, targetUser string) (string, bool) {
	//can't remove permission from admin
	if targetUser == "admin" {
		return accessDenied, false
	}
	//Check permissions to do this operation (current principal is admin, p, or q)
	if (currUsername != "admin" && currUsername != owner && currUsername != targetUser) || !CheckPermission(varname, owner, PermissionDelegate) {
		return accessDenied, false
	}

	if currUsername == owner && !CheckPermission(varname, owner, PermissionDelegate) {
		return accessDenied, false
	}
	//check that owner exist
	_, exist := store.users[owner]
	if !exist {
		return funcFailed, false
	}
	//check that target user exist
	_, exist = store.users[targetUser]
	if !exist {
		return funcFailed, false
	}
	// TODO special handling of "all" keywords
	// TODO good name for holder
	// TODO may be break cycle when delete one delegation since no duplicates allowed
	//delete delegation
	assertions := permState.assertions[varname]
	holder := assertions[:0]
	for _, ass := range assertions {
		if ass.compare(owner, permission, targetUser) {
			holder = append(holder, ass)
		}
	}
	return DeleteDelegationSuccessful, true
}

//Check if username has permission on varname
func CheckPermission(varname string, username string, permission Permission) bool {
	return false
}

// Sets the “default delegator” to p. This means that when a principal q is created,
// the system automatically delegates all from p to q. Changing the default delegator does not affect the
// permissions of existing principals. The initial default delegator is anyone.
// Failure conditions:
// Fails if p does not exist
// Security violation if the current principal is not admin.
// Successful status code: DEFAULT_DELEGATOR
// cmd: default delegator = p
func SetDefaultDelegator(delegator string) (string, bool) {
	//Check permissions to do this operation
	if currUsername != "admin" {
		return accessDenied, false
	}
	//check if we try to add not existing user
	_, exist := store.users[delegator]
	if !exist {
		return funcFailed, false
	}
	return setDefaultDelegatorSuccessful, true
}

//Return name of current default delegator
// cmd: there are no such cmd in public API.
func GetDefaultDelegator() string {
	return permState.defaultDelegator
}

//Check pass for username and set currUsername on success
//Return true if login success and false if not
//cmd: as principal p password s do
func Login(username string, password string) bool {
	//TODO check Oracle for login as anyone since it doesn't have password
	if username == "anyone" {
		currUsername = "anyone"
		return true
	}
	savedPass, exist := store.users[username]
	if exist && savedPass == password {
		currUsername = username
		return true
	}
	return false
}

//Add user
//Returns string with result and true if success and false if failed
//cmd: create principal p s
func AddUser(username string, password string) (string, bool) {
	//Check permissions to do this operation
	if currUsername != "admin" {
		return accessDenied, false
	}
	//check if we try to add existing user
	_, exist := store.users[username]
	if exist {
		return funcFailed, false
	}
	store.users[username] = password
	return addUserSuccessful, true
}

//Change user password
//Returns string with result and true if success and false if failed
//cmd: change password p s
func ChangeUserPassword(username string, password string) (string, bool) {
	//Check permissions to do this operation
	if currUsername != "username" || currUsername != "admin" {
		return accessDenied, false
	}
	//check existance of user
	_, exist := store.users[username]
	if exist {
		return funcFailed, false
	}
	store.users[username] = password
	return changeUserPasswordSuccessful, true
}

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
