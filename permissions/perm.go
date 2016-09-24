package perm

type Permission int

const (
	PermissionRead Permission = iota + 1
	PermissionWrite
	PermissionDelegate
	PermissionAppend
)

type Assertion struct {
	varname    string
	owner      string
	permission Permission
	targetUser string
}

type PermissionsState struct {
	assertions       []Assertion
	defaultDelegator string
}

//TODO Dependency:
// need curr_user
// need variable array of local and global variables

//TODO: use local var for now, change this when "data store model" will be complete
var permState PermissionsState

const (
	setDelegationSuccessful       = "{\"status\": \"SET_DELEGATION\"}"
	DeleteDelegationSuccessful    = "{\"status\": \"DELETE_DELEGATION\"}"
	setDefaultDelegatorSuccessful = "{\"status\": \"DEFAULT_DELEGATOR\"}"
)

// set delegation x q <right> -> p
// Indicates that q delegates <right> to p on variable x, so that p is given <right> whenever q is.
// If p is anyone, then effectively all principals are given <right> on x (for more detail, see here).
// If x is the keyword all then q delegates <right> to p for all variables on which q (currently) has
// delegate permission.
//
// Failure conditions:
// Fails if either p or q does not exist.
// Security violation if the running principal is not admin or q or if q does not have delegate permission on x.
// Successful status code: SET_DELEGATION
//
// variable mapping: set delegation varname owner permission -> targetUser
func SetDelegation(varname string, owner string, permission Permission, targetUser string) string {
	return setDelegationSuccessful
}

// delete delegation x q <right> -> p
// Indicates that q revokes a delegation assertion of <right> to p on variable x.
// In effect, this command revokes a previous command set delegation x q <right> -> p;
// see below for the precise semantics of what this means. If x is the keyword all then q revokes delegation
// of <right> to p for all variables on which q has delegate permission.
// delete delegation x p <right> -> q revokes assertion x p <right> -> q if it is explicitly present in S;
// otherwise the command does nothing.
//
// Failure conditions:
// Fails if either p or q does not exist.
// Security violation unless the current principal is admin, p, or q; if the principal is q, then it must have delegate permission on x (no special permission is needed if the current principal is p: any non-admin principal can always deny himself rights).
// Successful status code: DELETE_DELEGATION
func DeleteDelegation(varname string, owner string, permission Permission, targetUser string) string {
	return DeleteDelegationSuccessful
}

//Check if username has permission on varname
func CheckPermission(varname string, username string, permission Permission) bool {
	return false
}

// default delegator = p
// Sets the “default delegator” to p. This means that when a principal q is created,
// the system automatically delegates all from p to q. Changing the default delegator does not affect the
// permissions of existing principals. The initial default delegator is anyone.
// Failure conditions:
// Fails if p does not exist
// Security violation if the current principal is not admin.
// Successful status code: DEFAULT_DELEGATOR
func SetDefaultDelegator(delegator string) string {
	return setDefaultDelegatorSuccessful
}

//Return name of current default delegator
func GetDefaultDelegator() string {
	return permState.defaultDelegator
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
