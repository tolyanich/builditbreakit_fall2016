package perm

import "fmt"

// Permission type for store permissions
type Permission int

const (
	// PermissionRead for read
	PermissionRead Permission = iota + 1
	// PermissionWrite for write
	PermissionWrite
	// PermissionDelegate for delegate
	PermissionDelegate
	// PermissionAppend for append
	PermissionAppend
)

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
	CurrUserName     string
}

type Variable struct {
	stringValue string
	arrayValue  []Variable
}
type Store struct {
	Users           map[string]string //username is key, password - value
	GlobalVariables map[string]Variable
	PermState       PermissionsState
}

//TODO: use local var for now, change this when "data Storage model" will be complete
var Storage Store

const (
	SetDelegationSuccessful       = "{\"status\": \"SET_DELEGATION\"}"
	DeleteDelegationSuccessful    = "{\"status\": \"DELETE_DELEGATION\"}"
	SetDefaultDelegatorSuccessful = "{\"status\": \"DEFAULT_DELEGATOR\"}"
	AddUserSuccessful             = "{\"status\": \"CREATE_PRINCIPAL\"}"
	ChangeUserPasswordSuccessful  = "{\"status\": \"CHANGE_PASSWORD\"}"
	AccessDeniedResult            = "{\"status\": \"DENIED\"}"
	FuncFailedResult              = "{\"status\": \"FAILED\"}"
	//TODO rewrite to global variable depending on ENV
	shouldLog = true
)

// When <tgt> is a variable x, Indicates that q delegates <right> to p on x, so that p is given <right>
// whenever q is. If p is anyone, then effectively all principals are given <right> on x (for more detail, see here).
// When <tgt> is the keyword all then q delegates <right> to p for all variables on which q (currently)
// has delegate permission.
// Failure conditions:
// Fails if either p or q does not exist.
// Security violation if the running principal is not admin or q or if q does not have delegate permission on x,
// when <tgt> is a variable x.
// Successful status code: SET_DELEGATION
// variable mapping: set delegation varname owner permission -> targetUser
// cmd: set delegation <tgt> q <right> -> p
// TODO check if owner can be "anyone"
func SetDelegation(varname string, owner string, permission Permission, targetUser string) (string, bool) {
	if shouldLog {
		fmt.Printf("SetDelegation(%s, %s, %s, %s) starts Storage: %+v\n", varname, owner, permission, targetUser, Storage)
	}
	//Check permissions to do this operation
	if Storage.PermState.CurrUserName != "admin" && Storage.PermState.CurrUserName != owner {
		return AccessDeniedResult, false
	}
	// Handle special case
	// When <tgt> is the keyword all then q delegates <right> to p for all
	// variables on which q (currently) has delegate permission.
	if varname == "all" {
		//check that owner exist
		_, exist := Storage.Users[owner]
		if !exist {
			return FuncFailedResult, false
		}
		//check that target user exist
		_, exist = Storage.Users[targetUser]
		if !exist {
			return FuncFailedResult, false
		}
		// Find all varname where owner has DelegatePermission and issue add delegate cmd for this varname
		// We don't check return value since we already pass all checks and afaik we have delegate Permission
		for varname, assertions := range Storage.PermState.assertions {
			for _, ass := range assertions {
				if (ass.targetUser == owner || ass.targetUser == "anyone") && ass.permission == PermissionDelegate {
					SetDelegation(varname, owner, permission, targetUser)
				}
			}
		}
		if shouldLog {
			fmt.Printf("SetDelegation(%s, %s, %s, %s) return ok Storage: %+v\n", varname, owner, permission, targetUser, Storage)
		}
		return SetDelegationSuccessful, true
	}

	if Storage.PermState.CurrUserName == owner && !HasPermission(varname, owner, PermissionDelegate) {
		return AccessDeniedResult, false
	}
	//check that owner exist
	_, exist := Storage.Users[owner]
	if !exist {
		return FuncFailedResult, false
	}
	//check that target user exist
	_, exist = Storage.Users[targetUser]
	if !exist {
		return FuncFailedResult, false
	}
	//check that varname variable exist
	// TODO: check Oracle can we set delegation on local variable. If so we need to check them in different way
	// of globals
	_, exist = Storage.GlobalVariables[varname]
	if !exist {
		return FuncFailedResult, false
	}
	asserion := Assertion{owner: owner, permission: permission, targetUser: targetUser}
	Storage.PermState.assertions[varname] = append(Storage.PermState.assertions[varname], asserion)

	if shouldLog {
		fmt.Printf("SetDelegation(%s, %s, %s, %s) return ok Storage: %+v\n", varname, owner, permission, targetUser, Storage)
	}
	return SetDelegationSuccessful, true
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
	if shouldLog {
		fmt.Printf("DeleteDelegation(%s, %s, %s, %s) start Storage: %+v\n", varname, owner, permission, targetUser, Storage)
	}
	//can't remove permission from admin
	if targetUser == "admin" {
		return AccessDeniedResult, false
	}
	//Check permissions to do this operation (current principal is admin, p, or q)
	if Storage.PermState.CurrUserName != "admin" && Storage.PermState.CurrUserName != owner && Storage.PermState.CurrUserName != targetUser {
		return AccessDeniedResult, false
	}
	// Handle special case.
	// If <tgt> is the keyword all then q revokes delegation of <right> to p for all
	// variables on which q has delegate permission
	if varname == "all" {
		//check that owner exist
		_, exist := Storage.Users[owner]
		if !exist {
			return FuncFailedResult, false
		}
		//check that target user exist
		_, exist = Storage.Users[targetUser]
		if !exist {
			return FuncFailedResult, false
		}
		// Find all varname where owner has DelegatePermission and issue delete cmd for this varname
		// We don't check return value since we already pass all checks and afaik we have delegate Permission
		for varname, assertions := range Storage.PermState.assertions {
			for _, ass := range assertions {
				if (ass.targetUser == owner || ass.targetUser == "anyone") && ass.permission == PermissionDelegate {
					DeleteDelegation(varname, owner, permission, targetUser)
				}
			}
		}
		if shouldLog {
			fmt.Printf("DeleteDelegation(%s, %s, %s, %s) return ok Storage: %+v\n", varname, owner, permission, targetUser, Storage)
		}
		return DeleteDelegationSuccessful, true
	}
	//if the principal is q and <tgt>
	// is a variable x, then it must have delegate permission on x
	if Storage.PermState.CurrUserName == owner && !HasPermission(varname, owner, PermissionDelegate) {
		return AccessDeniedResult, false
	}
	//check that owner exist
	_, exist := Storage.Users[owner]
	if !exist {
		return FuncFailedResult, false
	}
	//check that target user exist
	_, exist = Storage.Users[targetUser]
	if !exist {
		return FuncFailedResult, false
	}
	// TODO special handling of "all" keywords
	// TODO good name for holder
	// TODO may be break cycle when delete one delegation since no duplicates allowed
	// delete delegation

	holder := Storage.PermState.assertions[varname][:0]
	for _, ass := range Storage.PermState.assertions[varname] {
		if !ass.compare(owner, permission, targetUser) {
			holder = append(holder, ass)
		}
	}
	Storage.PermState.assertions[varname] = holder

	if shouldLog {
		fmt.Printf("DeleteDelegation(%s, %s, %s, %s) return ok Storage: %+v\n", varname, owner, permission, targetUser, Storage)
	}
	return DeleteDelegationSuccessful, true
}

//Check if username has permission on varname
func HasPermission(varname string, username string, permission Permission) bool {
	if shouldLog {
		fmt.Printf("HasPermission(%s, %s, %s) start Storage: %+v\n", varname, username, permission, Storage)
	}
	//admin always have all permissions
	if username == "admin" {
		return true
	}
	assertions := Storage.PermState.assertions[varname]
	// We look for record with delegate varname someone permission -> username
	// if someone is admin => return true
	// or remove current record and check if someone have permission on varname
	for i, ass := range assertions {
		if ass.targetUser == username && ass.permission == permission {
			if ass.owner == "admin" {
				return true
			}
			reduced_assertions := assertions[:i+copy(assertions[i:], assertions[i+1:])]
			return reducedHasPermission(varname, ass.owner, permission, reduced_assertions)
		}
	}
	return false
}

//internal check if username has permission on varname on reduced assertions array for 1 variable
func reducedHasPermission(varname string, username string, permission Permission, assertions []Assertion) bool {
	if shouldLog {
		fmt.Printf("reducedHasPermission(%s, %s, %s) start assertions: %+v\n", varname, username, permission, assertions)
	}
	for i, ass := range assertions {
		if ass.targetUser == username && ass.permission == permission {
			if ass.owner == "admin" {
				return true
			}
			reduced_assertions := assertions[:i+copy(assertions[i:], assertions[i+1:])]
			return reducedHasPermission(varname, ass.owner, permission, reduced_assertions)
		}
	}
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
	if shouldLog {
		fmt.Printf("SetDefaultDelegator(%s) start Storage: %+v\n", delegator, Storage)
	}
	//Check permissions to do this operation
	if Storage.PermState.CurrUserName != "admin" {
		return AccessDeniedResult, false
	}
	//check if we try to add not existing user
	_, exist := Storage.Users[delegator]
	if !exist {
		return FuncFailedResult, false
	}
	Storage.PermState.defaultDelegator = delegator
	return SetDefaultDelegatorSuccessful, true
}

//Return name of current default delegator
// cmd: there are no such cmd in public API.
func GetDefaultDelegator() string {
	return Storage.PermState.defaultDelegator
}

//Check pass for username and set Storage.PermState.CurrUserName on success
//Return true if login success and false if not
//cmd: as principal p password s do
func Login(username string, password string) bool {
	//TODO check Oracle for login as anyone since it doesn't have password
	if username == "anyone" {
		Storage.PermState.CurrUserName = "anyone"
		return true
	}
	savedPass, exist := Storage.Users[username]
	if exist && savedPass == password {
		Storage.PermState.CurrUserName = username
		return true
	}
	return false
}

//Add user
//Returns string with result and true if success and false if failed
//cmd: create principal p s
func AddUser(username string, password string) (string, bool) {
	//Check permissions to do this operation
	if Storage.PermState.CurrUserName != "admin" {
		return AccessDeniedResult, false
	}
	//check if we try to add existing user
	_, exist := Storage.Users[username]
	if exist {
		return FuncFailedResult, false
	}
	Storage.Users[username] = password
	// From default delegator description
	// This means that when a principal q is created,
	// the system automatically delegates all from p to q. Changing the default delegator does not
	// affect the permissions of existing principals. The initial default delegator is anyone.
	//TODO there are no PermissionDescription threre. keyword "all" is for variable name
	if Storage.PermState.defaultDelegator != "anyone" {
		SetDelegation("all", Storage.PermState.defaultDelegator, PermissionRead, username)
	}
	return AddUserSuccessful, true
}

//Change user password
//Returns string with result and true if success and false if failed
//cmd: change password p s
func ChangeUserPassword(username string, password string) (string, bool) {
	//Check permissions to do this operation
	if Storage.PermState.CurrUserName != username && Storage.PermState.CurrUserName != "admin" {
		return AccessDeniedResult, false
	}
	//check existance of user
	_, exist := Storage.Users[username]
	if !exist {
		return FuncFailedResult, false
	}
	Storage.Users[username] = password
	return ChangeUserPasswordSuccessful, true
}

// Should be called after creating variable. From set cmd description
// If x is created set command, and the current principal is not admin, then the current principal is
// delegated read, write, append, and delegate rights from the admin on x (equivalent to executing set
// delegation x admin read -> p and set delegation x admin write -> p, etc. where p is the current principal).
func SetPermissionOnNewVariable(varname string) {
	if Storage.PermState.CurrUserName == "admin" {
		return
	}
	asserion := Assertion{owner: "admin", permission: PermissionRead, targetUser: Storage.PermState.CurrUserName}
	Storage.PermState.assertions[varname] = append(Storage.PermState.assertions[varname], asserion)
	asserion = Assertion{owner: "admin", permission: PermissionWrite, targetUser: Storage.PermState.CurrUserName}
	Storage.PermState.assertions[varname] = append(Storage.PermState.assertions[varname], asserion)
	asserion = Assertion{owner: "admin", permission: PermissionAppend, targetUser: Storage.PermState.CurrUserName}
	Storage.PermState.assertions[varname] = append(Storage.PermState.assertions[varname], asserion)
	asserion = Assertion{owner: "admin", permission: PermissionDelegate, targetUser: Storage.PermState.CurrUserName}
	Storage.PermState.assertions[varname] = append(Storage.PermState.assertions[varname], asserion)
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

func SetupInitialPermissionState(adminPassword string) {
	Storage = Store{Users: make(map[string]string), PermState: PermissionsState{}, GlobalVariables: make(map[string]Variable)}
	Storage.Users["admin"] = adminPassword
	Storage.Users["anyone"] = ""
	Storage.PermState = PermissionsState{defaultDelegator: "anyone", assertions: make(map[string][]Assertion)}
	if shouldLog {
		fmt.Printf("SetupInitialPermissionState(%s) Storage: %+v\n", adminPassword, Storage)
	}

}
