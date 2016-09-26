package perm_test

import (
	. "cyberGo/permissions"
	"testing"
	// . "github.com/smartystreets/goconvey/convey"
)

func TestSpec(t *testing.T) {
	SetupInitialPermissionState("admin")
	if !Login("admin", "admin") {
		t.Errorf("Login fail")
	}
}

func TestLogin(t *testing.T) {
	SetupInitialPermissionState("admin")
	if !Login("admin", "admin") {
		t.Errorf("Login fail")
	}
	if Login("admin", "wrong") {
		t.Errorf("Loged in with wrong pass")
	}
	if Login("notexist", "pass") {
		t.Errorf("Loged in with not exist user")
	}
}

func TestChangePassword(t *testing.T) {
	SetupInitialPermissionState("admin")
	if !Login("admin", "admin") {
		t.Errorf("admin Login fail")
	}
	output, bRes := ChangeUserPassword("admin", "newadmin")
	if !bRes || output != ChangeUserPasswordSuccessful {
		t.Errorf("ChangeUserPassword fail ", bRes, output)
	}
	if !Login("admin", "newadmin") {
		t.Errorf("Loged with new password fail")
	}
	output, bRes = ChangeUserPassword("notexist", "newadmin")
	if bRes || output != FuncFailedResult {
		t.Errorf("ChangeUserPassword on notexist user success ", bRes, output)
	}
	output, bRes = AddUser("alice", "alice")
	if !bRes || output != AddUserSuccessful {
		t.Errorf("Add user alice fail ", bRes, output)
	}
	output, bRes = ChangeUserPassword("alice", "alice1")
	if !bRes || output != ChangeUserPasswordSuccessful {
		t.Errorf("ChangeUserPassword alice by admin fail ", bRes, output)
	}
	if !Login("alice", "alice1") {
		t.Errorf("Login with changed password fail")
	}
	output, bRes = ChangeUserPassword("alice", "alice_newpass")
	if !bRes || output != ChangeUserPasswordSuccessful {
		t.Errorf("ChangeUserPassword alice by alice fail ", bRes, output)
	}
	if !Login("alice", "alice_newpass") {
		t.Errorf("Login with changed password fail")
	}
	output, bRes = ChangeUserPassword("admin", "alice_newpass")
	if bRes || output != AccessDeniedResult {
		t.Errorf("ChangeUserPassword admin by alice success ", bRes, output)
	}
}

func TestAddUser(t *testing.T) {
	SetupInitialPermissionState("admin")
	if !Login("admin", "admin") {
		t.Errorf("Login fail")
	}
	output, bRes := AddUser("alice", "alice")
	if !bRes || output != AddUserSuccessful {
		t.Errorf("Add user fail ", bRes, output)
	}
	if !Login("alice", "alice") {
		t.Errorf("Can't login on created user")
	}
	output, bRes = AddUser("bob", "bob")
	if bRes || output != AccessDeniedResult {
		t.Errorf("Should deny create user for non admin", bRes, output)
	}
}

func TestSetGetDefaultDelegator(t *testing.T) {
	SetupInitialPermissionState("admin")
	if !Login("admin", "admin") {
		t.Errorf("Login fail")
	}
	output, bRes := SetDefaultDelegator("admin")
	if !bRes || output != SetDefaultDelegatorSuccessful {
		t.Errorf("SetDefaultDelegator fail", bRes, output)
	}
	output = GetDefaultDelegator()
	if output != "admin" {
		t.Errorf("Error in GetDefaultDelegator", output)
	}
}

func TestAccessDefaultDelegator(t *testing.T) {
	SetupInitialPermissionState("admin")
	if !Login("admin", "admin") {
		t.Errorf("Login fail")
	}
	AddUser("alice", "alice")
	if !Login("alice", "alice") {
		t.Errorf("Login fail")
	}
	output, bRes := SetDefaultDelegator("changed")
	if bRes || output != AccessDeniedResult {
		t.Errorf("SetDefaultDelegator fail", bRes, output)
	}
	output = GetDefaultDelegator()
	if output != "anyone" {
		t.Errorf("Error in GetDefaultDelegator", output)
	}
}

func TestPermissionOnNewVar(t *testing.T) {
	SetupInitialPermissionState("admin")
	if !Login("admin", "admin") {
		t.Errorf("admin login fail")
	}
	SetPermissionOnNewVariable("admin_var")

	if !HasPermission("admin_var", "admin", PermissionRead) {
		t.Errorf("Admin does'n have read permission on created var")
	}
	if !HasPermission("admin_var", "admin", PermissionWrite) {
		t.Errorf("Admin does'n have PermissionWrite permission on created var")
	}
	if !HasPermission("admin_var", "admin", PermissionDelegate) {
		t.Errorf("Admin does'n have PermissionDelegate permission on created var")
	}
	if !HasPermission("admin_var", "admin", PermissionAppend) {
		t.Errorf("Admin does'n have PermissionAppend permission on created var")
	}

	output, bRes := AddUser("alice", "alice")
	if !bRes || output != AddUserSuccessful {
		t.Errorf("Add user fail ", bRes, output)
	}
	if !Login("alice", "alice") {
		t.Errorf("Can't login on created user")
	}
	SetPermissionOnNewVariable("var")
	if !HasPermission("var", "alice", PermissionRead) {
		t.Errorf("User does'n have read permission on created var")
	}
	if !HasPermission("var", "alice", PermissionWrite) {
		t.Errorf("User does'n have PermissionWrite permission on created var")
	}
	if !HasPermission("var", "alice", PermissionDelegate) {
		t.Errorf("User does'n have PermissionDelegate permission on created var")
	}
	if !HasPermission("var", "alice", PermissionAppend) {
		t.Errorf("User does'n have PermissionAppend permission on created var")
	}
	if !HasPermission("var", "admin", PermissionRead) || !HasPermission("var", "admin", PermissionWrite) ||
		!HasPermission("var", "admin", PermissionDelegate) || !HasPermission("var", "admin", PermissionAppend) {
		t.Errorf("Admin should always have full perimission on all users variables")
	}

	if HasPermission("admin_var", "alice", PermissionRead) || HasPermission("admin_var", "alice", PermissionWrite) ||
		HasPermission("admin_var", "alice", PermissionDelegate) || HasPermission("admin_var", "alice", PermissionAppend) {
		t.Errorf("User should not have full perimission on admin variables")
	}
}

func TestSetDelegation(t *testing.T) {
	SetupInitialPermissionState("admin")
	if !Login("admin", "admin") {
		t.Errorf("admin login fail")
	}
	output, bRes := AddUser("alice", "alice")
	if !bRes || output != AddUserSuccessful {
		t.Errorf("Add user alice fail ", bRes, output)
	}
	output, bRes = AddUser("bob", "bob")
	if !bRes || output != AddUserSuccessful {
		t.Errorf("Add user bob fail ", bRes, output)
	}

	Storage.GlobalVariables["admin_var"] = Variable{}
	Storage.GlobalVariables["var"] = Variable{}
	if HasPermission("admin_var", "alice", PermissionRead) {
		t.Errorf("User have read permission on admin var")
	}
	output, bRes = SetDelegation("admin_var", "admin", PermissionRead, "alice")
	if !bRes || output != SetDelegationSuccessful {
		t.Errorf("Set delegation fail", bRes, output)
	}
	if !HasPermission("admin_var", "alice", PermissionRead) {
		t.Errorf("User does'n have read permission on delegated var")
	}
	output, bRes = SetDelegation("var", "admin", PermissionDelegate, "alice")
	if !bRes || output != SetDelegationSuccessful {
		t.Errorf("Set delegation fail", bRes, output)
	}
	output, bRes = SetDelegation("var", "admin", PermissionWrite, "alice")
	if !bRes || output != SetDelegationSuccessful {
		t.Errorf("Set delegation fail", bRes, output)
	}
	if !HasPermission("var", "alice", PermissionDelegate) {
		t.Errorf("User does'n have delegation permission on delegated var")
	}
	//AccessDeniedResult
	if !Login("alice", "alice") {
		t.Errorf("admin login fail")
	}
	output, bRes = SetDelegation("var", "admin", PermissionRead, "alice")
	if bRes || output != AccessDeniedResult {
		t.Errorf("User can't set delegation from admin user", bRes, output)
	}
	output, bRes = SetDelegation("admin_var", "alice", PermissionRead, "alice")
	if bRes || output != AccessDeniedResult {
		t.Errorf("User can't set delegation on admin_var", bRes, output)
	}

	//chain delegation
	output, bRes = SetDelegation("var", "alice", PermissionWrite, "bob")
	if !bRes || output != SetDelegationSuccessful {
		t.Errorf("User chain delegation", bRes, output)
	}
	output, bRes = SetDelegation("var", "alice", PermissionRead, "bob")
	if !bRes || output != SetDelegationSuccessful {
		t.Errorf("User chain delegation", bRes, output)
	}
	if HasPermission("var", "bob", PermissionRead) {
		t.Errorf("Bob  have read permission on delegated var")
	}
	if !HasPermission("var", "bob", PermissionWrite) {
		t.Errorf("Bob  doesn't have write permission on delegated var")
	}
}

func TestSetAllDelegation(t *testing.T) {
	SetupInitialPermissionState("admin")
	if !Login("admin", "admin") {
		t.Errorf("admin login fail")
	}
	output, bRes := AddUser("alice", "alice")
	if !bRes || output != AddUserSuccessful {
		t.Errorf("Add user alice fail ", bRes, output)
	}
	output, bRes = AddUser("bob", "bob")
	if !bRes || output != AddUserSuccessful {
		t.Errorf("Add user bob fail ", bRes, output)
	}

	Storage.GlobalVariables["var"] = Variable{}
	Storage.GlobalVariables["var1"] = Variable{}

	output, bRes = SetDelegation("var", "admin", PermissionDelegate, "alice")
	if !bRes || output != SetDelegationSuccessful {
		t.Errorf("Set delegation fail", bRes, output)
	}

	output, bRes = SetDelegation("var", "admin", PermissionWrite, "alice")
	if !bRes || output != SetDelegationSuccessful {
		t.Errorf("Set delegation fail", bRes, output)
	}

	output, bRes = SetDelegation("all", "alice", PermissionWrite, "bob")
	if !bRes || output != SetDelegationSuccessful {
		t.Errorf("User chain delegation", bRes, output)
	}
	if HasPermission("var1", "bob", PermissionWrite) {
		t.Errorf("Bob  have write permission on delegated var")
	}
	if !HasPermission("var", "bob", PermissionWrite) {
		t.Errorf("Bob  doesn't have write permission on delegated var")
	}
}

func TestDeleteDelegation(t *testing.T) {
	SetupInitialPermissionState("admin")
	if !Login("admin", "admin") {
		t.Errorf("admin login fail")
	}
	output, bRes := AddUser("alice", "alice")
	if !bRes || output != AddUserSuccessful {
		t.Errorf("Add user alice fail ", bRes, output)
	}
	output, bRes = AddUser("bob", "bob")
	if !bRes || output != AddUserSuccessful {
		t.Errorf("Add user bob fail ", bRes, output)
	}

	Storage.GlobalVariables["admin_var"] = Variable{}
	Storage.GlobalVariables["var"] = Variable{}

	output, bRes = SetDelegation("var", "admin", PermissionDelegate, "alice")
	if !bRes || output != SetDelegationSuccessful {
		t.Errorf("Set delegation fail", bRes, output)
	}
	output, bRes = SetDelegation("var", "admin", PermissionAppend, "alice")
	if !bRes || output != SetDelegationSuccessful {
		t.Errorf("Set delegation fail", bRes, output)
	}
	output, bRes = SetDelegation("var", "admin", PermissionWrite, "alice")
	if !bRes || output != SetDelegationSuccessful {
		t.Errorf("Set delegation fail", bRes, output)
	}
	if !HasPermission("var", "alice", PermissionDelegate) || !HasPermission("var", "alice", PermissionWrite) {
		t.Errorf("User does'n have permissions on var")
	}
	output, bRes = DeleteDelegation("var", "admin", PermissionWrite, "alice")
	if !bRes || output != DeleteDelegationSuccessful {
		t.Errorf("Delete delegation fail", bRes, output)
	}
	if !HasPermission("var", "alice", PermissionDelegate) || HasPermission("var", "alice", PermissionWrite) {
		t.Errorf("Alice should have PermissionDelegate and not have PermissionWrite on var")
	}

	//AccessDeniedResult
	if !Login("alice", "alice") {
		t.Errorf("admin login fail")
	}
	output, bRes = DeleteDelegation("var", "admin", PermissionRead, "bob")
	if bRes || output != AccessDeniedResult {
		t.Errorf("User can't set delegation from admin user", bRes, output)
	}
	output, bRes = DeleteDelegation("admin_var", "bob", PermissionRead, "bob")
	if bRes || output != AccessDeniedResult {
		t.Errorf("User can't set delegation on admin_var", bRes, output)
	}

	//chain delegation break if we remove middle elem
	output, bRes = SetDelegation("var", "alice", PermissionAppend, "bob")
	if !bRes || output != SetDelegationSuccessful {
		t.Errorf("Set delegation fail", bRes, output)
	}
	if !HasPermission("var", "bob", PermissionAppend) {
		t.Errorf("Bob should have PermissionRead on var")
	}
	output, bRes = DeleteDelegation("var", "admin", PermissionAppend, "alice")
	if !bRes || output != DeleteDelegationSuccessful {
		t.Errorf("Fail delete own delegation", bRes, output)
	}
	if HasPermission("var", "bob", PermissionAppend) {
		t.Errorf("Bob should not have PermissionRead on var")
	}
}

// TODO need test for DeleteAllDelegation
// TODO need test for anyone user
// TODO need test for create new principal when default delegator not anyone
