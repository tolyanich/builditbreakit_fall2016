package store

import "testing"

func TestAsPrincipal(t *testing.T) {
	s := NewStore("password")
	ls, err := s.AsPrincipal(adminUsername, "password")
	if err != nil {
		t.Fatalf("Unexpeted error: %v", err)
	}
	if ls == nil {
		t.Fatalf("LocalStore should peresent")
	}
	if !ls.IsAdmin() {
		t.Errorf("User must be an admin")
	}

	if _, err := s.AsPrincipal("test", "test"); err != ErrFailed {
		t.Errorf("Should fail if user does not exist")
	}
	if _, err := s.AsPrincipal(adminUsername, "test"); err != ErrDenied {
		t.Errorf("Should denied if invalid password")
	}
}

func TestChangePassword(t *testing.T) {
	s := NewStore("password")
	ls, err := s.AsPrincipal(adminUsername, "password")
	if err != nil {
		t.Fatalf("admin Login fail")
	}
	err = ls.ChangePassword("admin", "newadmin")
	if err != nil {
		t.Errorf("ChangePassword fail ", err)
	}
	ls.Commit()

	ls, err = s.AsPrincipal(adminUsername, "newadmin")
	if err != nil {
		t.Fatalf("Loged with new password fail")
	}
	err = ls.ChangePassword("notexist", "newadmin")
	if err != ErrFailed {
		t.Errorf("ChangePassword on notexist user success ", err)
	}
	err = ls.CreatePrincipal("alice", "alice")
	if err != nil {
		t.Errorf("Add user alice fail ", err)
	}
	err = ls.ChangePassword("alice", "alice1")
	if err != nil {
		t.Errorf("ChangePassword alice by admin fail ", err)
	}
	ls.Commit()
	ls, err = s.AsPrincipal("alice", "alice1")
	if err != nil {
		t.Fatalf("Login with changed password fail")
	}
	err = ls.ChangePassword("alice", "alice_newpass")
	if err != nil {
		t.Errorf("ChangePassword alice by alice fail ", err)
	}
	ls.Commit()

	ls, err = s.AsPrincipal("alice", "alice_newpass")
	if err != nil {
		t.Fatalf("Login with changed password fail")
	}
	err = ls.ChangePassword("admin", "alice_newpass")
	if err == nil {
		t.Errorf("ChangePassword admin by alice success ", err)
	}
}

func TestCreatePrincipal(t *testing.T) {
	s := NewStore("password")
	ls, err := s.AsPrincipal(adminUsername, "password")
	if err != nil {
		t.Fatalf("Login fail")
	}
	err = ls.CreatePrincipal("alice", "alice")
	if err != nil {
		t.Errorf("Add user fail ", err)
	}
	ls.Commit()
	ls, err = s.AsPrincipal("alice", "alice")
	if err != nil {
		t.Fatalf("Can't login on created user")
	}

	err = ls.CreatePrincipal("bob", "bob")
	if err == nil {
		t.Errorf("Should deny create user for non admin", err)
	}

}

func TestSetgetDefaultDelegator(t *testing.T) {
	s := NewStore("password")
	ls, err := s.AsPrincipal(adminUsername, "password")
	if err != nil {
		t.Fatalf("Login fail")
	}
	err = ls.SetDefaultDelegator("admin")
	if err != nil {
		t.Errorf("SetDefaultDelegator fail", err)
	}
	output := ls.getDefaultDelegator()
	if output != "admin" {
		t.Errorf("Error in ls.getDefaultDelegator", output)
	}
}

func TestAccessDefaultDelegator(t *testing.T) {
	s := NewStore("password")
	ls, err := s.AsPrincipal(adminUsername, "password")
	if err != nil {
		t.Fatalf("Login fail")
	}
	ls.CreatePrincipal("alice", "alice")
	ls.Commit()
	ls, err = s.AsPrincipal("alice", "alice")
	if err != nil {
		t.Fatalf("Login fail")
	}
	err = ls.SetDefaultDelegator("changed")
	if err == nil {
		t.Errorf("SetDefaultDelegator should fail for non admin", err)
	}
	output := ls.getDefaultDelegator()
	if output != "anyone" {
		t.Errorf("DefaultDelegator shold be anyone", output)
	}
}

func TestPermissionOnNewVar(t *testing.T) {
	s := NewStore("password")
	ls, err := s.AsPrincipal(adminUsername, "password")
	if err != nil {
		t.Fatalf("admin login fail")
	}
	ls.setPermissionOnNewVariable("admin_var")

	if !ls.HasPermission("admin_var", "admin", PermissionRead) {
		t.Errorf("Admin does'n have read permission on created var")
	}
	if !ls.HasPermission("admin_var", "admin", PermissionWrite) {
		t.Errorf("Admin does'n have PermissionWrite permission on created var")
	}
	if !ls.HasPermission("admin_var", "admin", PermissionDelegate) {
		t.Errorf("Admin does'n have PermissionDelegate permission on created var")
	}
	if !ls.HasPermission("admin_var", "admin", PermissionAppend) {
		t.Errorf("Admin does'n have PermissionAppend permission on created var")
	}

	err = ls.CreatePrincipal("alice", "alice")
	if err != nil {
		t.Fatalf("Add user fail ", err)
	}
	ls.Commit()
	ls, err = s.AsPrincipal("alice", "alice")
	if err != nil {
		t.Fatalf("Should be able to login on created user")
	}
	ls.setPermissionOnNewVariable("var")
	if !ls.HasPermission("var", "alice", PermissionRead) {
		t.Errorf("User does'n have read permission on created var")
	}
	if !ls.HasPermission("var", "alice", PermissionWrite) {
		t.Errorf("User does'n have PermissionWrite permission on created var")
	}
	if !ls.HasPermission("var", "alice", PermissionDelegate) {
		t.Errorf("User does'n have PermissionDelegate permission on created var")
	}
	if !ls.HasPermission("var", "alice", PermissionAppend) {
		t.Errorf("User does'n have PermissionAppend permission on created var")
	}
	if !ls.HasPermission("var", "admin", PermissionRead) || !ls.HasPermission("var", "admin", PermissionWrite) ||
		!ls.HasPermission("var", "admin", PermissionDelegate) || !ls.HasPermission("var", "admin", PermissionAppend) {
		t.Errorf("Admin should always have full perimission on all users variables")
	}

	if ls.HasPermission("admin_var", "alice", PermissionRead) || ls.HasPermission("admin_var", "alice", PermissionWrite) ||
		ls.HasPermission("admin_var", "alice", PermissionDelegate) || ls.HasPermission("admin_var", "alice", PermissionAppend) {
		t.Errorf("User should not have perimission on admin variables")
	}
}

func TestSetDelegation(t *testing.T) {
	s := NewStore("password")
	ls, err := s.AsPrincipal(adminUsername, "password")
	if err != nil {
		t.Fatalf("admin login fail")
	}
	err = ls.CreatePrincipal("alice", "alice")
	if err != nil {
		t.Errorf("Add user alice fail ", err)
	}
	err = ls.CreatePrincipal("bob", "bob")
	if err != nil {
		t.Errorf("Add user bob fail ", err)
	}

	ls.Set("admin_var", "admin_var")
	ls.Set("var", "var")
	if ls.HasPermission("admin_var", "alice", PermissionRead) {
		t.Errorf("User should not have read permission on admin var")
	}
	err = ls.SetDelegation("admin_var", "admin", PermissionRead, "alice")
	if err != nil {
		t.Errorf("Set delegation should not fail", err)
	}
	if !ls.HasPermission("admin_var", "alice", PermissionRead) {
		t.Errorf("User should have read permission on delegated var")
	}
	err = ls.SetDelegation("var", "admin", PermissionDelegate, "alice")
	if err != nil {
		t.Errorf("Set delegation should not fail", err)
	}
	err = ls.SetDelegation("var", "admin", PermissionWrite, "alice")
	if err != nil {
		t.Errorf("Set delegation should not fail", err)
	}
	if !ls.HasPermission("var", "alice", PermissionDelegate) {
		t.Errorf("User should have delegation permission on delegated var")
	}
	ls.Commit()

	//AccessDeniedResult
	ls, err = s.AsPrincipal("alice", "alice")
	if err != nil {
		t.Fatalf("User login should not fail")
	}
	err = ls.SetDelegation("var", "admin", PermissionRead, "alice")
	if err == nil {
		t.Errorf("User can set delegation from admin user", err)
	}
	err = ls.SetDelegation("admin_var", "alice", PermissionRead, "alice")
	if err == nil {
		t.Errorf("User can set delegation on admin_var", err)
	}

	//chain delegation
	err = ls.SetDelegation("var", "alice", PermissionWrite, "bob")
	if err != nil {
		t.Errorf("User can't set chain delegation", err)
	}
	err = ls.SetDelegation("var", "alice", PermissionRead, "bob")
	if err != nil {
		t.Errorf("User can't set chain delegation", err)
	}
	if ls.HasPermission("var", "bob", PermissionRead) {
		t.Errorf("Bob should not have read permission on delegated var")
	}
	if !ls.HasPermission("var", "bob", PermissionWrite) {
		t.Errorf("Bob should have write permission on delegated var")
	}
}

func TestSetAllDelegation(t *testing.T) {
	s := NewStore("password")
	ls, err := s.AsPrincipal(adminUsername, "password")
	if err != nil {
		t.Fatalf("admin login fail")
	}
	err = ls.CreatePrincipal("alice", "alice")
	if err != nil {
		t.Errorf("Add user alice fail ", err)
	}
	err = ls.CreatePrincipal("bob", "bob")
	if err != nil {
		t.Errorf("Add user bob fail ", err)
	}

	ls.Set("admin_var", "admin_var")
	ls.Set("var", "var")

	err = ls.SetDelegation("var", "admin", PermissionDelegate, "alice")
	if err != nil {
		t.Errorf("Admin should be able set delegation", err)
	}

	err = ls.SetDelegation("var", "admin", PermissionWrite, "alice")
	if err != nil {
		t.Errorf("Admin should be able set delegation", err)
	}

	err = ls.SetDelegation("all", "alice", PermissionWrite, "bob")
	if err != nil {
		t.Errorf("Should be able to set all delegation", err)
	}
	if ls.HasPermission("var1", "bob", PermissionWrite) {
		t.Errorf("Bob  shold not have write permission on delegated var")
	}
	if !ls.HasPermission("var", "bob", PermissionWrite) {
		t.Errorf("Bob  should have write permission on delegated var")
	}
}

func TestDeleteDelegation(t *testing.T) {
	s := NewStore("password")
	ls, err := s.AsPrincipal(adminUsername, "password")
	if err != nil {
		t.Fatalf("admin login fail")
	}
	err = ls.CreatePrincipal("alice", "alice")
	if err != nil {
		t.Errorf("Add user alice fail ", err)
	}
	err = ls.CreatePrincipal("bob", "bob")
	if err != nil {
		t.Errorf("Add user bob fail ", err)
	}

	ls.Set("admin_var", "admin_var")
	ls.Set("var", "var")

	err = ls.SetDelegation("var", "admin", PermissionDelegate, "alice")
	if err != nil {
		t.Errorf("Admin should be able set delegation", err)
	}
	err = ls.SetDelegation("var", "admin", PermissionAppend, "alice")
	if err != nil {
		t.Errorf("Admin should be able set delegation", err)
	}
	err = ls.SetDelegation("var", "admin", PermissionWrite, "alice")
	if err != nil {
		t.Errorf("Admin should be able set delegation", err)
	}
	if !ls.HasPermission("var", "alice", PermissionDelegate) || !ls.HasPermission("var", "alice", PermissionWrite) {
		t.Errorf("User should have permissions on var")
	}
	err = ls.DeleteDelegation("var", "admin", PermissionWrite, "alice")
	if err != nil {
		t.Errorf("Admin should be able to delete delegation", err)
	}
	if !ls.HasPermission("var", "alice", PermissionDelegate) || ls.HasPermission("var", "alice", PermissionWrite) {
		t.Errorf("Alice should have PermissionDelegate and not have PermissionWrite on var")
	}
	ls.Commit()
	//AccessDeniedResult
	ls, err = s.AsPrincipal("alice", "alice")
	if err != nil {
		t.Fatalf("admin login fail")
	}
	err = ls.DeleteDelegation("var", "admin", PermissionRead, "bob")
	if err == nil {
		t.Errorf("User should fail set delegation from admin user", err)
	}
	err = ls.DeleteDelegation("admin_var", "bob", PermissionRead, "bob")
	if err == nil {
		t.Errorf("User shold not delete delegation from admin_var", err)
	}

	//chain delegation break if we remove middle elem
	err = ls.SetDelegation("var", "alice", PermissionAppend, "bob")
	if err != nil {
		t.Errorf("User should be able set delegation", err)
	}
	if !ls.HasPermission("var", "bob", PermissionAppend) {
		t.Errorf("Bob should have PermissionRead on var")
	}
	err = ls.DeleteDelegation("var", "admin", PermissionAppend, "alice")
	if err != nil {
		t.Errorf("User should be able to delete own delegation", err)
	}
	if ls.HasPermission("var", "bob", PermissionAppend) {
		t.Errorf("Bob should not have PermissionRead on var")
	}
}

func TestAppendArray(t *testing.T) {
	s := NewStore("password")
	ls, err := s.AsPrincipal(adminUsername, "password")
	if err != nil {
		t.Fatalf("Login fail")
	}
	ls.CreatePrincipal("alice", "alice")
	ls.Set("var_write_only", ListVal{"1", "2"})
	ls.Set("var_append_only", ListVal{"1", "2"})
	err = ls.SetDelegation("var_append_only", "admin", PermissionAppend, "alice")
	if err != nil {
		t.Errorf("User should be able set delegation", err)
	}
	err = ls.SetDelegation("var_write_only", "admin", PermissionWrite, "alice")
	if err != nil {
		t.Errorf("User should be able set delegation", err)
	}
	arr := []string{"1", "2"}
	err = ls.Set("x", ListVal{"1", "2"})
	if err != nil {
		t.Fatalf("Should set x with array")
	}
	val, err := ls.Get("x")
	if err != nil {
		t.Errorf("Should be the same", arr, val, err)
	}
	err = ls.SetDelegation("x", "admin", PermissionAppend, "alice")
	if err != nil {
		t.Errorf("User should be able set delegation", err)
	}
	err = ls.SetDelegation("x", "admin", PermissionWrite, "alice")
	if err != nil {
		t.Errorf("User should be able set delegation", err)
	}
	err = ls.SetDelegation("x", "admin", PermissionRead, "alice")
	if err != nil {
		t.Errorf("User should be able set delegation", err)
	}

	ls.Commit()
	ls, err = s.AsPrincipal("alice", "alice")
	if err != nil {
		t.Fatalf("Login fail")
	}
	val, err = ls.Get("x")
	if err != nil {
		t.Errorf("Should be the same", arr, val, err)
	}
	err = ls.AppendTo("x", ListVal{"3"})
	if err != nil {
		t.Fatalf("Should append arr with arr", err)
	}
	arr = append(arr, []string{"3"}...)
	val, err = ls.Get("x")
	if err != nil {
		t.Errorf("Should be the same", arr, val, err)
	}
	err = ls.AppendTo("x", "3")
	if err != nil {
		t.Errorf("Should append arr with arr", err)
	}
	arr = append(arr, "3")
	val, err = ls.Get("x")
	// t.Errorf("Should be the same", arr, val, err)
	if err != nil {
		t.Errorf("Should be the same", arr, val, err)
	}
	err = ls.AppendTo("var_write_only", "3")
	if err != nil {
		t.Errorf("Should append on write_only var", err)
	}
	err = ls.AppendTo("var_append_only", "3")
	if err != nil {
		t.Errorf("Should append on var_append_only var", err)
	}
}

func TestDiscradsInFail(t *testing.T) {
	s := NewStore("password")
	ls, err := s.AsPrincipal(adminUsername, "password")
	if err != nil {
		t.Fatalf("admin login fail")
	}
	err = ls.CreatePrincipal("alice", "alice")
	if err != nil {
		t.Errorf("Add user alice fail ", err)
	}
	ls.Set("admin_var", "admin_var")
	err = ls.SetDelegation("admin_var", "admin", PermissionAppend, "alice")
	if err != nil {
		t.Errorf("Admin should be able set delegation", err)
	}
	ls.Commit()

	ls, err = s.AsPrincipal(adminUsername, "password")
	if err != nil {
		t.Fatalf("admin login fail")
	}
	_, err = ls.Get("admin_var")
	if err != nil {
		t.Errorf("Should be the same")
	}
	err = ls.CreatePrincipal("bob", "bob")
	if err != nil {
		t.Errorf("Add user bob fail ", err)
	}
	ls.Set("fail", "fail_var")
	err = ls.SetDelegation("admin_var", "admin", PermissionDelegate, "alice")
	if err != nil {
		t.Errorf("Admin should be able set delegation", err)
	}
	// NO COMMIT HERE
	ls, err = s.AsPrincipal("bob", "bob")
	if err != ErrFailed {
		t.Fatalf("Can login with discarded user", err)
	}

	ls, err = s.AsPrincipal(adminUsername, "password")
	if err != nil {
		t.Fatalf("admin login fail")
	}
	_, err = ls.Get("fail_var")
	if err != ErrFailed {
		t.Errorf("Admin can get discarded var")
	}

	if ls.HasPermission("admin_var", "alice", PermissionDelegate) {
		t.Errorf("Alice should not have discarded PermissionDelegate")
	}
	if !ls.HasPermission("admin_var", "alice", PermissionAppend) {
		t.Errorf("Alice should have PermissionAppend")
	}
}

func TestDefaultDelegatorNotAnyone(t *testing.T) {
	s := NewStore("password")
	ls, err := s.AsPrincipal(adminUsername, "password")
	if err != nil {
		t.Fatalf("admin login fail")
	}
	err = ls.CreatePrincipal("alice", "alice")
	if err != nil {
		t.Errorf("Add user alice fail ", err)
	}
	ls.Set("admin_var", "admin_var")
	err = ls.SetDelegation("admin_var", "admin", PermissionAppend, "alice")
	if err != nil {
		t.Errorf("Admin should be able set delegation", err)
	}
	err = ls.SetDelegation("admin_var", "admin", PermissionDelegate, "alice")
	if err != nil {
		t.Errorf("Admin should be able set delegation", err)
	}
	ls.SetDefaultDelegator("alice")
	if err != nil {
		t.Errorf("SetDefaultDelegator should work", err)
	}
	ls.Commit()
	ls, err = s.AsPrincipal(adminUsername, "password")
	if err != nil {
		t.Fatalf("admin login fail")
	}
	delegator := ls.getDefaultDelegator()
	if delegator != "alice" {
		t.Errorf("GetDefaultDelegator returns wrong name", err)
	}
	err = ls.CreatePrincipal("bob", "bob")
	if err != nil {
		t.Errorf("Add user alice fail ", err)
	}
	if !ls.HasPermission("admin_var", "bob", PermissionAppend) {
		t.Errorf("Bob should have PermissionAppend")
	}

}

func TestCiclePermission(t *testing.T) {
	s := NewStore("password")
	ls, err := s.AsPrincipal(adminUsername, "password")
	if err != nil {
		t.Fatalf("admin login fail")
	}
	err = ls.CreatePrincipal("ab", "ab")
	if err != nil {
		t.Errorf("Add user ab fail ", err)
	}
	err = ls.CreatePrincipal("bc", "bc")
	if err != nil {
		t.Errorf("Add user bc fail ", err)
	}
	err = ls.CreatePrincipal("ca", "ca")
	if err != nil {
		t.Errorf("Add user ca fail ", err)
	}
	ls.Set("admin_var", "admin_var")
	err = ls.SetDelegation("admin_var", "admin", PermissionRead, "ab")
	if err != nil {
		t.Errorf("Admin should be able set delegation", err)
	}
	err = ls.SetDelegation("admin_var", "ab", PermissionRead, "bc")
	if err != nil {
		t.Errorf("Admin should be able set delegation", err)
	}
	err = ls.SetDelegation("admin_var", "bc", PermissionRead, "ca")
	if err != nil {
		t.Errorf("Admin should be able set delegation", err)
	}
	err = ls.SetDelegation("admin_var", "ca", PermissionRead, "ab")
	if err != nil {
		t.Errorf("Admin should be able set delegation", err)
	}
	ls.Commit()
	ls, err = s.AsPrincipal(adminUsername, "password")
	if err != nil {
		t.Fatalf("admin login fail")
	}
	if !ls.HasPermission("admin_var", "ab", PermissionRead) {
		t.Errorf("ab should have PermissionRead")
	}
	if !ls.HasPermission("admin_var", "bc", PermissionRead) {
		t.Errorf("bc should have PermissionRead")
	}
	if !ls.HasPermission("admin_var", "ca", PermissionRead) {
		t.Errorf("ca should have PermissionRead")
	}
	//delete delegation from admin
	err = ls.DeleteDelegation("admin_var", "admin", PermissionRead, "ab")
	if err != nil {
		t.Errorf("Admin should be able set delegation", err)
	}

	if ls.HasPermission("admin_var", "ab", PermissionRead) {
		t.Errorf("ab should not have PermissionRead")
	}
	if ls.HasPermission("admin_var", "bc", PermissionRead) {
		t.Errorf("bc should not have PermissionRead")
	}
	if ls.HasPermission("admin_var", "ca", PermissionRead) {
		t.Errorf("ca should not have PermissionRead")
	}
}
