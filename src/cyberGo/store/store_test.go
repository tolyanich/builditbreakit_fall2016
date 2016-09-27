package store

import "testing"

func TestAsPrincipal(t *testing.T) {
	s := NewStore("password")
	ls, err := s.AsPrincipal(adminUsername, "password")
	if err != nil {
		t.Errorf("Unexpeted error: %v", err)
	}
	if ls == nil {
		t.Errorf("LocalStore should present")
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
