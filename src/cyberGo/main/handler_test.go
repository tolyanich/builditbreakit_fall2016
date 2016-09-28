package main

import (
	"testing"

	"cyberGo/parser"
	"cyberGo/store"
)

func TestPrepareString(t *testing.T) {
	h := Handler{}
	val, err := h.prepareValue("test")
	if err != nil {
		t.Error("Unexpected error for prepare string:", err)
	}
	if val != "test" {
		t.Error("Wrong value for prepared string: (%v != %v)", val, "test")
	}
}

func TestPrepareList(t *testing.T) {
	h := Handler{}
	in := parser.List{"abc", "def"}
	val, err := h.prepareValue(in)
	if err != nil {
		t.Error("Unexpected error for prepare list:", err)
	}
	if l, ok := val.(parser.List); ok {
		if len(l) != len(in) {
			t.Error("Inavlid list size: %d != %d", len(l), len(in))
		}
		for i := range in {
			if l[i] != in[i] {
				t.Error("Inavlid %d list item", i, l[i], in[i])
			}
		}
	} else {
		t.Error("Unexpected return type")
	}
}

func TestPrepareRecordWithStrings(t *testing.T) {
	h := Handler{}
	in := parser.Record{"a": "b", "c": "d"}
	val, err := h.prepareValue(in)
	if err != nil {
		t.Error("Unexpected error for prepare record:", err)
	}
	if r, ok := val.(parser.Record); ok {
		if len(r) != len(in) {
			t.Error("Inavlid record size: %d != %d", len(r), len(in))
		}
		for k, v := range in {
			if o, ok := r[k]; ok {
				if o != v {
					t.Error("Invalid value for '%s' key in resulting record: %v != %v", k, o, v)
				}
			} else {
				t.Errorf("'%s' key not found in resulting record", k)
			}
		}
	} else {
		t.Error("Unexpected return type")
	}
}

func TestPrepareIdentifierForString(t *testing.T) {
	s := store.NewStore("admin")
	// TODO: create mock for local store
	ls, err := s.AsPrincipal("admin", "admin")
	ls.Set("a", "b")
	h := Handler{ls: ls}

	val, err := h.prepareValue(parser.Identifier("a"))
	if err != nil {
		t.Error("Unexpected error for prepare string value:", err)
	}
	if val != "b" {
		t.Error("Wrong value for prepared string value: (%v != %v)", val, "b")
	}
}

func TestPrepareFieldVarIdentifier(t *testing.T) {
	s := store.NewStore("admin")
	// TODO: create mock for local store
	ls, err := s.AsPrincipal("admin", "admin")
	ls.Set("a", store.RecordVal{"b": "value"})
	h := Handler{ls: ls}

	val, err := h.prepareValue(parser.FieldVal{"a", "b"})
	if err != nil {
		t.Error("Unexpected error for prepare fieldvar value:", err)
	}
	if val != "value" {
		t.Error("Wrong value for prepared fieldvar value: (%v != %v)", val, "b")
	}
}

func TestPrepareRecordIdentifier(t *testing.T) {
	s := store.NewStore("admin")
	// TODO: create mock for local store
	ls, err := s.AsPrincipal("admin", "admin")
	ls.Set("a", "b")
	h := Handler{ls: ls}

	in := parser.Record{"a": parser.Identifier("a")}
	val, err := h.prepareValue(in)
	if err != nil {
		t.Error("Unexpected error for prepare string value:", err)
	}
	if r, ok := val.(parser.Record); ok {
		if len(r) != len(in) {
			t.Error("Inavlid record size: %d != %d", len(r), len(in))
		}
		if o, ok := r["a"]; ok {
			if o != "b" {
				t.Errorf("Identifier not equals %s != %s", o, "b")
			}
		} else {
			t.Errorf("'%s' key not found in resulting record", "a")
		}
	} else {
		t.Error("Unexpected return type")
	}
}

func TestPrepareRecordNonexistentIdentifier(t *testing.T) {
	// TODO:
}

func TestPrepareRecordListIdentifier(t *testing.T) {
	// TODO:
}

func TestPrepareRecordRecordIdentifier(t *testing.T) {
	// TODO:
}

func TestPrepareRecordFieldVarIdentifier(t *testing.T) {
	// TODO:
}
