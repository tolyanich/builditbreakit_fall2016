package parser

import (
	"fmt"
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		result Cmd
	}{
		{"as principal", `as principal admin password "admin" do`, Cmd{
			CmdAsPrincipal,
			ArgsType{Identifier("admin"), "admin"},
		}},
		{"exit", "exit", Cmd{Type: CmdExit}},
		{"return string", `return "test"`, Cmd{
			CmdReturn,
			ArgsType{"test"},
		}},
		{"return identifier", "return x", Cmd{
			CmdReturn,
			ArgsType{Identifier("x")},
		}},
		{"create principal", `create principal alice "alice_password"`, Cmd{
			CmdCreatePrincipal,
			ArgsType{Identifier("alice"), "alice_password"},
		}},
		{"change password", `change password alice "new_password"`, Cmd{
			CmdChangePassword,
			ArgsType{Identifier("alice"), "new_password"},
		}},
		{"set string", `set x = "hello"`, Cmd{
			CmdSet,
			ArgsType{Identifier("x"), "hello"},
		}},
		{"set identifier", `set x = y`, Cmd{
			CmdSet,
			ArgsType{Identifier("x"), Identifier("y")},
		}},
		{"append to with string", `append to x with "abc"`, Cmd{
			CmdAppendTo,
			ArgsType{Identifier("x"), "abc"},
		}},
		{"append to with identifier", `append to x with y`, Cmd{
			CmdAppendTo,
			ArgsType{Identifier("x"), Identifier("y")},
		}},
		{"local with string", `local x = "abc"`, Cmd{
			CmdLocal,
			ArgsType{Identifier("x"), "abc"},
		}},
		{"local with identifier", `local x = y`, Cmd{
			CmdLocal,
			ArgsType{Identifier("x"), Identifier("y")},
		}},
		{"foreach with string", `foreach y in x replacewith "abc"`, Cmd{
			CmdForeach,
			ArgsType{Identifier("y"), Identifier("x"), "abc"},
		}},
		{"foreach with identifier", `foreach y in x replacewith z`, Cmd{
			CmdForeach,
			ArgsType{Identifier("y"), Identifier("x"), Identifier("z")},
		}},
		{"set delegation x", `set delegation x q read -> p`, Cmd{
			CmdSetDelegation,
			ArgsType{Identifier("x"), Identifier("q"), Identifier("read"), Identifier("p")},
		}},
		{"set delegation all", `set delegation all q read -> p`, Cmd{
			CmdSetDelegation,
			ArgsType{Identifier("all"), Identifier("q"), Identifier("read"), Identifier("p")},
		}},
		{"delete delegation x", `delete delegation x q read -> p`, Cmd{
			CmdDeleteDelegation,
			ArgsType{Identifier("x"), Identifier("q"), Identifier("read"), Identifier("p")},
		}},
		{"delete delegation all", `delete delegation all q read -> p`, Cmd{
			CmdDeleteDelegation,
			ArgsType{Identifier("all"), Identifier("q"), Identifier("read"), Identifier("p")},
		}},
		{"default delegator = x", `default delegator = x`, Cmd{
			CmdDefaultDelegator,
			ArgsType{Identifier("x")},
		}},
		{"set field var", `set x = a.b`, Cmd{
			CmdSet,
			ArgsType{Identifier("x"), FieldVal{"a", "b"}},
		}},
		{"parse should fail with incomplete field", `set x = a.`, Cmd{
			CmdError,
			ArgsType{fmt.Errorf("Unexpected token 'end' for field value")},
		}},
		{"parse empty list", `set x = []`, Cmd{
			CmdSet,
			ArgsType{Identifier("x"), List{}},
		}},
		{"parse should fail for incomplete list", `set x = [`, Cmd{
			CmdError,
			ArgsType{fmt.Errorf("Unexpected token 'end' for list type")},
		}},
		{"parse empty object", `set x = {}`, Cmd{
			CmdSet,
			ArgsType{Identifier("x"), Record{}},
		}},
		{"parse should fail for incomplete record", `set x = {`, Cmd{
			CmdError,
			ArgsType{fmt.Errorf("Unexpected token 'end' for record key name")},
		}},
		{"parse simple object with strings", `set x = {x = "a", y = "b"}`, Cmd{
			CmdSet,
			ArgsType{Identifier("x"), Record{"x": "a", "y": "b"}},
		}},
		{"parse object with vars", `set x = {x = "a", y = b, z = x}`, Cmd{
			CmdSet,
			ArgsType{Identifier("x"), Record{"x": "a", "y": Identifier("b"), "z": Identifier("x")}},
		}},
		{"parse object with fieldvar", `set x = {x = "a", y = a.b}`, Cmd{
			CmdSet,
			ArgsType{Identifier("x"), Record{"x": "a", "y": FieldVal{"a", "b"}}},
		}},
		{"split function", `set y = split(x,"--")`, Cmd{
			CmdSet,
			ArgsType{Identifier("y"), Function{"split", ArgsType{Identifier("x"), "--"}}},
		}},
		{"concat function", `set z = concat(x,y.fst)`, Cmd{
			CmdSet,
			ArgsType{Identifier("z"), Function{"concat", ArgsType{Identifier("x"), FieldVal{"y", "fst"}}}},
		}},
	}
	for _, c := range cases {
		cmd := Parse(c.in)
		if cmd.Type != c.result.Type {
			t.Errorf("%s: Invalid command returned: %+v != %+v", c.name, cmd.Type, c.result.Type)
		}
		if len(cmd.Args) == len(c.result.Args) {
			for i := range c.result.Args {
				if !reflect.DeepEqual(c.result.Args[i], cmd.Args[i]) {
					t.Errorf("%s: Invalid argument %d: %v != %v", c.name, i, c.result.Args[i], cmd.Args[i])
				}
			}
		} else {
			t.Errorf("%s: Invalid arguments count: %+v != %+v", c.name, cmd.Args, c.result.Args)
		}
	}
}

func TestString(t *testing.T) {
	var id interface{} = "test"
	switch id.(type) {
	case Identifier:
		t.Error("Should not be a Identifier")
	}
}

func TestIdentifier(t *testing.T) {
	var id interface{} = Identifier("test")
	switch id.(type) {
	case string:
		t.Error("Should not be a string")
	}
}
