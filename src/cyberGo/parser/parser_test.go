package parser

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		result Cmd
	}{
		{"as principal", `as principal admin password "admin" do`, Cmd{
			CmdAsPrincipal,
			[]string{"admin", "admin"},
		}},
		{"exit", "exit", Cmd{Type: CmdExit}},
		{"return string", `return "test"`, Cmd{
			CmdReturn,
			[]string{"test"},
		}},
		{"return identifier", "return x", Cmd{
			CmdReturn,
			[]string{"x"},
		}},
		{"create principal", `create principal alice "alice_password"`, Cmd{
			CmdCreatePrincipal,
			[]string{"alice", "alice_password"},
		}},
		{"change password", `change password alice "new_password"`, Cmd{
			CmdChangePassword,
			[]string{"alice", "new_password"},
		}},
		{"set string", `set x = "hello"`, Cmd{
			CmdSet,
			[]string{"x", "hello"},
		}},
		{"set identifier", `set x = y`, Cmd{
			CmdSet,
			[]string{"x", "y"},
		}},
		{"append to with string", `append to x with "abc"`, Cmd{
			CmdAppendTo,
			[]string{"x", "abc"},
		}},
		{"append to with identifier", `append to x with y`, Cmd{
			CmdAppendTo,
			[]string{"x", "y"},
		}},
		{"local with string", `local x = "abc"`, Cmd{
			CmdLocal,
			[]string{"x", "abc"},
		}},
		{"local with identifier", `local x = y`, Cmd{
			CmdLocal,
			[]string{"x", "y"},
		}},
		{"foreach with string", `foreach y in x replacewith "abc"`, Cmd{
			CmdForeach,
			[]string{"y", "x", "abc"},
		}},
		{"foreach with identifier", `foreach y in x replacewith z`, Cmd{
			CmdForeach,
			[]string{"y", "x", "z"},
		}},
		{"set delegation x", `set delegation x q read -> p`, Cmd{
			CmdSetDelegation,
			[]string{"x", "q", "read", "p"},
		}},
		{"set delegation all", `set delegation all q read -> p`, Cmd{
			CmdSetDelegation,
			[]string{"all", "q", "read", "p"},
		}},
		{"delete delegation x", `delete delegation x q read -> p`, Cmd{
			CmdDeleteDelegation,
			[]string{"x", "q", "read", "p"},
		}},
		{"delete delegation all", `delete delegation all q read -> p`, Cmd{
			CmdDeleteDelegation,
			[]string{"all", "q", "read", "p"},
		}},
		{"default delegator = x", `default delegator = x`, Cmd{
			CmdDefaultDelegator,
			[]string{"x"},
		}},
	}
	for _, c := range cases {
		cmd := Parse(c.in)
		if cmd.Type != c.result.Type {
			t.Errorf("%s: Invalid command returned: %+v != %+v", c.name, cmd.Type, c.result.Type)
		}
		if len(cmd.Args) == len(c.result.Args) {
			for i := range c.result.Args {
				if c.result.Args[i] != cmd.Args[i] {
					t.Errorf("%s: Invalid argument %d: %v != %v", c.name, i, c.result.Args[i], cmd.Args[i])
				}
			}
		} else {
			t.Errorf("%s: Invalid arguments count: %+v != %+v", c.name, cmd.Args, c.result.Args)
		}
	}
}
