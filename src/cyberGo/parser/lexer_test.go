package parser

import "testing"

func TestNext(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		result []token
	}{
		{"Termination", "***", []token{{typ: tokenTerminate}}},
		{"String parsing", `"abc"`, []token{{typ: tokenStr, val: "abc"}}},
		{"Unclosed string", `set a = "abc`, []token{
			{typ: tokenSet},
			{typ: tokenId, val: "a"},
			{typ: tokenEquals},
			{typ: tokenError},
		}},
		{"As principal", `as principal admin password "admin" do`, []token{
			{typ: tokenAs},
			{typ: tokenPrincipal},
			{typ: tokenId, val: "admin"},
			{typ: tokenPassword},
			{typ: tokenStr, val: "admin"},
			{typ: tokenDo},
		}},
		{"Create principal", `create principal alice "alices_password"`, []token{
			{typ: tokenCreate},
			{typ: tokenPrincipal},
			{typ: tokenId, val: "alice"},
			{typ: tokenStr, val: "alices_password"},
		}},
		{"Set variable", `set msg = "Hi Alice. Good luck in Build-it, Break-it, Fix-it!"`, []token{
			{typ: tokenSet},
			{typ: tokenId, val: "msg"},
			{typ: tokenEquals},
			{typ: tokenStr, val: "Hi Alice. Good luck in Build-it, Break-it, Fix-it!"},
		}},
		{"Set delegation", "set delegation msg admin read -> alice", []token{
			{typ: tokenSet},
			{typ: tokenDelegation},
			{typ: tokenId, val: "msg"},
			{typ: tokenId, val: "admin"},
			{typ: tokenRead},
			{typ: tokenArrow},
			{typ: tokenId, val: "alice"},
		}},
		{"Incomplete allow operator", "set delegation msg admin read - alice", []token{
			{typ: tokenSet},
			{typ: tokenDelegation},
			{typ: tokenId, val: "msg"},
			{typ: tokenId, val: "admin"},
			{typ: tokenRead},
			{typ: tokenError},
		}},
		{"Line comment", "// test comment", []token{
			{typ: tokenComment, val: "test comment"},
		}},
		{"Incomplete comment", `set a = "abc" / test`, []token{
			{typ: tokenSet},
			{typ: tokenId, val: "a"},
			{typ: tokenEquals},
			{typ: tokenStr, val: "abc"},
			{typ: tokenError},
		}},
		{"Comment at the end of line", `set x = "test"// test comment`, []token{
			{typ: tokenSet},
			{typ: tokenId, val: "x"},
			{typ: tokenEquals},
			{typ: tokenStr, val: "test"},
			{typ: tokenComment, val: "test comment"},
		}},
		{"Spaces at the beginning of line comment", "  // test comment", []token{
			{typ: tokenError},
		}},
		{"Invalid symbols in input", "*abc", []token{{typ: tokenError}}},
	}
	for _, c := range cases {
		lex := newLexer(c.in)
		for _, res := range c.result {
			tok := lex.next()
			if (tok.typ != res.typ) || ((res.typ != tokenError) && (tok.val != res.val)) {
				t.Errorf("%s: %+v != %+v", c.name, res, tok)
			}
		}
		tok := lex.next()
		if tok.typ != tokenEnd {
			t.Errorf("%s: unparsed tokens left - %+v", c.name, tok)
		}
	}
}