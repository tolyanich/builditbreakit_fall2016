package parser

import "fmt"

type CmdType int

const (
	CmdError            CmdType = iota // error command
	CmdAsPrincipal                     // 'as principal' command
	CmdExit                            // 'exit' command
	CmdReturn                          // 'return' command
	CmdCreatePrincipal                 // 'create principal' command
	CmdChangePassword                  // 'change password' command
	CmdSet                             // 'set' command
	CmdAppendTo                        // 'append to' command
	CmdLocal                           // 'local' command
	CmdForeach                         // 'foreach' command
	CmdSetDelegation                   // 'set delegation' command
	CmdDeleteDelegation                // 'delete delegation' command
	CmdDefaultDelegator                // 'default delegator' command
)

var cmds = [...]string{
	"error",
	"asPrincipal",
	"exit",
	"return",
	"createPrincipal",
	"changePassword",
	"set",
	"appendTo",
	"local",
	"foreach",
	"setDelegation",
	"deleteDelegation",
	"defaultDelegator",
}

func (t CmdType) String() string { return cmds[t] }

type Cmd struct {
	Type CmdType
	Args []string // TODO: change to variable types
}

func Parse(line string) Cmd {
	var cmd Cmd
	lex := newLexer(line)
	tok := lex.next()
	switch tok.typ {
	case tokenAs:
		cmd = parseAsPrincipal(lex)
	case tokenExit:
		cmd = parseExit(lex)
	case tokenReturn:
		cmd = parseReturn(lex)
	case tokenCreate:
		cmd = parseCreatePrincipal(lex)
	case tokenChange:
		cmd = parseChangePassword(lex)
	case tokenSet: // set variable or delegation
		cmd = parseSet(lex)
	case tokenAppend:
		cmd = parseAppend(lex)
	case tokenLocal:
		cmd = parseLocal(lex)
	case tokenForeach:
		cmd = parseForeach(lex)
	case tokenDelete:
		cmd = parseDeleteDelegation(lex)
	case tokenDefault:
		cmd = parseDefaultDelegator(lex)
	default:
		cmd = Cmd{CmdError, []string{fmt.Sprintf("Unexpeted token: %v", tok.typ)}}
	}
	if cmd.Type != CmdError {
		tok = lex.next() // test end of command
		if tok.typ != tokenEnd {
			return invalidTokenError(tok.typ, tokenEnd)
		}
	}
	return cmd
}

// as principal admin password "admin" do
func parseAsPrincipal(lex *lexer) Cmd {
	cmd := Cmd{CmdAsPrincipal, make([]string, 2)}
	tok := lex.next()
	if tok.typ != tokenPrincipal {
		return invalidTokenError(tok.typ, tokenPrincipal)
	}
	tok = lex.next()
	if tok.typ != tokenId {
		return invalidTokenError(tok.typ, tokenId)
	}
	cmd.Args[0] = tok.val
	tok = lex.next()
	if tok.typ != tokenPassword {
		return invalidTokenError(tok.typ, tokenPassword)
	}
	tok = lex.next()
	if tok.typ != tokenStr {
		return invalidTokenError(tok.typ, tokenStr)
	}
	cmd.Args[1] = tok.val
	tok = lex.next()
	if tok.typ != tokenDo {
		return invalidTokenError(tok.typ, tokenDo)
	}
	return cmd
}

func parseExit(lex *lexer) Cmd {
	return Cmd{Type: CmdExit}
}

func parseReturn(lex *lexer) Cmd {
	cmd := Cmd{CmdReturn, make([]string, 1)}
	val := parseExpr(lex)
	cmd.Args[0] = val
	return cmd
}

func parseCreatePrincipal(lex *lexer) Cmd {
	cmd := Cmd{CmdCreatePrincipal, make([]string, 2)}
	tok := lex.next()
	if tok.typ != tokenPrincipal {
		return invalidTokenError(tok.typ, tokenPrincipal)
	}
	tok = lex.next()
	if tok.typ != tokenId {
		return invalidTokenError(tok.typ, tokenId)
	}
	cmd.Args[0] = tok.val
	tok = lex.next()
	if tok.typ != tokenStr {
		return invalidTokenError(tok.typ, tokenStr)
	}
	cmd.Args[1] = tok.val
	return cmd
}

func parseChangePassword(lex *lexer) Cmd {
	cmd := Cmd{CmdChangePassword, make([]string, 2)}
	tok := lex.next()
	if tok.typ != tokenPassword {
		return invalidTokenError(tok.typ, tokenPassword)
	}
	tok = lex.next()
	if tok.typ != tokenId {
		return invalidTokenError(tok.typ, tokenId)
	}
	cmd.Args[0] = tok.val
	tok = lex.next()
	if tok.typ != tokenStr {
		return invalidTokenError(tok.typ, tokenStr)
	}
	cmd.Args[1] = tok.val
	return cmd
}

func parseSet(lex *lexer) Cmd {
	tok := lex.next()
	if tok.typ == tokenDelegation {
		return parseSetDelegation(lex)
	} else if tok.typ != tokenId {
		return invalidTokenError(tok.typ, tokenId)
	}
	cmd := Cmd{CmdSet, make([]string, 2)}
	cmd.Args[0] = tok.val
	tok = lex.next()
	if tok.typ != tokenEquals {
		return invalidTokenError(tok.typ, tokenEquals)
	}
	val := parseExpr(lex)
	cmd.Args[1] = val
	return cmd
}

func parseAppend(lex *lexer) Cmd {
	cmd := Cmd{CmdAppendTo, make([]string, 2)}
	tok := lex.next()
	if tok.typ != tokenTo {
		return invalidTokenError(tok.typ, tokenTo)
	}
	tok = lex.next()
	if tok.typ != tokenId {
		return invalidTokenError(tok.typ, tokenId)
	}
	cmd.Args[0] = tok.val
	tok = lex.next()
	if tok.typ != tokenWith {
		return invalidTokenError(tok.typ, tokenWith)
	}
	val := parseExpr(lex)
	cmd.Args[1] = val
	return cmd
}

func parseLocal(lex *lexer) Cmd {
	cmd := Cmd{CmdLocal, make([]string, 2)}
	tok := lex.next()
	if tok.typ != tokenId {
		return invalidTokenError(tok.typ, tokenId)
	}
	cmd.Args[0] = tok.val
	tok = lex.next()
	if tok.typ != tokenEquals {
		return invalidTokenError(tok.typ, tokenEquals)
	}
	val := parseExpr(lex)
	cmd.Args[1] = val
	return cmd
}

func parseForeach(lex *lexer) Cmd {
	cmd := Cmd{CmdForeach, make([]string, 3)}
	tok := lex.next()
	if tok.typ != tokenId {
		return invalidTokenError(tok.typ, tokenId)
	}
	cmd.Args[0] = tok.val
	tok = lex.next()
	if tok.typ != tokenIn {
		return invalidTokenError(tok.typ, tokenIn)
	}
	tok = lex.next()
	if tok.typ != tokenId {
		return invalidTokenError(tok.typ, tokenId)
	}
	cmd.Args[1] = tok.val
	tok = lex.next()
	if tok.typ != tokenReplacewith {
		return invalidTokenError(tok.typ, tokenReplacewith)
	}
	val := parseExpr(lex)
	cmd.Args[2] = val
	return cmd
}

func parseSetDelegation(lex *lexer) Cmd {
	args := parseDelegationArgs(lex)
	if args == nil {
		return Cmd{CmdError, []string{"Failed to parse delegation args"}}
	}
	return Cmd{CmdSetDelegation, args}
}

func parseDeleteDelegation(lex *lexer) Cmd {
	tok := lex.next()
	if tok.typ != tokenDelegation {
		return invalidTokenError(tok.typ, tokenDelegation)
	}
	args := parseDelegationArgs(lex)
	if args == nil {
		return Cmd{CmdError, []string{"Failed to parse delegation args"}}
	}
	return Cmd{CmdDeleteDelegation, args}
}

func parseDefaultDelegator(lex *lexer) Cmd {
	tok := lex.next()
	if tok.typ != tokenDelegator {
		return invalidTokenError(tok.typ, tokenDelegator)
	}
	tok = lex.next()
	if tok.typ != tokenEquals {
		return invalidTokenError(tok.typ, tokenEquals)
	}
	tok = lex.next()
	if tok.typ != tokenId {
		return invalidTokenError(tok.typ, tokenId)
	}
	cmd := Cmd{CmdDefaultDelegator, make([]string, 1)}
	cmd.Args[0] = tok.val
	return cmd
}

func parseExpr(lex *lexer) string {
	tok := lex.next()
	if tok.typ == tokenStr {
		return tok.val
	} else if tok.typ == tokenId {
		return tok.val
	}
	// TODO: supported only strings and identifiers for now
	return ""
}

// parse <tgt> q <right> -> p
func parseDelegationArgs(lex *lexer) []string {
	args := make([]string, 4)
	tok := lex.next()
	if tok.typ == tokenId {
		args[0] = tok.val
	} else if tok.typ == tokenAll {
		args[0] = "all"
	} else {
		return nil
	}
	tok = lex.next()
	if tok.typ != tokenId {
		return nil
	}
	args[1] = tok.val
	tok = lex.next()
	var right string
	switch tok.typ {
	case tokenRead:
		right = "read"
	case tokenWrite:
		right = "write"
	case tokenAppend:
		right = "append"
	case tokenDelegate:
		right = "delegate"
	default:
		return nil
	}
	args[2] = right
	tok = lex.next()
	if tok.typ != tokenArrow {
		return nil
	}
	tok = lex.next()
	if tok.typ != tokenId {
		return nil
	}
	args[3] = tok.val
	return args
}

func invalidTokenError(got, expected tokenType) Cmd {
	return Cmd{CmdError, []string{fmt.Sprintf("Invalid token error (expected=%v, got=%v)", expected, got)}}
}
