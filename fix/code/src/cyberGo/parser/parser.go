package parser

import "fmt"

type CmdType int

const (
	CmdError CmdType = iota // error command
	CmdEmpty
	CmdAsPrincipal      // 'as principal' command
	CmdExit             // 'exit' command
	CmdReturn           // 'return' command
	CmdCreatePrincipal  // 'create principal' command
	CmdChangePassword   // 'change password' command
	CmdSet              // 'set' command
	CmdAppendTo         // 'append to' command
	CmdLocal            // 'local' command
	CmdForeach          // 'foreach' command
	CmdFiltereach       // 'filtereach' command
	CmdSetDelegation    // 'set delegation' command
	CmdDeleteDelegation // 'delete delegation' command
	CmdDefaultDelegator // 'default delegator' command
	CmdTerminate        // '***' command
)

var cmds = [...]string{
	"error",
	"empty",
	"asPrincipal",
	"exit",
	"return",
	"createPrincipal",
	"changePassword",
	"set",
	"appendTo",
	"local",
	"foreach",
	"filtereach",
	"setDelegation",
	"deleteDelegation",
	"defaultDelegator",
	"***",
}

func (t CmdType) String() string { return cmds[t] }

type Identifier string
type Record map[string]interface{}
type List []interface{}
type FieldVal struct{ Rec, Key string }
type Function struct {
	Name string
	Args ArgsType
}
type Let struct {
	Var   string
	Left  interface{}
	Right interface{}
}

type ArgsType []interface{}

type Cmd struct {
	Type CmdType
	Args ArgsType
}

func Parse(line string) Cmd {
	var cmd Cmd
	lex := newLexer(line)
	tok := lex.next()
	if tok.typ == tokenComment {
		tok = lex.next()
	}
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
	case tokenFiltereach:
		cmd = parseFiltereach(lex)
	case tokenDelete:
		cmd = parseDeleteDelegation(lex)
	case tokenDefault:
		cmd = parseDefaultDelegator(lex)
	case tokenEnd:
		cmd = Cmd{CmdEmpty, nil}
	case tokenTerminate:
		cmd = Cmd{CmdTerminate, nil}
	default:
		cmd = Cmd{CmdError, ArgsType{fmt.Sprintf("Unexpeted token: %v", tok.typ)}}
	}
	if cmd.Type != CmdError {
		tok = lex.next() // test end of command
		if (tok.typ != tokenEnd) && (tok.typ != tokenComment) {
			return invalidTokenError(tok.typ, tokenEnd)
		}
	}
	return cmd
}

// as principal admin password "admin" do
func parseAsPrincipal(lex *lexer) Cmd {
	cmd := Cmd{CmdAsPrincipal, make(ArgsType, 2)}
	tok := lex.next()
	if tok.typ != tokenPrincipal {
		return invalidTokenError(tok.typ, tokenPrincipal)
	}
	tok = lex.next()
	if tok.typ != tokenId {
		return invalidTokenError(tok.typ, tokenId)
	}
	cmd.Args[0] = Identifier(tok.val)
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
	cmd := Cmd{CmdReturn, make(ArgsType, 1)}
	arg, err := parseExpr(lex)
	if err != nil {
		return errorCmd(err)
	}
	cmd.Args[0] = arg
	return cmd
}

func parseCreatePrincipal(lex *lexer) Cmd {
	cmd := Cmd{CmdCreatePrincipal, make(ArgsType, 2)}
	tok := lex.next()
	if tok.typ != tokenPrincipal {
		return invalidTokenError(tok.typ, tokenPrincipal)
	}
	tok = lex.next()
	if tok.typ != tokenId {
		return invalidTokenError(tok.typ, tokenId)
	}
	cmd.Args[0] = Identifier(tok.val)
	tok = lex.next()
	if tok.typ != tokenStr {
		return invalidTokenError(tok.typ, tokenStr)
	}
	cmd.Args[1] = tok.val
	return cmd
}

func parseChangePassword(lex *lexer) Cmd {
	cmd := Cmd{CmdChangePassword, make(ArgsType, 2)}
	tok := lex.next()
	if tok.typ != tokenPassword {
		return invalidTokenError(tok.typ, tokenPassword)
	}
	tok = lex.next()
	if tok.typ != tokenId {
		return invalidTokenError(tok.typ, tokenId)
	}
	cmd.Args[0] = Identifier(tok.val)
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
	cmd := Cmd{CmdSet, make(ArgsType, 2)}
	cmd.Args[0] = Identifier(tok.val)
	tok = lex.next()
	if tok.typ != tokenEquals {
		return invalidTokenError(tok.typ, tokenEquals)
	}
	arg, err := parseExpr(lex)
	if err != nil {
		return errorCmd(err)
	}
	cmd.Args[1] = arg
	return cmd
}

func parseAppend(lex *lexer) Cmd {
	cmd := Cmd{CmdAppendTo, make(ArgsType, 2)}
	tok := lex.next()
	if tok.typ != tokenTo {
		return invalidTokenError(tok.typ, tokenTo)
	}
	tok = lex.next()
	if tok.typ != tokenId {
		return invalidTokenError(tok.typ, tokenId)
	}
	cmd.Args[0] = Identifier(tok.val)
	tok = lex.next()
	if tok.typ != tokenWith {
		return invalidTokenError(tok.typ, tokenWith)
	}
	arg, err := parseExpr(lex)
	if err != nil {
		return errorCmd(err)
	}
	cmd.Args[1] = arg
	return cmd
}

func parseLocal(lex *lexer) Cmd {
	cmd := Cmd{CmdLocal, make(ArgsType, 2)}
	tok := lex.next()
	if tok.typ != tokenId {
		return invalidTokenError(tok.typ, tokenId)
	}
	cmd.Args[0] = Identifier(tok.val)
	tok = lex.next()
	if tok.typ != tokenEquals {
		return invalidTokenError(tok.typ, tokenEquals)
	}
	arg, err := parseExpr(lex)
	if err != nil {
		return errorCmd(err)
	}
	cmd.Args[1] = arg
	return cmd
}

func parseForeach(lex *lexer) Cmd {
	cmd := Cmd{CmdForeach, make(ArgsType, 3)}
	tok := lex.next()
	if tok.typ != tokenId {
		return invalidTokenError(tok.typ, tokenId)
	}
	cmd.Args[0] = Identifier(tok.val)
	tok = lex.next()
	if tok.typ != tokenIn {
		return invalidTokenError(tok.typ, tokenIn)
	}
	tok = lex.next()
	if tok.typ != tokenId {
		return invalidTokenError(tok.typ, tokenId)
	}
	cmd.Args[1] = Identifier(tok.val)
	tok = lex.next()
	if tok.typ != tokenReplacewith {
		return invalidTokenError(tok.typ, tokenReplacewith)
	}
	arg, err := parseExpr(lex)
	if err != nil {
		return errorCmd(err)
	}
	cmd.Args[2] = arg
	return cmd
}

func parseFiltereach(lex *lexer) Cmd {
	cmd := Cmd{CmdFiltereach, make(ArgsType, 3)}
	tok := lex.next()
	if tok.typ != tokenId {
		return invalidTokenError(tok.typ, tokenId)
	}
	cmd.Args[0] = Identifier(tok.val)
	tok = lex.next()
	if tok.typ != tokenIn {
		return invalidTokenError(tok.typ, tokenIn)
	}
	tok = lex.next()
	if tok.typ != tokenId {
		return invalidTokenError(tok.typ, tokenId)
	}
	cmd.Args[1] = Identifier(tok.val)
	tok = lex.next()
	if tok.typ != tokenWith {
		return invalidTokenError(tok.typ, tokenWith)
	}
	arg, err := parseExpr(lex)
	if err != nil {
		return errorCmd(err)
	}
	cmd.Args[2] = arg
	return cmd
}

func parseSetDelegation(lex *lexer) Cmd {
	args := parseDelegationArgs(lex)
	if args == nil {
		return Cmd{CmdError, ArgsType{"Failed to parse delegation args"}}
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
		return Cmd{CmdError, ArgsType{"Failed to parse delegation args"}}
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
	cmd := Cmd{CmdDefaultDelegator, make(ArgsType, 1)}
	cmd.Args[0] = Identifier(tok.val)
	return cmd
}

func parseExpr(lex *lexer) (interface{}, error) {
	tok := lex.next()
	switch tok.typ {
	case tokenStr:
		return tok.val, nil
	case tokenId:
		tok2 := lex.next()
		if (tok2.typ == tokenEnd) || (tok2.typ == tokenComment) { // x
			return Identifier(tok.val), nil
		} else if tok2.typ == tokenDot { // x.y
			keyTok := lex.next()
			if keyTok.typ != tokenId {
				return nil, fmt.Errorf("Unexpected token '%v' for field value", keyTok.typ)
			}
			return FieldVal{tok.val, keyTok.val}, nil
		} else if tok2.typ == tokenLeftParen { // function call
			args, err := parseFunctionArgs(lex)
			if err != nil {
				return nil, err
			}
			return Function{tok.val, args}, nil
		}
	case tokenLeftSBracket: // []
		tok2 := lex.next()
		if tok2.typ != tokenRightSBracket {
			return nil, fmt.Errorf("Unexpected token '%v' for list type", tok2.typ)
		}
		return List{}, nil
	case tokenLeftCBracket: // {a = "s", b = v, c = x.y}
		return parseRecord(lex)
	case tokenLet: // let z = ... in ...
		varTok := lex.next()
		if varTok.typ != tokenId {
			return nil, fmt.Errorf("Unexpected token '%c' in 'let' expression", varTok.typ)
		}
		eqTok := lex.next()
		if eqTok.typ != tokenEquals {
			return nil, fmt.Errorf("Unexpected token '%c' in 'let' expression", eqTok.typ)
		}
		left, err := parseExpr(lex)
		if err != nil {
			return nil, err
		}
		inTok := lex.next()
		if inTok.typ != tokenIn {
			return nil, fmt.Errorf("Unexpected token '%c' in 'let' expression", inTok.typ)
		}
		right, err := parseExpr(lex)
		if err != nil {
			return nil, err
		}
		return Let{varTok.val, left, right}, nil
	}
	return nil, fmt.Errorf("Unexpected token '%v'", tok.typ)
}

// parse <tgt> q <right> -> p
func parseDelegationArgs(lex *lexer) ArgsType {
	args := make(ArgsType, 4)
	tok := lex.next()
	if tok.typ == tokenId {
		args[0] = Identifier(tok.val)
	} else if tok.typ == tokenAll {
		args[0] = Identifier("all")
	} else {
		return nil
	}
	tok = lex.next()
	if tok.typ != tokenId {
		return nil
	}
	args[1] = Identifier(tok.val)
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
	args[2] = Identifier(right)
	tok = lex.next()
	if tok.typ != tokenArrow {
		return nil
	}
	tok = lex.next()
	if tok.typ != tokenId {
		return nil
	}
	args[3] = Identifier(tok.val)
	return args
}

func parseRecord(lex *lexer) (Record, error) {
	rec := make(Record)
	for cur := lex.next(); cur.typ != tokenRightCBracket; {
		if cur.typ != tokenId {
			return nil, fmt.Errorf("Unexpected token '%v' for record key name", cur.typ)
		}
		key := cur.val
		if _, exists := rec[key]; exists {
			return nil, fmt.Errorf("Record key '%s' already exists", key)
		}
		cur = lex.next()
		if cur.typ != tokenEquals {
			return nil, fmt.Errorf("Unexpected token '%v' for record equals sign", cur.typ)
		}
		cur = lex.next()
		if cur.typ == tokenStr { // a = "s"
			rec[key] = cur.val
			cur = lex.next()
		} else if cur.typ == tokenId {
			val := cur.val
			cur = lex.next()
			if cur.typ == tokenDot {
				cur = lex.next()
				if cur.typ == tokenId {
					rec[key] = FieldVal{val, cur.val} // c = x.y
					cur = lex.next()
				}
			} else {
				rec[key] = Identifier(val) // b = v
			}
		} else {
			return nil, fmt.Errorf("Unexpected token '%v' for record key value", cur.typ)
		}
		if cur.typ == tokenComma {
			cur = lex.next()
		}
	}
	return rec, nil
}

func parseFunctionArgs(lex *lexer) (ArgsType, error) {
	args := make(ArgsType, 0, 2)
	for cur := lex.next(); cur.typ != tokenRightParen; {
		switch cur.typ {
		case tokenStr:
			args = append(args, cur.val)
			cur = lex.next()
		case tokenId:
			val := cur.val
			cur = lex.next()
			if cur.typ == tokenDot {
				cur = lex.next()
				if cur.typ == tokenId {
					args = append(args, FieldVal{val, cur.val}) // x.y
					cur = lex.next()
				}
			} else {
				args = append(args, Identifier(val)) // v
			}
		default:
			return nil, fmt.Errorf("Unexpected token '%v' for function argument", cur.typ)
		}
		if cur.typ == tokenComma {
			cur = lex.next()
		}
	}
	return args, nil
}

func errorCmd(err error) Cmd {
	return Cmd{CmdError, ArgsType{err}}
}

func invalidTokenError(got, expected tokenType) Cmd {
	return errorCmd(fmt.Errorf("Invalid token error (expected=%v, got=%v)", expected, got))
}
