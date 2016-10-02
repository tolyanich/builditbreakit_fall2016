package parser

import (
	"fmt"
	"strings"
)

type tokenType int

type token struct {
	typ tokenType
	val string
}

const (
	tokenError         tokenType = iota // error occurred; val is text of error
	tokenEnd                            // end of input reached
	tokenAs                             // 'as' keyword
	tokenPrincipal                      // 'principal' keyword
	tokenPassword                       // 'password' keyword
	tokenDo                             // 'do' keyword
	tokenExit                           // 'exit' keyword
	tokenReturn                         // 'return' keyword
	tokenTerminate                      // '***' keyword
	tokenStr                            // string constant
	tokenId                             // identifier
	tokenLeftSBracket                   // '[' keyword
	tokenRightSBracket                  // '[' keyword
	tokenLeftCBracket                   // '{' keyword
	tokenRightCBracket                  // '}' keyword
	tokenLeftParen                      // '(' keyword
	tokenRightParen                     // ')' keyword
	tokenEquals                         // '=' keyword
	tokenDot                            // '.' keyword
	tokenComma                          // ',' keyword
	tokenArrow                          // '->' token
	tokenCreate                         // 'create' keyword
	tokenChange                         // 'change' keyword
	tokenSet                            // 'set' keyword
	tokenAppend                         // 'append' keyword
	tokenTo                             // 'to' keyword
	tokenWith                           // 'with' keyword
	tokenLocal                          // 'local' keyword
	tokenForeach                        // 'foreach' keyword
	tokenIn                             // 'in' keyword
	tokenReplacewith                    // 'replacewith' keyword
	tokenDelegation                     // 'delegation' keyword
	tokenDelete                         // 'delete' keyword
	tokenDefault                        // 'default' keyword
	tokenDelegator                      // 'delegator' keyword
	tokenAll                            // 'all' keyword
	tokenRead                           // 'read' keyword
	tokenWrite                          // 'write' keyword
	tokenDelegate                       // 'delegate' keyword
	tokenFiltereach                     // 'filtereach' keyword
	tokenLet                            // 'let' keyword
	tokenComment                        // comment
)

var tokens = [...]string{
	"error",
	"end",
	"as",
	"principal",
	"password",
	"do",
	"exit",
	"return",
	"terminate",
	"str",
	"id",
	"leftSBracket",
	"rightSBracket",
	"leftCBracket",
	"rightCBracket",
	"tokenLeftParen",
	"tokenRightParen",
	"equals",
	"dot",
	"comma",
	"arrow",
	"create",
	"change",
	"set",
	"append",
	"to",
	"with",
	"local",
	"foreach",
	"in",
	"replacewith",
	"delegation",
	"delete",
	"default",
	"delegator",
	"all",
	"read",
	"write",
	"delegate",
	"filtereach",
	"let",
	"comment",
}

func (t tokenType) String() string { return tokens[t] }

var keywordsMap = map[string]tokenType{
	"as":          tokenAs,
	"principal":   tokenPrincipal,
	"password":    tokenPassword,
	"do":          tokenDo,
	"exit":        tokenExit,
	"return":      tokenReturn,
	"create":      tokenCreate,
	"change":      tokenChange,
	"set":         tokenSet,
	"append":      tokenAppend,
	"to":          tokenTo,
	"with":        tokenWith,
	"local":       tokenLocal,
	"foreach":     tokenForeach,
	"in":          tokenIn,
	"replacewith": tokenReplacewith,
	"delegation":  tokenDelegation,
	"delete":      tokenDelete,
	"default":     tokenDefault,
	"delegator":   tokenDelegator,
	"all":         tokenAll,
	"read":        tokenRead,
	"write":       tokenWrite,
	"delegate":    tokenDelegate,
	"filtereach":  tokenFiltereach,
	"let":         tokenLet,
}

const eof = 0
const maxString = 65535
const maxIdentifier = 255

type lexer struct {
	input string // the string being scanned
	pos   int    // current position in the input
	start int    // start position of this item
}

func newLexer(input string) *lexer {
	return &lexer{input, 0, 0}
}

func (l *lexer) next() token {
	for {
		c := l.nextc()
		switch {
		case c == eof:
			return token{tokenEnd, ""}
		case c == ' ': // skip to the next char
		case c == '"':
			if s, ok := l.readString(); ok && len(s) <= maxString {
				return token{tokenStr, s}
			} else {
				l.seteof()
				return token{tokenError, "Invalid string"}
			}
		case isLetter(c):
			l.backup()
			id := l.readIdentifier()
			if len(id) > maxIdentifier {
				l.seteof()
				return token{tokenError, "Invalid identifier"}
			}
			if kw, ok := keywordsMap[id]; ok { // check keywords
				return token{kw, ""}
			}
			return token{tokenId, id}
		case c == '[':
			return token{tokenLeftSBracket, ""}
		case c == ']':
			return token{tokenRightSBracket, ""}
		case c == '{':
			return token{tokenLeftCBracket, ""}
		case c == '}':
			return token{tokenRightCBracket, ""}
		case c == '=':
			return token{tokenEquals, ""}
		case c == '(':
			return token{tokenLeftParen, ""}
		case c == ')':
			return token{tokenRightParen, ""}
		case c == '.':
			return token{tokenDot, ""}
		case c == ',':
			return token{tokenComma, ""}
		case c == '-': // ->
			if c2 := l.nextc(); c2 == '>' {
				return token{tokenArrow, ""}
			} else {
				l.seteof()
				return token{tokenError, fmt.Sprintf("Invalid character for arrow token: '%c'", c2)}
			}
		case c == '/': // comment
			if c2 := l.nextc(); c2 == '/' {
				if l.checkCommentValid() {
					return token{tokenComment, l.tail()}
				} else {
					l.seteof()
					return token{tokenError, "Invalid comment"}
				}
			} else {
				l.seteof()
				return token{tokenError, fmt.Sprintf("Invalid character for comment token: '%c'", c2)}
			}
		case c == '*' && l.accepts("**"): // '***'
			return token{tokenTerminate, ""}
		default:
			l.seteof()
			return token{tokenError, fmt.Sprintf("Unexpected token: '%c'", c)}
		}
	}
}

// gets next character from the input
// since the string is ascii, just use the byte return type
func (l *lexer) nextc() byte {
	if l.eof() {
		return eof
	}
	c := l.input[l.pos]
	l.pos++
	return c
}

// backup steps back one char. Can only be called once per call of next.
func (l *lexer) backup() {
	l.pos--
}

// checks end of input
func (l *lexer) eof() bool {
	return l.pos >= len(l.input)
}

// checks if input starts with given string and accepts it if so
// returns true if string accepted
func (l *lexer) accepts(valid string) bool {
	if !l.eof() && strings.HasPrefix(l.input[l.pos:], valid) {
		l.pos += len(valid)
		return true
	}
	return false
}

// reads input up to the first occurrence of '"' character
func (l *lexer) readString() (string, bool) {
	if l.eof() {
		return "", false
	}
	if i := strings.IndexByte(l.input[l.pos:], '"'); i >= 0 {
		s := l.input[l.pos : l.pos+i]
		l.pos += i + 1
		return s, true
	}
	return "", false
}

// reads identifier from input
func (l *lexer) readIdentifier() string {
	if l.eof() {
		return ""
	}
	i := l.pos
	for i < len(l.input) && isAlphaNumeric(l.input[i]) {
		i++
	}
	s := l.input[l.pos:i]
	l.pos = i
	return s
}

// reads to the end of input and trim spaces
func (l *lexer) tail() string {
	if l.eof() {
		return ""
	}
	s := strings.TrimSpace(l.input[l.pos:])
	l.seteof()
	return s
}

// checks if comment valid for this input
// comments allowed only for non-empty strings
// or empty line without any whitespaces
func (l *lexer) checkCommentValid() bool {
	if l.pos < 2 || l.input[l.pos-1] != '/' || l.input[l.pos-2] != '/' {
		return false
	}
	if l.pos == 2 { // line comment
		return true
	}
	for i := l.pos - 3; i >= 0; i-- {
		if l.input[i] != ' ' { // allows any non-space character
			return true
		}
	}
	return false
}

// sets end of input (for error purposes)
func (l *lexer) seteof() {
	l.pos = len(l.input)
}

// checks symbol is letter
func isLetter(ch byte) bool {
	return ('a' <= ch && ch <= 'z') || ('A' <= ch && ch <= 'Z')
}

// checks symbol is alphanumeric or _
func isAlphaNumeric(ch byte) bool {
	return isLetter(ch) || ('0' <= ch && ch <= '9') || (ch == '_')
}
