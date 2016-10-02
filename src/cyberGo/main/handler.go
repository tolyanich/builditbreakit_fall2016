package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"log"
	"net"
	"os"
	"reflect"
	"strings"
	"time"

	"cyberGo/parser"
	"cyberGo/store"
)

type Status struct {
	Status string `json:"status"`
}

type ReturningStatus struct {
	Status string      `json:"status"`
	Output interface{} `json:"output"`
}

var statusFailed = &Status{"FAILED"}
var statusDenied = &Status{"DENIED"}
var statusTimeout = &Status{"TIMEOUT"}

var errPrepareFailed = errors.New("handler: prepare failed")

const initialBufferSize = 4096
const maxBufferSize = 1000000
const maxProgramSize = 1000000
const readTimeoutSeconds = 30

type scope map[string]interface{}
type function func(args parser.ArgsType) (interface{}, error)

type Handler struct {
	conn   net.Conn
	global *store.Store // should have global store before authorization
	ls     *store.LocalStore
}

func NewHandler(conn net.Conn, s *store.Store) *Handler {
	return &Handler{conn, s, nil}
}

func (h *Handler) Execute() {
	defer h.conn.Close()
	h.conn.SetReadDeadline(time.Now().Add(readTimeoutSeconds * time.Second))

	scanner := bufio.NewScanner(h.conn)
	buf := make([]byte, initialBufferSize)
	scanner.Buffer(buf, maxBufferSize)
	if !scanner.Scan() { // failed to read authorization string
		return
	}
	principal := parser.Parse(scanner.Text())
	if principal.Type != parser.CmdAsPrincipal {
		h.sendResult(statusFailed)
		log.Println("Unexpected command:", principal.Type)
		return
	}

	var err error
	h.ls, err = h.global.AsPrincipal(asString(principal.Args[0]), asString(principal.Args[1]))
	if err != nil {
		h.sendResult(convertError(err))
		return
	}

	var cmds []parser.Cmd
	totalLen := len(scanner.Text()) + 1 // with '\n' char
	failed := false
	shouldTerminate := false
	for scanner.Scan() {
		text := scanner.Text()
		totalLen += len(text) + 1
		if totalLen > maxProgramSize {
			failed = true
			break
		}
		cmd := parser.Parse(text)
		if shouldTerminate && cmd.Type != parser.CmdTerminate {
			failed = true
			break
		}
		if cmd.Type == parser.CmdEmpty { // skip empty commands
			continue
		} else if cmd.Type == parser.CmdReturn || cmd.Type == parser.CmdExit {
			shouldTerminate = true
		} else if cmd.Type == parser.CmdError {
			log.Println("Parsing error:", cmd.Args[0])
			failed = true
		}
		cmds = append(cmds, cmd)
		if cmd.Type == parser.CmdTerminate {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		if err == bufio.ErrTooLong {
			h.sendResult(statusFailed)
		} else if err, ok := err.(net.Error); ok && err.Timeout() {
			h.sendResult(statusTimeout)
		} else {
			log.Println("Read error:", err)
		}
		return
	}
	if failed {
		h.sendResult(statusFailed)
		return
	}

	results := make([]interface{}, 0)
ParseLoop:
	for _, cmd := range cmds {
		var result interface{}
		switch cmd.Type {
		case parser.CmdExit:
			result = h.cmdExit(&cmd)
		case parser.CmdReturn:
			result = h.cmdReturn(&cmd)
		case parser.CmdCreatePrincipal:
			result = h.cmdCreatePrincipal(&cmd)
		case parser.CmdChangePassword:
			result = h.cmdChangePassword(&cmd)
		case parser.CmdSet:
			result = h.cmdSet(&cmd)
		case parser.CmdAppendTo:
			result = h.cmdAppendTo(&cmd)
		case parser.CmdLocal:
			result = h.cmdLocal(&cmd)
		case parser.CmdForeach:
			result = h.cmdForeach(&cmd)
		case parser.CmdFiltereach:
			result = h.cmdFiltereach(&cmd)
		case parser.CmdSetDelegation:
			result = h.cmdSetDelegation(&cmd)
		case parser.CmdDeleteDelegation:
			result = h.cmdDeleteDelegation(&cmd)
		case parser.CmdDefaultDelegator:
			result = h.cmdDefaultDelegator(&cmd)
		case parser.CmdTerminate:
			h.ls.Commit()
			h.sendSuccessResults(results)
			break ParseLoop
		default:
			log.Println("Invalid command:", cmd.Type)
			result = statusFailed
		}
		if result == statusFailed || result == statusDenied {
			h.sendResult(result)
			break ParseLoop
		}
		results = append(results, result)
	}
}

func (h *Handler) sendSuccessResults(results []interface{}) {
	for _, res := range results {
		h.sendResult(res)
	}
}

func (h *Handler) sendResult(res interface{}) {
	enc := json.NewEncoder(h.conn)
	if err := enc.Encode(res); err != nil {
		log.Println("Failed to send encoded result:", err)
	}
}

func (h *Handler) cmdExit(c *parser.Cmd) *Status {
	if !h.ls.IsAdmin() {
		return statusDenied
	}
	h.sendResult(&Status{"EXITING"})
	os.Exit(0)
	return nil
}

func (h *Handler) cmdReturn(c *parser.Cmd) interface{} {
	output, err := h.prepareValue(c.Args[0], nil)
	if err != nil {
		return convertError(err)
	}
	if lst, ok := output.(store.ListVal); ok {
		output = flattenList(lst)
	}
	return &ReturningStatus{"RETURNING", output}
}

func (h *Handler) cmdCreatePrincipal(c *parser.Cmd) *Status {
	if err := h.ls.CreatePrincipal(asString(c.Args[0]), asString(c.Args[1])); err != nil {
		return convertError(err)
	}
	return &Status{"CREATE_PRINCIPAL"}
}

func (h *Handler) cmdChangePassword(c *parser.Cmd) *Status {
	if err := h.ls.ChangePassword(asString(c.Args[0]), asString(c.Args[1])); err != nil {
		return convertError(err)
	}
	return &Status{"CHANGE_PASSWORD"}
}

func (h *Handler) cmdSet(c *parser.Cmd) *Status {
	val, err := h.prepareValue(c.Args[1], nil)
	if err != nil {
		return convertError(err)
	}
	if err := h.ls.Set(asString(c.Args[0]), val); err != nil {
		return convertError(err)
	}
	return &Status{"SET"}
}

//append to x with value
func (h *Handler) cmdAppendTo(c *parser.Cmd) *Status {
	value, err := h.prepareValue(c.Args[1], nil)
	if err != nil {
		return convertError(err)
	}
	if err := h.ls.AppendTo(asString(c.Args[0]), value); err != nil {
		return convertError(err)
	}
	return &Status{"APPEND"}
}

func (h *Handler) cmdLocal(c *parser.Cmd) *Status {
	val, err := h.prepareValue(c.Args[1], nil)
	if err != nil {
		return convertError(err)
	}
	if err := h.ls.SetLocal(asString(c.Args[0]), val); err != nil {
		return convertError(err)
	}
	return &Status{"LOCAL"}
}

func (h *Handler) cmdForeach(c *parser.Cmd) *Status {
	varname := asString(c.Args[1])
	list, err := h.ls.Get(varname)
	if err != nil {
		return convertError(err)
	}
	x, ok := list.(store.ListVal)
	if !ok {
		return statusFailed
	}
	y := asString(c.Args[0])
	if h.ls.IsVarExist(y) {
		return statusFailed
	}
	expr := c.Args[2]
	newx := flattenList(x)
	for i, v := range newx {
		val, err := h.prepareValue(expr, scope{y: v})
		if err != nil {
			return convertError(err)
		}
		newx[i] = val
	}
	if err := h.ls.Set(varname, newx); err != nil {
		return convertError(err)
	}
	return &Status{"FOREACH"}
}

func (h *Handler) cmdFiltereach(c *parser.Cmd) *Status {
	varname := asString(c.Args[1])
	list, err := h.ls.Get(varname)
	if err != nil {
		return convertError(err)
	}
	x, ok := list.(store.ListVal)
	if !ok {
		return statusFailed
	}
	y := asString(c.Args[0])
	if h.ls.IsVarExist(y) {
		return statusFailed
	}
	expr := c.Args[2]
	x = flattenList(x)
	var res store.ListVal
	for _, v := range x {
		val, err := h.prepareValue(expr, scope{y: v})
		if err != nil {
			return convertError(err)
		}
		if s, ok := val.(string); ok && s == "" {
			res = append(res, v)
		}
	}
	if err := h.ls.Set(varname, res); err != nil {
		return convertError(err)
	}
	return &Status{"FILTEREACH"}
}

func (h *Handler) cmdSetDelegation(c *parser.Cmd) *Status {
	if err := h.ls.SetDelegation(asString(c.Args[0]), asString(c.Args[1]),
		toPermission(asString(c.Args[2])), asString(c.Args[3])); err != nil {
		return convertError(err)
	}
	return &Status{"SET_DELEGATION"}
}

func (h *Handler) cmdDeleteDelegation(c *parser.Cmd) *Status {
	if err := h.ls.DeleteDelegation(asString(c.Args[0]), asString(c.Args[1]),
		toPermission(asString(c.Args[2])), asString(c.Args[3])); err != nil {
		return convertError(err)
	}
	return &Status{"DELETE_DELEGATION"}
}

func (h *Handler) cmdDefaultDelegator(c *parser.Cmd) *Status {
	if err := h.ls.SetDefaultDelegator(asString(c.Args[0])); err != nil {
		return convertError(err)
	}
	return &Status{"DEFAULT_DELEGATOR"}
}

func (h *Handler) prepareValue(in interface{}, sc scope) (interface{}, error) {
	switch x := in.(type) {
	case string:
		return in, nil
	case parser.Identifier:
		if sc != nil {
			if val, ok := sc[string(x)]; ok {
				return val, nil
			}
		}
		val, err := h.ls.Get(string(x))
		if err != nil {
			return nil, err
		}
		return val, nil
	case parser.List:
		return store.ListVal(x), nil
	case parser.FieldVal:
		if sc != nil {
			if val, ok := sc[x.Rec]; ok {
				if rec, ok := val.(store.RecordVal); ok {
					if res, found := rec[x.Key]; found {
						return res, nil
					}
				}
			}
		}
		val, err := h.ls.Get(x.Rec)
		if err != nil {
			return nil, err
		}
		if rec, ok := val.(store.RecordVal); ok {
			if res, found := rec[x.Key]; found {
				return res, nil
			}
		}
	case parser.Record:
		rec := make(store.RecordVal, len(x))
		for k, v := range x {
			val, err := h.prepareValue(v, sc)
			if err != nil {
				return nil, err
			}
			if s, ok := val.(string); ok {
				rec[k] = s
			} else {
				return nil, errPrepareFailed
			}
		}
		return rec, nil
	case parser.Function:
		if fn, ok := functionsMap[x.Name]; ok {
			args := make(parser.ArgsType, len(x.Args))
			for i, v := range x.Args {
				arg, err := h.prepareValue(v, sc)
				if err != nil {
					return nil, err
				}
				args[i] = arg
			}
			return fn(args)
		}
	case parser.Let:
		if sc != nil {
			if _, ok := sc[x.Var]; ok { // scope variable already exists
				return nil, errPrepareFailed
			}
		}
		if h.ls.IsVarExist(x.Var) {
			return nil, errPrepareFailed
		}
		left, err := h.prepareValue(x.Left, sc)
		if err != nil {
			return nil, err
		}
		if sc == nil {
			sc = make(scope, 1)
		}
		sc[x.Var] = left
		res, err := h.prepareValue(x.Right, sc)
		delete(sc, x.Var) // delete scope variable
		if err != nil {
			return nil, err
		}
		return res, nil
	}
	return nil, errPrepareFailed
}

func convertError(err error) *Status {
	if err == store.ErrFailed {
		return statusFailed
	} else if err == store.ErrDenied {
		return statusDenied
	} else if err != nil {
		log.Println("Unknown error:", err)
		return statusFailed
	}
	return nil
}

var functionsMap = map[string]function{
	"split":    splitFunc,
	"concat":   concatFunc,
	"tolower":  tolowerFunc,
	"equal":    equalFunc,
	"notequal": notequalFunc,
}

var PermissionsMap = map[string]store.Permission{
	"read":     store.PermissionRead,
	"write":    store.PermissionWrite,
	"delegate": store.PermissionDelegate,
	"append":   store.PermissionAppend,
}

func toPermission(perm string) store.Permission {
	return PermissionsMap[perm]
}

func asString(val interface{}) string {
	switch v := val.(type) {
	case string:
		return v
	case parser.Identifier:
		return string(v)
	}
	return ""
}

func flattenList(lst store.ListVal) store.ListVal {
	out := make(store.ListVal, len(lst))
	out, _ = flatten(out, lst, 0)
	return out
}

func flatten(out, in store.ListVal, pos int) (store.ListVal, int) {
	n := 0
	for _, val := range in {
		if lst, ok := val.(store.ListVal); ok {
			var c int
			out, c = flatten(out, lst, pos+n)
			n += c
		} else {
			needLen := pos + n + 1
			if cap(out) < needLen {
				newOut := make(store.ListVal, needLen, cap(out)*2)
				// copy old values
				for i, v := range out {
					newOut[i] = v
				}
				out = newOut
			} else {
				// sufficient capacity
				out = out[0:needLen]
			}
			out[pos+n] = val
			n += 1
		}
	}
	return out, n
}

// string functions

// split(s1,s2)
// returns a record { fst = s11, snd = s12 } where s11 and s12 are the result of splitting string s1.
// String s11 is the first N characters of s1 where N is the length of s2,
// and string s12 is the remainder of s1.
// If N is greater than the length of s1 then fst = s1 and snd = "".
// Fails if s1 and/or s2 are not strings.
func splitFunc(args parser.ArgsType) (interface{}, error) {
	if len(args) != 2 {
		return nil, errPrepareFailed
	}
	s1, ok1 := args[0].(string)
	s2, ok2 := args[1].(string)
	if !ok1 || !ok2 {
		return nil, errPrepareFailed
	}
	l := len(s2)
	if len(s1) >= l {
		return store.RecordVal{"fst": s1[0:l], "snd": s1[l:]}, nil
	} else {
		return store.RecordVal{"fst": s1, "snd": ""}, nil
	}
}

// concat(s1,s2)
// returns a new string that is the concatenation of s1 and s2.
// The concatenated string is truncated to 65535 characters (if it would exceed that length).
// Fails if s1 or s2 is not a string.
func concatFunc(args parser.ArgsType) (interface{}, error) {
	if len(args) != 2 {
		return nil, errPrepareFailed
	}
	s1, ok1 := args[0].(string)
	s2, ok2 := args[1].(string)
	if !ok1 || !ok2 {
		return nil, errPrepareFailed
	}
	res := s1 + s2
	if len(res) > 65535 {
		res = res[:65535]
	}
	return res, nil
}

// tolower(s)
// returns a new string that converts all uppercase characters in s to lowercase.
// Fails if s is not a string.
func tolowerFunc(args parser.ArgsType) (interface{}, error) {
	if len(args) != 1 {
		return nil, errPrepareFailed
	}
	s, ok := args[0].(string)
	if !ok {
		return nil, errPrepareFailed
	}
	return strings.ToLower(s), nil
}

// equal(<value>,<value>)
// takes two arguments and returns "" if they are equal, and "0" if they are not.
// (as with string functions, arguments are evaluated left to right)
// Arguments are permitted to be strings or records; fails otherwise.
func equalFunc(args parser.ArgsType) (interface{}, error) {
	if len(args) != 2 {
		return nil, errPrepareFailed
	}

	// compare strings
	s1, ok1 := args[0].(string)
	s2, ok2 := args[1].(string)
	if ok1 && ok2 {
		if s1 == s2 {
			return "", nil
		} else {
			return "0", nil
		}
	}

	// compare records
	rec1, ok1 := args[0].(store.RecordVal)
	rec2, ok2 := args[1].(store.RecordVal)
	if ok1 && ok2 {
		if reflect.DeepEqual(rec1, rec2) {
			return "", nil
		} else {
			return "0", nil
		}
	}

	// invalid type
	return nil, errPrepareFailed
}

// notequal(<value>,<value>)
// takes two arguments and returns "" if they are not equal, and "0" if they are.
// (as with string functions, arguments are evaluated left to right)
// Arguments are permitted to be strings or records; fails otherwise.
func notequalFunc(args parser.ArgsType) (interface{}, error) {
	res, err := equalFunc(args)
	if err != nil {
		return nil, err
	}
	if s, ok := res.(string); ok && s == "" {
		return "0", nil
	} else {
		return "", nil
	}
}
