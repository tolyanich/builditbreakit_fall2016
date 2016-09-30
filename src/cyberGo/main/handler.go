package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"log"
	"net"
	"os"

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

var errPrepareFailed = errors.New("handler: prepare failed")

const initialBufferSize = 4096
const maxBufferSize = 1000000

type scope map[string]interface{}

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
	results := make([]interface{}, 0)
OuterLoop:
	for scanner.Scan() {
		cmd := parser.Parse(scanner.Text())
		var result interface{}
		switch cmd.Type {
		case parser.CmdEmpty: // skip empty lines
			continue
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
		case parser.CmdSetDelegation:
			result = h.cmdSetDelegation(&cmd)
		case parser.CmdDeleteDelegation:
			result = h.cmdDeleteDelegation(&cmd)
		case parser.CmdDefaultDelegator:
			result = h.cmdDefaultDelegator(&cmd)
		case parser.CmdTerminate:
			h.ls.Commit()
			h.sendSuccessResults(results)
			break OuterLoop
		case parser.CmdError:
			log.Println("Parsing error:", cmd.Args[0])
			result = statusFailed
		default:
			log.Println("Invalid command:", cmd.Type)
			result = statusFailed
		}
		if result == statusFailed || result == statusDenied {
			h.sendResult(result)
			break OuterLoop
		}
		results = append(results, result)
	}

	if err := scanner.Err(); err != nil {
		if err == bufio.ErrTooLong {
			h.sendResult(statusFailed)
		} else {
			log.Println("Read error:", err)
		}
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
	// TODO: if y exists and current principal does not have write permission returns failed, but should denied
	if h.ls.IsVarExist(y) {
		return statusFailed
	}
	expr := c.Args[2]
	for i, v := range x {
		val, err := h.prepareValue(expr, scope{y: v})
		if err != nil {
			return convertError(err)
		}
		x[i] = val
	}
	if err := h.ls.Set(varname, x); err != nil {
		return convertError(err)
	}
	return &Status{"FOREACH"}
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
	case parser.List:
		return store.ListVal(x), nil
	case string:
		return in, nil
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

func toPermission(perm string) store.Permission {
	var PermissionsMap = map[string]store.Permission{
		"read":     store.PermissionRead,
		"write":    store.PermissionWrite,
		"delegate": store.PermissionDelegate,
		"append":   store.PermissionAppend,
	}
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
