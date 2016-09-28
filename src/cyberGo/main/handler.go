package main

import (
	"bufio"
	"encoding/json"
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
			h.sendResult(statusFailed)
			break OuterLoop
		default:
			log.Println("Invalid command:", cmd.Type)
			h.sendResult(statusFailed)
			break OuterLoop
		}
		if result == statusFailed || result == statusDenied {
			h.sendResult(result)
			break OuterLoop
		}
		results = append(results, result)
	}

	if err := scanner.Err(); err != nil {
		log.Println("Read error:", err)
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
	var output interface{}
	switch x := c.Args[0].(type) {
	case parser.Identifier:
		var err error
		output, err = h.ls.Get(string(x))
		if err != nil {
			return convertError(err)
		}
	case parser.FieldVal:
		val, err := h.ls.Get(x.Rec)
		if err != nil {
			return convertError(err)
		}
		if rec, ok := val.(store.RecordVal); ok {
			if res, found := rec[x.Key]; found {
				output = res
			} else {
				return statusFailed
			}
		} else {
			return statusFailed
		}
	case parser.Record:
	case parser.List:
	case string:
		output = x
	default:
		return statusFailed
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
	if err := h.ls.Set(asString(c.Args[0]), c.Args[1]); err != nil {
		return convertError(err)
	}
	return &Status{"SET"}
}

func (h *Handler) cmdAppendTo(c *parser.Cmd) *Status {
	// TODO: not implemented
	return &Status{"APPEND"}
}

func (h *Handler) cmdLocal(c *parser.Cmd) *Status {
	if err := h.ls.SetLocal(asString(c.Args[0]), c.Args[1]); err != nil {
		return convertError(err)
	}
	return &Status{"LOCAL"}
}

func (h *Handler) cmdForeach(c *parser.Cmd) *Status {
	// TODO: not implemented
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
