package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

func main_handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "{\"status\":\"DENIED\"}")
}

var (
	PORT       int    = 0       //port number
	ADMIN_PASS string = "admin" //default admin pass
	KEYWORDS          = []string{"all", "append", "as", "change", "create", "default", "delegate",
		"delegation", "delegator", "delete", "do", "exit", "foreach", "in",
		"local", "password", "principal", "read", "replacewith", "return",
		"set", "to", "write", "split", "concat", "tolower", "notequal", "equal",
		"filtereach", "with", "let"}
)

//Check if val is from KEYWORDS array which is restricted by task
func IsKeyword(val string) bool {
	for _, el := range KEYWORDS {
		if el == val {
			return (true)
		}
	}
	return (false)
}

// Signal handler to catch SIGTERM signal and exit with 0 code as task require
func signal_handler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Block until a signal is received.
	s := <-c
	fmt.Println("Got Signal: ", s)
	os.Exit(0)
}

//   Command line arguments
// Any command-line input that is not valid according to the rules below should cause the program to exit with
// a return code of 255. When the server cleanly terminates, it should exit with return code 0.
// Command line arguments cannot exceed 4096 characters each
// The port argument must be a number between 1,024 and 65,535 (inclusive).
// It should be provided in decimal without any leading 0's. Thus 1042 is a valid input number but the octal 052
// or hexadecimal 0x2a are not.
// The password argument, if present, must be a legal string s, per the rules for strings given above,
// but without the surrounding quotation marks.

func check_args(params []string) {

	if len(params) < 1 || len(params) > 2 {
		fmt.Println("Wrong args")
		os.Exit(255)
	}

	if len(params[0]) > 4096 || params[0][0] == '0' {
		fmt.Println("Wrong port number format")
		os.Exit(255)
	}
	PORT, _ = strconv.Atoi(params[0])

	//check port number range
	if PORT < 1025 || PORT > 65535 {
		fmt.Println("Wrong port number range")
		os.Exit(255)
	}

	if len(params) == 2 {
		if len(params[1]) > 4096 {
			fmt.Println("Wrong args[1] len")
			os.Exit(255)
		}
		ADMIN_PASS = params[1]
	}
}

func main() {
	flag.Parse()
	params := flag.Args()

	check_args(params)

	//Should be run in separate thread
	go signal_handler()

	//setup http handler and bind to port
	http.HandleFunc("/", main_handler)
	http.ListenAndServe(":"+strconv.Itoa(PORT), nil)
	//if port already binded return 63 as required by task
	os.Exit(63)
}
