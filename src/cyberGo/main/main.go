package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

func mainHandler(conn net.Conn) {
	// Close the connection when you're done with it.
	defer conn.Close()
	// Make a buffer to hold incoming data.
	// Any program that fails to parse (i.e., is not correct according to the grammar) results in failure.
	// All programs consist of at most 1,000,000 ASCII (8-byte) characters (not a wide character set, like unicode);
	// non-compliant programs result in failure.
	reqBuf := make([]byte, 1000000)
	reqLen, err := conn.Read(reqBuf)
	fmt.Println("read: ", reqLen)
	if err != nil {
		//TODO: this situation isn't described. so just close connection and return
		return
	}
	conn.Write([]byte("{\"status\":\"DENIED\"}"))
}

var (
	portNumber    int    = 0       //port number
	adminPassword string = "admin" //default admin pass
)

// Signal handler to catch SIGTERM signal and exit with 0 code as task require
func signalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Block until a signal is received.
	s := <-c
	fmt.Println("Got Signal: ", s)
	os.Exit(0)
}

// Command line arguments
// Any command-line input that is not valid according to the rules below should cause the program to exit with
// a return code of 255. When the server cleanly terminates, it should exit with return code 0.
// Command line arguments cannot exceed 4096 characters each
// The port argument must be a number between 1,024 and 65,535 (inclusive).
// It should be provided in decimal without any leading 0's. Thus 1042 is a valid input number but the octal 052
// or hexadecimal 0x2a are not.
// The password argument, if present, must be a legal string s, per the rules for strings given above,
// but without the surrounding quotation marks.

func checkArgs(params []string) {

	if len(params) < 1 || len(params) > 2 {
		fmt.Println("Wrong args")
		os.Exit(255)
	}

	if len(params[0]) > 4096 || params[0][0] == '0' {
		fmt.Println("Wrong port number format")
		os.Exit(255)
	}
	portNumber, _ = strconv.Atoi(params[0])

	//check port number range
	if portNumber < 1025 || portNumber > 65535 {
		fmt.Println("Wrong port number range")
		os.Exit(255)
	}

	if len(params) == 2 {
		if len(params[1]) > 4096 {
			fmt.Println("Wrong args[1] len")
			os.Exit(255)
		}
		//TODO may be should strict check for match the regular expression "[A-Za-z0-9_ ,;\.?!-]*"
		adminPassword = params[1]
	}
}

func main() {
	params := os.Args[1:]

	checkArgs(params)

	//Should be run in separate thread
	go signalHandler()

	// Listen for incoming connections.
	l, err := net.Listen("tcp", ":"+strconv.Itoa(portNumber))
	if err != nil {
		//if port already binded return 63 as required by task
		os.Exit(63)
	}
	defer l.Close()
	for {
		// Listen for an incoming connection.
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(255)
		}
		mainHandler(conn)
	}
	os.Exit(0)
}
