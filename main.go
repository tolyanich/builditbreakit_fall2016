package main

import (
  "flag"
  "fmt"
  "net/http"
  "os"
  "os/signal"
  "syscall"
  "strconv"
)

func main_handler(w http.ResponseWriter, r *http.Request) {
  fmt.Fprintf(w, "{\"status\":\"DENIED\"}")
}

var (
  PORT       int    = 0 //port number
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

func main() {
  flag.Parse()
  params := flag.Args()

  if len(params) < 1 || len(params) > 2 {
    fmt.Println("Wrong args")
    os.Exit(255)
  }
  PORT, _ := strconv.Atoi(params[0])

  //check port number range
  if PORT < 1025 || PORT > 65535 {
    fmt.Println("Wrong port number")
    os.Exit(255)
  }

  if len(params) == 2 {
    ADMIN_PASS = params[1]
  }

  //Run signal_handler in parallel
  go signal_handler()

  //setup http handler and bind to port
  http.HandleFunc("/", main_handler)
  http.ListenAndServe(":"+strconv.Itoa(PORT), nil)
  //if port already binded return 63 as required by task
  os.Exit(63)
}
