package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

func list(conn *tls.Conn) {
	conn.Write([]byte(strconv.Itoa(LIST)))

	if checkAuthPass(conn) {
		fmt.Fprintf(os.Stderr, "password is not correct.\n")
		return
	}

	if checkMFA(conn) {
		var list bytes.Buffer
		io.Copy(&list, conn)

		labels := strings.Split(string(list.Bytes()), "\n")
		for _, label := range labels {
			fmt.Println(label)
		}
	}
}
