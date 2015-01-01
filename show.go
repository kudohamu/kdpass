package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"strconv"
)

func show(conn *tls.Conn, label string) {
	if len(label) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: kdpass show [label]\n")
		return
	}
	conn.Write([]byte(strconv.Itoa(SHOW)))

	if checkAuthPass(conn) {
		fmt.Fprintf(os.Stderr, "password is not correct.\n")
		return
	}

	conn.Write([]byte(label))

	passwd := make([]byte, 255)
	passLen, err := conn.Read(passwd)
	checkError(err, "failed to read password.")

	remark := make([]byte, 1023)
	remarkLen, err := conn.Read(remark)
	checkError(err, "failed to read remark.")

	fmt.Printf("label: %s\n", label)
	fmt.Printf("password: %s\n", string(passwd[:passLen]))
	fmt.Printf("remark: %s\n", string(remark[:remarkLen]))
}
