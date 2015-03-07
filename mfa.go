package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"time"
)

func checkMFA(conn net.Conn) bool {
	isCheck := make([]byte, 16)
	checkLen, err := conn.Read(isCheck)
	if err != nil {
		return false
	}

	if string(isCheck[:checkLen]) == "false" {
		return true
	}

	timeLimit := time.Now().Add(3 * 60 * time.Second)
	fmt.Printf("enter multi factor auth code: ")
	cmd := exec.Command("stty", "echo")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Run()
	var userMFA string
	_, err = fmt.Scanf("%s", &userMFA)
	if err != nil {
		return false
	}

	conn.Write([]byte(userMFA))

	result := make([]byte, 32)
	resultLen, err := conn.Read(result)
	if err != nil {
		if 0 <= time.Now().Sub(timeLimit) {
			checkError(err, "multi factor auth reception is timeout.")
		}
		return false
	}

	if string(result[:resultLen]) == "success" {
		return true
	} else {
		fmt.Printf("failed! multi factor auth code is not a valid.")
		return false
	}
}
