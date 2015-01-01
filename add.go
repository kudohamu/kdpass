package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

func add(conn *tls.Conn) {
	conn.Write([]byte(strconv.Itoa(ADD)))

	if checkAuthPass(conn) {
		fmt.Fprintf(os.Stderr, "password is not correct.\n")
		return
	}

	fmt.Printf("enter new password's label: ")
	var label string
	cmd := exec.Command("stty", "echo")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Run()
	_, err := fmt.Scanf("%s", &label)
	checkError(err, "failed to read label.")

	fmt.Printf("enter new password: ")
	cmd = exec.Command("stty", "-echo")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Run()
	var passwd string
	_, err = fmt.Scanf("%s", &passwd)
	fmt.Println("")
	checkError(err, "failed to read password.")

	fmt.Printf("retype new password: ")
	cmd.Run()
	var verify_passwd string
	_, err = fmt.Scanf("%s", &verify_passwd)
	fmt.Println("")
	checkError(err, "failed to read verify password.")

	if passwd != verify_passwd {
		fmt.Println("retyped password is not correct.")
		return
	}

	fmt.Printf("enter remarks(if any): ")
	cmd = exec.Command("stty", "echo")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Run()
	var remark string
	_, err = fmt.Scanf("%s", &remark)
	fmt.Println("")
	checkError(err, "failed to read remark.")

	conn.Write([]byte(label))
	conn.Write([]byte(passwd))
	conn.Write([]byte(remark))
}
