package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/codegangsta/cli"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
)

type server struct {
	IP        string
	Port      string
	RootCAUrl string
	Name      string
}

type kdpassConf struct {
	Server server
}

const (
	SHOW = iota
	ADD
)

func checkError(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal: "+msg+" %s\n", err)
		os.Exit(1)
	}
}

func readConf(url string) (config kdpassConf, err error) {
	confFile, err := os.Open(url)
	if err != nil {
		return
	}
	defer confFile.Close()
	decoder := json.NewDecoder(confFile)
	err = decoder.Decode(&config)
	return config, err
}

func connectTLS(config kdpassConf) (conn *tls.Conn, err error) {
	CAPool := x509.NewCertPool()
	serverCert, err := ioutil.ReadFile(config.Server.RootCAUrl)
	if err != nil {
		return
	}
	CAPool.AppendCertsFromPEM(serverCert)
	tlsConf := tls.Config{RootCAs: CAPool, ServerName: config.Server.Name}
	conn, err = tls.Dial("tcp", config.Server.IP+":"+config.Server.Port, &tlsConf)
	return
}

func askAuthPass() (passwd string, err error) {
	fmt.Printf("enter your password: ")
	cmd := exec.Command("stty", "-echo")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Run()
	_, err = fmt.Scanf("%s", &passwd)
	return
}

func checkAuthPass(conn *tls.Conn) bool {
	authPass, err := askAuthPass()
	fmt.Println()
	if err != nil {
		return false
	}
	conn.Write([]byte(authPass))
	isAuth := make([]byte, 127)
	isAuthLen, err := conn.Read(isAuth)
	if string(isAuth[:isAuthLen]) != "success" {
		return true
	} else {
		return false
	}
}

func showPasswd(conn *tls.Conn, label string) {
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

func addPasswd(conn *tls.Conn) {
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

func main() {
	config, err := readConf("kdpass.conf")
	checkError(err, "failed to read config file.")

	conn, err := connectTLS(config)
	checkError(err, "failed to connect server.")

	app := cli.NewApp()
	app.Name = "kdpass"

	app.Commands = []cli.Command{
		{
			Name:  "show",
			Usage: "show specified label's password",
			Action: func(c *cli.Context) {
				showPasswd(conn, c.Args().First())
			},
		},
		{
			Name:  "add",
			Usage: "add new password",
			Action: func(c *cli.Context) {
				addPasswd(conn)
			},
		},
	}

	app.Run(os.Args)
}
