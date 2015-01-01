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
	LIST
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

func checkAuthPass(conn *tls.Conn) bool {
	fmt.Printf("enter your password: ")
	cmd := exec.Command("stty", "-echo")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Run()
	var authPass string
	_, err := fmt.Scanf("%s", &authPass)
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
				show(conn, c.Args().First())
			},
		},
		{
			Name:  "add",
			Usage: "add new password",
			Action: func(c *cli.Context) {
				add(conn)
			},
		},
		{
			Name:  "list",
			Usage: "show all labels",
			Action: func(c *cli.Context) {
				list(conn)
			},
		},
	}

	app.Run(os.Args)
}
