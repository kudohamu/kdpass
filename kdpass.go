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

func showPasswd(conn *tls.Conn, label string) {
	if len(label) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: kdpass show [label]\n")
	} else {
		fmt.Printf("enter your password: ")
		cmd := exec.Command("stty", "-echo")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		cmd.Run()
		var passwd string
		_, err := fmt.Scanf("%s", &passwd)
		checkError(err, "failed to read password.")
		fmt.Println("\n" + passwd)
		conn.Write([]byte("Hello"))
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
				showPasswd(conn, c.Args().First())
			},
		},
	}

	app.Run(os.Args)
}
