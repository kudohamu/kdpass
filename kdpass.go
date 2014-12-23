package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
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

func main() {
	label := ""
	if len(os.Args) > 1 {
		label = os.Args[1]
	} else {
		os.Exit(1)
	}

	fmt.Println(label)

	config, err := readConf("kdpass.conf")
	checkError(err, "failed to read config file.")

	conn, err := connectTLS(config)
	checkError(err, "failed to connect server")

	conn.Write([]byte(label))
}
