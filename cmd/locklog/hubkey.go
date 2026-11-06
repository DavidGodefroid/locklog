package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/DavidGodefroid/lockkit/hubclient"
)

// hubKeyCmd is `locklog hub-key --instance NAME`: the instance's public
// key, made on the first call in the console account's home (the home
// volume in the image), for `lox up` to pin at the hub. The private key
// never leaves that home.
func hubKeyCmd(args []string, stdout, stderr io.Writer) int {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(stderr, "locklog hub-key:", err)
		return 1
	}
	return hubKey(home, args, stdout, stderr)
}

func hubKey(home string, args []string, stdout, stderr io.Writer) int {
	if err := hubclient.HubKeyCommand(stdout, home, args); err != nil {
		fmt.Fprintln(stderr, "locklog hub-key:", err)
		if strings.HasPrefix(err.Error(), "usage:") {
			return 2
		}
		return 1
	}
	return 0
}
