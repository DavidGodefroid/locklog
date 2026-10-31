// Package product declares locklog's names for lockkit.
package product

import "github.com/DavidGodefroid/lockkit/kit"

// P is locklog as a lockkit product: its binary, directories, console
// account, clients group, keychain service and environment prefix.
var P = kit.Product{
	Name:            "locklog",
	Tagline:         "Your AI reads the logs, not the people in them.",
	Account:         "locklog",
	ClientsGroup:    "locklog-clients",
	KeychainService: "locklog",
	EnvPrefix:       "LOCKLOG_",
}

// Account ids, fixed across the image, the launcher and the hub: the
// clients group, the console account and the image's agent account.
const (
	ClientsGID = 10050
	ConsoleUID = 10051
	AgentUID   = 10052
)
