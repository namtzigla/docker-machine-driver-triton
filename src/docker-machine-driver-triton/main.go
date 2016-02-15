package main

import (
	"github.com/docker/machine/libmachine/drivers/plugin"
	"github.com/docker/machine/libmachine/drivers/plugin/localbinary"

	"fmt"
	"os"
	"triton"
)

func main() {
	if os.Getenv(localbinary.PluginEnvKey) != localbinary.PluginEnvVal {
		fmt.Printf("VERSION: %s, COMMIT: %s\n", Version, GitCommit)
	}
	plugin.RegisterDriver(new(triton.Driver))
}
