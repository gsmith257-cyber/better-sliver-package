package generate

import (
	"fmt"
	"os"
	"time"

	"github.com/gsmith257-cyber/better-sliver-package/client/console"
	"github.com/gsmith257-cyber/better-sliver-package/protobuf/clientpb"
	"github.com/spf13/cobra"
)

var (
	minBaconInterval         = 5 * time.Second
	ErrBaconIntervalTooShort = fmt.Errorf("bacon interval must be %v or greater", minBaconInterval)
)

// GenerateBaconCmd - The main command used to generate implant binaries
func GenerateBaconCmd(cmd *cobra.Command, con *console.SliverClient, args []string) {
	name, config := parseCompileFlags(cmd, con)
	if config == nil {
		return
	}
	config.IsBacon = true
	err := parseBaconFlags(cmd, config)
	if err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}
	save, _ := cmd.Flags().GetString("save")
	if save == "" {
		save, _ = os.Getwd()
	}
	if external, _ := cmd.Flags().GetBool("external-builder"); !external {
		compile(config, save, con)
	} else {
		externalBuild(name, config, save, con)
	}
}

func parseBaconFlags(cmd *cobra.Command, config *clientpb.ImplantConfig) error {
	days, _ := cmd.Flags().GetInt64("days")
	hours, _ := cmd.Flags().GetInt64("hours")
	minutes, _ := cmd.Flags().GetInt64("minutes")
	interval := time.Duration(days) * time.Hour * 24
	interval += time.Duration(hours) * time.Hour
	interval += time.Duration(minutes) * time.Minute

	/*
		If seconds has not been specified but any of the other time units have, then do not add
		the default 60 seconds to the interval.

		If seconds have been specified, then add them regardless.
	*/
	if (!cmd.Flags().Changed("seconds") && interval.Seconds() == 0) || (cmd.Flags().Changed("seconds")) {
		// if (ctx.Flags["seconds"].IsDefault && interval.Seconds() == 0) || (!ctx.Flags["seconds"].IsDefault) {
		seconds, _ := cmd.Flags().GetInt64("seconds")
		interval += time.Duration(seconds) * time.Second
	}

	if interval < minBaconInterval {
		return ErrBaconIntervalTooShort
	}

	BaconJitter, _ := cmd.Flags().GetInt64("jitter")
	config.BaconInterval = int64(interval)
	config.BaconJitter = int64(time.Duration(BaconJitter) * time.Second)
	return nil
}
