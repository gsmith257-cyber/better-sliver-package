package jobs

/*
	Sliver Implant Framework
	Copyright (C) 2019  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"context"

	"github.com/gsmith257-cyber/better-sliver-package/client/console"
	"github.com/gsmith257-cyber/better-sliver-package/protobuf/clientpb"
	"github.com/spf13/cobra"
)

// WGListenerCmd - Start a WireGuard listener.
func WGListenerCmd(cmd *cobra.Command, con *console.SliverClient, args []string) {
	lport, _ := cmd.Flags().GetUint32("lport")
	nport, _ := cmd.Flags().GetUint32("nport")
	keyExchangePort, _ := cmd.Flags().GetUint32("key-port")

	con.PrintInfof("Starting Wireguard listener ...\n")
	wg, err := con.Rpc.StartWGListener(context.Background(), &clientpb.WGListenerReq{
		Port:    lport,
		NPort:   nport,
		KeyPort: keyExchangePort,
	})
	if err != nil {
		con.PrintErrorf("%s\n", err)
	} else {
		con.PrintInfof("Successfully started job #%d\n", wg.JobID)
	}
}
