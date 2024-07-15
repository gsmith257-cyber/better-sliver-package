package reconfig

/*
	Sliver Implant Framework
	Copyright (C) 2022  Bishop Fox

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

	"github.com/gsmith257-cyber/better-sliver/client/console"
	"github.com/gsmith257-cyber/better-sliver/protobuf/clientpb"
	"github.com/gsmith257-cyber/better-sliver/util"
	"github.com/spf13/cobra"
)

// RecnameCmd - Reconfigure metadata about a sessions.
func RenameCmd(cmd *cobra.Command, con *console.SliverClient, args []string) {
	session, beacon := con.ActiveTarget.GetInteractive()
	if session == nil && beacon == nil {
		return
	}

	// Option to change the agent name
	name, _ := cmd.Flags().GetString("name")
	if err := util.AllowedName(name); err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}

	var baconID string
	var sessionID string
	if beacon != nil {
		baconID = beacon.ID
	} else if session != nil {
		sessionID = session.ID
	}
	_, err := con.Rpc.Rename(context.Background(), &clientpb.RenameReq{
		SessionID: sessionID,
		BaconID:  baconID,
		Name:      name,
	})
	if err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}

	con.PrintInfof("Renamed implant to %s\n", name)
	con.ActiveTarget.Set(nil, nil)
}