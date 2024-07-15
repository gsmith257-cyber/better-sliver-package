package use

/*
	Sliver Implant Framework
	Copyright (C) 2021  Bishop Fox

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
	"github.com/spf13/cobra"

	"github.com/gsmith257-cyber/better-sliver-package/client/command/beacons"
	"github.com/gsmith257-cyber/better-sliver-package/client/console"
)

// UseBeaconCmd - Change the active bacon
func UseBeaconCmd(cmd *cobra.Command, con *console.SliverClient, args []string) {
	bacon, err := beacons.SelectBeacon(con)
	if bacon != nil {
		con.ActiveTarget.Set(nil, bacon)
		con.PrintInfof("Active bacon %s (%s)\n", bacon.Name, bacon.ID)
	} else if err != nil {
		switch err {
		case beacons.ErrNoBeacons:
			con.PrintErrorf("No bacon available\n")
		case beacons.ErrNoSelection:
			con.PrintErrorf("No bacon selected\n")
		default:
			con.PrintErrorf("%s\n", err)
		}
	}
}
