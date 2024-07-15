package privilege

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
	"context"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	"github.com/gsmith257-cyber/better-sliver-package/client/console"
	"github.com/gsmith257-cyber/better-sliver-package/protobuf/clientpb"
	"github.com/gsmith257-cyber/better-sliver-package/protobuf/sliverpb"
)

// GetPrivsCmd - Get the current process privileges (Windows only)
func GetPrivsCmd(cmd *cobra.Command, con *console.SliverClient, args []string) {
	session, bacon := con.ActiveTarget.GetInteractive()
	if session == nil && bacon == nil {
		return
	}
	targetOS := getOS(session, bacon)
	if targetOS != "windows" {
		con.PrintErrorf("Command only supported on Windows.\n")
		return
	}

	privs, err := con.Rpc.GetPrivs(context.Background(), &sliverpb.GetPrivsReq{
		Request: con.ActiveTarget.Request(cmd),
	})
	if err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}
	pid := getPID(session, bacon)
	if privs.Response != nil && privs.Response.Async {
		con.AddBaconCallback(privs.Response.TaskID, func(task *clientpb.BaconTask) {
			err = proto.Unmarshal(task.Response, privs)
			if err != nil {
				con.PrintErrorf("Failed to decode response %s\n", err)
				return
			}
			PrintGetPrivs(privs, pid, con)
			err = updateBaconIntegrityInformation(con, bacon.ID, privs.ProcessIntegrity)
			if err != nil {
				con.PrintWarnf("Could not save integrity information for the bacon: %s\n", err)
				return
			}
		})
		con.PrintAsyncResponse(privs.Response)
	} else {
		PrintGetPrivs(privs, pid, con)
	}
}

// PrintGetPrivs - Print the results of the get privs command
func PrintGetPrivs(privs *sliverpb.GetPrivs, pid int32, con *console.SliverClient) {
	// Response is the Envelope (see RPC API), Err is part of it.
	if privs.Response != nil && privs.Response.Err != "" {
		con.PrintErrorf("\nNOTE: Information may be incomplete due to an error:\n")
		con.PrintErrorf("%s\n", privs.Response.Err)
	}
	if privs.PrivInfo == nil {
		return
	}

	var processName string = "Current Process"
	if privs.ProcessName != "" {
		processName = privs.ProcessName
	}

	// To make things look pretty, figure out the longest name and description
	// for column width
	var nameColumnWidth int = 0
	var descriptionColumnWidth int = 0
	var introWidth int = 34 + len(processName) + len(strconv.Itoa(int(pid)))

	for _, entry := range privs.PrivInfo {
		if len(entry.Name) > nameColumnWidth {
			nameColumnWidth = len(entry.Name)
		}
		if len(entry.Description) > descriptionColumnWidth {
			descriptionColumnWidth = len(entry.Description)
		}
	}

	// Give one more space
	nameColumnWidth += 1
	descriptionColumnWidth += 1

	con.Printf("\nPrivilege Information for %s (PID: %d)\n", processName, pid)
	con.Println(strings.Repeat("-", introWidth))
	con.Printf("\nProcess Integrity Level: %s\n\n", privs.ProcessIntegrity)
	con.Printf("%-*s\t%-*s\t%s\n", nameColumnWidth, "Name", descriptionColumnWidth, "Description", "Attributes")
	con.Printf("%-*s\t%-*s\t%s\n", nameColumnWidth, "====", descriptionColumnWidth, "===========", "==========")
	for _, entry := range privs.PrivInfo {
		con.Printf("%-*s\t%-*s\t", nameColumnWidth, entry.Name, descriptionColumnWidth, entry.Description)
		if entry.Enabled {
			con.Printf("Enabled")
		} else {
			con.Printf("Disabled")
		}
		if entry.EnabledByDefault {
			con.Printf(", Enabled by Default")
		}
		if entry.Removed {
			con.Printf(", Removed")
		}
		if entry.UsedForAccess {
			con.Printf(", Used for Access")
		}
		con.Printf("\n")
	}
}

func getOS(session *clientpb.Session, bacon *clientpb.Bacon) string {
	if session != nil {
		return session.OS
	}
	if bacon != nil {
		return bacon.OS
	}
	panic("no session or bacon")
}

func getPID(session *clientpb.Session, bacon *clientpb.Bacon) int32 {
	if session != nil {
		return session.PID
	}
	if bacon != nil {
		return bacon.PID
	}
	panic("no session or bacon")
}

func updateBaconIntegrityInformation(con *console.SliverClient, baconID string, integrity string) error {
	_, err := con.Rpc.UpdateBaconIntegrityInformation(context.Background(), &clientpb.BaconIntegrity{BaconID: baconID,
		Integrity: integrity})

	return err
}
