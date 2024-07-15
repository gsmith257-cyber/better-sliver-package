package tasks

import (
	"context"

	"github.com/gsmith257-cyber/better-sliver-package/client/console"
	"github.com/gsmith257-cyber/better-sliver-package/protobuf/clientpb"
	"github.com/spf13/cobra"
)

// TasksCancelCmd - Cancel a bacon task before it's sent to the implant.
func TasksCancelCmd(cmd *cobra.Command, con *console.SliverClient, args []string) {
	bacon := con.ActiveTarget.GetBeaconInteractive()
	if bacon == nil {
		return
	}

	var idArg string
	if len(args) > 0 {
		idArg = args[0]
	}
	var task *clientpb.BeaconTask
	var err error
	if idArg == "" {
		BaconTasks, err := con.Rpc.GetBeaconTasks(context.Background(), &clientpb.Bacon{ID: bacon.ID})
		if err != nil {
			con.PrintErrorf("%s\n", err)
			return
		}
		tasks := []*clientpb.BeaconTask{}
		for _, task := range BaconTasks.Tasks {
			if task.State == "pending" {
				tasks = append(tasks, task)
			}
		}
		if len(tasks) == 0 {
			con.PrintErrorf("No pending tasks for bacon\n")
			return
		}

		task, err = SelectBeaconTask(tasks)
		if err != nil {
			con.PrintErrorf("%s\n", err)
			return
		}
		con.Printf(console.UpN+console.Clearln, 1)
	} else {
		task, err = con.Rpc.GetBeaconTaskContent(context.Background(), &clientpb.BeaconTask{ID: idArg})
		if err != nil {
			con.PrintErrorf("%s\n", err)
			return
		}
	}

	if task != nil {
		task, err := con.Rpc.CancelBeaconTask(context.Background(), task)
		if err != nil {
			con.PrintErrorf("%s\n", err)
			return
		}
		con.PrintInfof("Task %s canceled\n", task.ID)
	}
}
