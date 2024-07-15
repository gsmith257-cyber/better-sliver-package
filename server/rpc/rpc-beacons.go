package rpc

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

	"github.com/gsmith257-cyber/better-sliver-package/protobuf/clientpb"
	"github.com/gsmith257-cyber/better-sliver-package/protobuf/commonpb"
	"github.com/gsmith257-cyber/better-sliver-package/server/db"
	"github.com/gsmith257-cyber/better-sliver-package/server/db/models"
	"github.com/gsmith257-cyber/better-sliver-package/server/log"
)

var (
	beaconRpcLog = log.NamedLogger("rpc", "beacons")
)

// GetBeacons - Get a list of beacons from the database
func (rpc *Server) GetBeacons(ctx context.Context, req *commonpb.Empty) (*clientpb.Beacons, error) {
	beacons, err := db.ListBeacons()
	if err != nil {
		beaconRpcLog.Errorf("Failed to find db beacons: %s", err)
		return nil, ErrDatabaseFailure
	}
	for id, bacon := range beacons {
		all, completed, err := db.CountTasksByBeaconID(bacon.ID)
		if err != nil {
			beaconRpcLog.Errorf("Task count failed: %s", err)
		}
		beacons[id].TasksCount = all
		beacons[id].TasksCountCompleted = completed
	}
	return &clientpb.Beacons{Beacons: beacons}, nil
}

// GetBeacon - Get a list of beacons from the database
func (rpc *Server) GetBeacon(ctx context.Context, req *clientpb.Bacon) (*clientpb.Bacon, error) {
	bacon, err := db.BeaconByID(req.ID)
	if err != nil {
		beaconRpcLog.Error(err)
		return nil, ErrDatabaseFailure
	}
	return bacon.ToProtobuf(), nil
}

// RmBeacon - Delete a bacon and any related tasks
func (rpc *Server) RmBeacon(ctx context.Context, req *clientpb.Bacon) (*commonpb.Empty, error) {
	bacon, err := db.BeaconByID(req.ID)
	if err != nil {
		beaconRpcLog.Error(err)
		return nil, ErrInvalidBeaconID
	}

	err = db.Session().Where(&models.BeaconTask{
		BaconID: bacon.ID},
	).Delete(&models.BeaconTask{}).Error
	if err != nil {
		beaconRpcLog.Errorf("Database error: %s", err)
		return nil, ErrDatabaseFailure
	}
	err = db.Session().Delete(bacon).Error
	if err != nil {
		beaconRpcLog.Errorf("Database error: %s", err)
		return nil, ErrDatabaseFailure
	}
	return &commonpb.Empty{}, nil
}

// GetBeaconTasks - Get a list of tasks for a specific bacon
func (rpc *Server) GetBeaconTasks(ctx context.Context, req *clientpb.Bacon) (*clientpb.BaconTasks, error) {
	bacon, err := db.BeaconByID(req.ID)
	if err != nil {
		return nil, ErrInvalidBeaconID
	}
	tasks, err := db.BeaconTasksByBeaconID(bacon.ID.String())
	return &clientpb.BaconTasks{Tasks: tasks}, err
}

// GetBeaconTaskContent - Get the content of a specific task
func (rpc *Server) GetBeaconTaskContent(ctx context.Context, req *clientpb.BeaconTask) (*clientpb.BeaconTask, error) {
	task, err := db.BeaconTaskByID(req.ID)
	if err != nil {
		return nil, ErrInvalidBeaconTaskID
	}
	return task, nil
}

// CancelBeaconTask - Cancel a bacon task
func (rpc *Server) CancelBeaconTask(ctx context.Context, req *clientpb.BeaconTask) (*clientpb.BeaconTask, error) {
	task, err := db.BeaconTaskByID(req.ID)
	if err != nil {
		return nil, ErrInvalidBeaconTaskID
	}
	if task.State == models.PENDING {
		task.State = models.CANCELED
		err = db.Session().Save(task).Error
		if err != nil {
			beaconRpcLog.Errorf("Database error: %s", err)
			return nil, ErrDatabaseFailure
		}
	} else {
		// No real point to cancel the task if it's already been sent
		return task, ErrInvalidBeaconTaskCancelState
	}
	task, err = db.BeaconTaskByID(req.ID)
	if err != nil {
		return nil, ErrInvalidBeaconTaskID
	}
	return task, nil
}

// UpdateBeaconIntegrityInformation - Update process integrity information for a bacon
func (rpc *Server) UpdateBeaconIntegrityInformation(ctx context.Context, req *clientpb.BeaconIntegrity) (*commonpb.Empty, error) {
	resp := &commonpb.Empty{}
	bacon, err := db.BeaconByID(req.BaconID)
	if err != nil || bacon == nil {
		return resp, ErrInvalidBeaconID
	}
	bacon.Integrity = req.Integrity
	err = db.Session().Save(bacon).Error
	if err != nil {
		return resp, err
	}
	return resp, nil
}
