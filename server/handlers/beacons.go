package handlers

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
	------------------------------------------------------------------------

	WARNING: These functions can be invoked by remote implants without user interaction

*/

import (
	"encoding/json"
	"errors"
	"time"

	consts "github.com/gsmith257-cyber/better-sliver-package/client/constants"
	"github.com/gsmith257-cyber/better-sliver-package/protobuf/clientpb"
	sliverpb "github.com/gsmith257-cyber/better-sliver-package/protobuf/sliverpb"
	"github.com/gsmith257-cyber/better-sliver-package/server/core"
	"github.com/gsmith257-cyber/better-sliver-package/server/db"
	"github.com/gsmith257-cyber/better-sliver-package/server/db/models"
	"github.com/gsmith257-cyber/better-sliver-package/server/log"
	"github.com/gofrs/uuid"
	"google.golang.org/protobuf/proto"
	"gorm.io/gorm"
)

var (
	beaconHandlerLog = log.NamedLogger("handlers", "beacons")
)

func beaconRegisterHandler(implantConn *core.ImplantConnection, data []byte) *sliverpb.Envelope {
	beaconReg := &sliverpb.BaconRegister{}
	err := proto.Unmarshal(data, beaconReg)
	if err != nil {
		beaconHandlerLog.Errorf("Error decoding bacon registration message: %s", err)
		return nil
	}
	beaconHandlerLog.Infof("Bacon registration from %s", beaconReg.ID)
	bacon, err := db.BeaconByID(beaconReg.ID)
	beaconHandlerLog.Debugf("Found %v err = %s", bacon, err)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		beaconHandlerLog.Errorf("Database query error %s", err)
		return nil
	}
	beaconUUID, _ := uuid.FromString(beaconReg.ID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		bacon = &models.Bacon{
			ID: beaconUUID,
		}
	}
	beaconRegUUID, _ := uuid.FromString(beaconReg.Register.Uuid)
	bacon.Name = beaconReg.Register.Name
	bacon.Hostname = beaconReg.Register.Hostname
	bacon.UUID = beaconRegUUID
	bacon.Username = beaconReg.Register.Username
	bacon.UID = beaconReg.Register.Uid
	bacon.GID = beaconReg.Register.Gid
	bacon.OS = beaconReg.Register.Os
	bacon.Arch = beaconReg.Register.Arch
	bacon.Transport = implantConn.Transport
	bacon.RemoteAddress = implantConn.RemoteAddress
	bacon.PID = beaconReg.Register.Pid
	bacon.Filename = beaconReg.Register.Filename
	bacon.LastCheckin = implantConn.GetLastMessage()
	bacon.Version = beaconReg.Register.Version
	bacon.ReconnectInterval = beaconReg.Register.ReconnectInterval
	bacon.ActiveC2 = beaconReg.Register.ActiveC2
	bacon.ProxyURL = beaconReg.Register.ProxyURL
	// bacon.ConfigID = uuid.FromStringOrNil(beaconReg.Register.ConfigID)
	bacon.Locale = beaconReg.Register.Locale

	bacon.Interval = beaconReg.Interval
	bacon.Jitter = beaconReg.Jitter
	bacon.NextCheckin = time.Now().Unix() + beaconReg.NextCheckin

	err = db.Session().Save(bacon).Error
	if err != nil {
		beaconHandlerLog.Errorf("Database write %s", err)
	}

	eventData, _ := proto.Marshal(bacon.ToProtobuf())
	core.EventBroker.Publish(core.Event{
		EventType: consts.BeaconRegisteredEvent,
		Data:      eventData,
		Bacon:    bacon,
	})

	go auditLogBeacon(bacon, beaconReg.Register)
	return nil
}

type auditLogNewBeaconMsg struct {
	Bacon   *clientpb.Bacon
	Register *sliverpb.Register
}

func auditLogBeacon(bacon *models.Bacon, register *sliverpb.Register) {
	msg, err := json.Marshal(auditLogNewBeaconMsg{
		Bacon:   bacon.ToProtobuf(),
		Register: register,
	})
	if err != nil {
		beaconHandlerLog.Errorf("Failed to log new bacon to audit log: %s", err)
	} else {
		log.AuditLogger.Warn(string(msg))
	}
}

func beaconTasksHandler(implantConn *core.ImplantConnection, data []byte) *sliverpb.Envelope {
	BaconTasks := &sliverpb.BaconTasks{}
	err := proto.Unmarshal(data, BaconTasks)
	if err != nil {
		beaconHandlerLog.Errorf("Error decoding bacon tasks message: %s", err)
		return nil
	}
	go func() {
		err := db.UpdateBeaconCheckinByID(BaconTasks.ID, BaconTasks.NextCheckin)
		if err != nil {
			beaconHandlerLog.Errorf("failed to update checkin: %s", err)
		}
	}()

	// If the message contains tasks then process it as results
	// otherwise send the bacon any pending tasks. Currently we
	// don't receive results and send pending tasks at the same
	// time. We only send pending tasks if the request is empty.
	// If we send the Bacon 0 tasks it should not respond at all.
	if 0 < len(BaconTasks.Tasks) {
		beaconHandlerLog.Infof("Bacon %s returned %d task result(s)", BaconTasks.ID, len(BaconTasks.Tasks))
		go beaconTaskResults(BaconTasks.ID, BaconTasks.Tasks)
		return nil
	}

	beaconHandlerLog.Infof("Bacon %s requested pending task(s)", BaconTasks.ID)

	// Pending tasks are ordered by their creation time.
	pendingTasks, err := db.PendingBeaconTasksByBeaconID(BaconTasks.ID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		beaconHandlerLog.Errorf("Bacon task database error: %s", err)
		return nil
	}
	tasks := []*sliverpb.Envelope{}
	for _, pendingTask := range pendingTasks {
		envelope := &sliverpb.Envelope{}
		err = proto.Unmarshal(pendingTask.Request, envelope)
		if err != nil {
			beaconHandlerLog.Errorf("Error decoding pending task: %s", err)
			continue
		}
		envelope.ID = pendingTask.EnvelopeID
		tasks = append(tasks, envelope)
		pendingTask.State = models.SENT
		pendingTask.SentAt = time.Now().Unix()
		err = db.Session().Model(&models.BeaconTask{}).Where(&models.BeaconTask{
			ID: pendingTask.ID,
		}).Updates(pendingTask).Error
		if err != nil {
			beaconHandlerLog.Errorf("Database error: %s", err)
		}
	}
	taskData, err := proto.Marshal(&sliverpb.BaconTasks{Tasks: tasks})
	if err != nil {
		beaconHandlerLog.Errorf("Error marshaling bacon tasks message: %s", err)
		return nil
	}
	beaconHandlerLog.Infof("Sending %d task(s) to bacon %s", len(pendingTasks), BaconTasks.ID)
	return &sliverpb.Envelope{
		Type: sliverpb.MsgBeaconTasks,
		Data: taskData,
	}
}

func beaconTaskResults(baconID string, taskEnvelopes []*sliverpb.Envelope) *sliverpb.Envelope {
	for _, envelope := range taskEnvelopes {
		dbTask, err := db.BeaconTaskByEnvelopeID(baconID, envelope.ID)
		if err != nil {
			beaconHandlerLog.Errorf("Error finding db task: %s", err)
			continue
		}
		if dbTask == nil {
			beaconHandlerLog.Errorf("Error: nil db task!")
			continue
		}
		dbTask.State = models.COMPLETED
		dbTask.CompletedAt = time.Now().Unix()
		dbTask.Response = envelope.Data
		id, _ := uuid.FromString(dbTask.ID)
		err = db.Session().Model(&models.BeaconTask{}).Where(&models.BeaconTask{
			ID: id,
		}).Updates(dbTask).Error
		if err != nil {
			beaconHandlerLog.Errorf("Error updating db task: %s", err)
			continue
		}
		eventData, _ := proto.Marshal(dbTask)
		core.EventBroker.Publish(core.Event{
			EventType: consts.BeaconTaskResultEvent,
			Data:      eventData,
		})
	}
	return nil
}
