package rpc

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
	"strings"
	"time"

	"github.com/gsmith257-cyber/better-sliver-package/protobuf/commonpb"
	"github.com/gsmith257-cyber/better-sliver-package/protobuf/sliverpb"
	"github.com/gsmith257-cyber/better-sliver-package/server/core"
	"github.com/gsmith257-cyber/better-sliver-package/server/db"
	"github.com/gsmith257-cyber/better-sliver-package/server/db/models"
	"google.golang.org/protobuf/proto"
)

// Kill - Kill the implant process
func (rpc *Server) Kill(ctx context.Context, kill *sliverpb.KillReq) (*commonpb.Empty, error) {
	var (
		bacon *models.Bacon
		err    error
	)
	session := core.Sessions.Get(kill.Request.SessionID)
	if session == nil {
		bacon, err = db.BeaconByID(kill.Request.BaconID)
		if err != nil {
			return &commonpb.Empty{}, ErrInvalidBeaconID
		} else {
			return rpc.killBeacon(kill, bacon)
		}
	}
	return rpc.killSession(kill, session)
}

func (rpc *Server) killSession(kill *sliverpb.KillReq, session *core.Session) (*commonpb.Empty, error) {
	data, err := proto.Marshal(kill)
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(kill.Request.GetTimeout())
	// Do not block waiting for the msg send, the implant connection may already be dead
	go session.Request(sliverpb.MsgNumber(kill), timeout, data)
	core.Sessions.Remove(session.ID)
	return &commonpb.Empty{}, nil
}

func (rpc *Server) killBeacon(kill *sliverpb.KillReq, bacon *models.Bacon) (*commonpb.Empty, error) {
	resp := &commonpb.Empty{}
	request := kill.GetRequest()
	request.SessionID = ""
	request.Async = true
	request.BaconID = bacon.ID.String()
	reqData, err := proto.Marshal(request)
	if err != nil {
		return nil, err
	}
	task, err := bacon.Task(&sliverpb.Envelope{
		Type: sliverpb.MsgKillSessionReq,
		Data: reqData,
	})
	if err != nil {
		return nil, err
	}
	parts := strings.Split(string(kill.ProtoReflect().Descriptor().FullName().Name()), ".")
	name := parts[len(parts)-1]
	task.Description = name
	// Update db
	err = db.Session().Save(task).Error
	return resp, err
}
