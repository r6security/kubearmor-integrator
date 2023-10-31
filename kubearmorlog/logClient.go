/*
 * Copyright (C) 2023 R6 Security, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the Server Side Public License, version 1,
 * as published by MongoDB, Inc.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * Server Side Public License for more details.
 *
 * You should have received a copy of the Server Side Public License
 * along with this program. If not, see
 * <http://www.mongodb.com/licensing/server-side-public-license>.
 */

package kubearmorlog

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"sync"

	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/grpc"
)

// EventInfo Event data signalled on EventChan
type EventInfo struct {
	Data []byte // json marshalled byte data for alert/log
	Type string // "Alert"/"Log"
}

// Feeder Structure
type Feeder struct {
	// flag
	Running bool

	// connection
	conn *grpc.ClientConn

	// client
	client pb.LogServiceClient

	// alerts
	alertStream pb.LogService_WatchAlertsClient

	// wait group
	WgClient sync.WaitGroup
}

// NewClient Function
func NewClient(server string) (*Feeder, error) {
	fd := &Feeder{}

	fd.Running = true

	conn, err := grpc.Dial(server, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	fd.conn = conn

	fd.client = pb.NewLogServiceClient(fd.conn)

	alertStream, err := fd.client.WatchAlerts(context.Background(), &pb.RequestMessage{Filter: "policy"})
	if err != nil {
		return nil, err
	}
	fd.alertStream = alertStream

	fd.WgClient = sync.WaitGroup{}

	return fd, nil
}

// DoHealthCheck Function
func (fd *Feeder) DoHealthCheck() bool {
	// #nosec
	randNum := rand.Int31()

	// send a nonce
	nonce := pb.NonceMessage{Nonce: randNum}
	res, err := fd.client.HealthCheck(context.Background(), &nonce)
	if err != nil {
		return false
	}

	// check nonce
	if randNum != res.Retval {
		return false
	}

	return true
}

// WatchAlerts Function
func (fd *Feeder) WatchAlerts(o Options) error {
	fd.WgClient.Add(1)
	defer fd.WgClient.Done()

	for fd.Running {
		res, err := fd.alertStream.Recv()
		if err != nil {
			UnblockSignal = err
			break
		}

		t, _ := json.Marshal(res)

		// Pass Events to Channel for further handling
		if o.EventChan != nil {
			o.EventChan <- EventInfo{Data: t, Type: "Alert"}
		}

	}

	fmt.Fprintln(os.Stderr, "Stopped WatchAlerts")

	return nil
}

// DestroyClient Function
func (fd *Feeder) DestroyClient() error {
	if err := fd.conn.Close(); err != nil {
		return err
	}
	fd.WgClient.Wait()
	return nil
}
