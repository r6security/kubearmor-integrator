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

// Package log connects and observes telemetry from KubeArmor
package kubearmorlog

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kubearmor/kubearmor-client/k8s"
)

// Options Structure
type Options struct {
	GRPC      string
	EventChan chan EventInfo // channel to send events on
}

// UnblockSignal is a flag to check whether the Watch* APIs have exited or signal has rcvd
var UnblockSignal error

// GetOSSigChannel Function
func GetOSSigChannel() chan os.Signal {
	c := make(chan os.Signal, 1)

	signal.Notify(c,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		os.Interrupt)

	return c
}

// StartObserver Function
func StartObserver(c *k8s.Client, o Options) error {
	// create client
	logClient, err := NewClient(o.GRPC)
	if err != nil {
		return errors.New(fmt.Sprintf("Unable to create log client. Original error: %s", err))
	}

	// do healthcheck
	if ok := logClient.DoHealthCheck(); !ok {
		return errors.New("Failed to check the liveness of the gRPC server")
	}

	go logClient.WatchAlerts(o)

	ctrlc := false
	// listen for interrupt signals
	UnblockSignal = nil
	sigChan := GetOSSigChannel()
	for UnblockSignal == nil && !ctrlc {
		time.Sleep(50 * time.Millisecond)
		select {
		case <-sigChan:
			ctrlc = true
		default:
		}
	}

	logClient.Running = false

	// destroy the client
	_ = logClient.DestroyClient()
	if ctrlc {
		return nil
	}
	return UnblockSignal
}
