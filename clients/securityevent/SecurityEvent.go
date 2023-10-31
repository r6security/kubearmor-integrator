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

package securityevent

import (
	"context"

	amtdapi "github.com/r6security/phoenix/api/v1beta1"
	"k8s.io/client-go/rest"
)

type SecurityEventInterface interface {
	Create(ctx context.Context, obj *amtdapi.SecurityEvent) (*amtdapi.SecurityEvent, error)
}

type securityEventClient struct {
	client rest.Interface
}

func NewSecurityEventClient(client rest.Interface) SecurityEventInterface {
	return &securityEventClient{
		client: client,
	}
}

func (c *securityEventClient) Create(ctx context.Context, obj *amtdapi.SecurityEvent) (*amtdapi.SecurityEvent, error) {
	result := &amtdapi.SecurityEvent{}
	err := c.client.
		Post().
		Resource("securityevents").
		Body(obj).
		Do(ctx).
		Into(result)
	return result, err
}
