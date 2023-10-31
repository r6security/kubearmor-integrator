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

package clients

import (
	seceventclient "github.com/r6security/kubearmor-integrator/clients/securityevent"
	amtdapi "github.com/r6security/phoenix/api/v1beta1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
)

type AmtdV1Beta1Client struct {
	restClient rest.Interface
}

var SchemeGroupVersion = schema.GroupVersion{Group: amtdapi.GroupVersion.Group, Version: amtdapi.GroupVersion.Version}

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(amtdapi.GroupVersion,
		&amtdapi.SecurityEvent{},
		&amtdapi.SecurityEventList{},
	)
	meta_v1.AddToGroupVersion(scheme, amtdapi.GroupVersion)
	return nil
}

func NewClient(cfg *rest.Config) (*AmtdV1Beta1Client, error) {
	scheme := runtime.NewScheme()
	SchemeBuilder := runtime.NewSchemeBuilder(addKnownTypes)
	if err := SchemeBuilder.AddToScheme(scheme); err != nil {
		return nil, err
	}
	config := *cfg
	config.GroupVersion = &amtdapi.GroupVersion
	config.APIPath = "/apis"
	config.ContentType = runtime.ContentTypeJSON
	config.NegotiatedSerializer = serializer.NewCodecFactory(scheme).WithoutConversion()
	client, err := rest.RESTClientFor(&config)
	if err != nil {
		return nil, err
	}
	return &AmtdV1Beta1Client{restClient: client}, nil
}

func (c *AmtdV1Beta1Client) SecurityEvents() seceventclient.SecurityEventInterface {
	return seceventclient.NewSecurityEventClient(c.restClient)
}
