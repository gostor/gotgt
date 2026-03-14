/*
Copyright 2016 The GoStor Authors All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package target

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/apiserver/httputils"
	"github.com/gostor/gotgt/pkg/apiserver/router"
	"github.com/gostor/gotgt/pkg/scsi"
	"golang.org/x/net/context"
)

// targetRouter is a router to talk with the target controller
type targetRouter struct {
	routes []router.Route
}

// NewRouter initializes a new target router
func NewRouter() router.Router {
	r := &targetRouter{}
	r.initRoutes()
	return r
}

// Routes returns the available routers to the target controller
func (r *targetRouter) Routes() []router.Route {
	return r.routes
}

// initRoutes initializes the routes in target router
func (r *targetRouter) initRoutes() {
	r.routes = []router.Route{
		// GET
		router.NewGetRoute("/target/list", r.getTargetList),
		router.NewGetRoute("/target/tpgt/list", r.getTargetTPGTList),
		// POST
		router.NewPostRoute("/target/create", r.postTargetCreate),
		router.NewPostRoute("/target/up", r.postTargetUp),
		// DELETE
		router.NewDeleteRoute("/target/{name:.*}", r.deleteTarget),
	}
}

func (r *targetRouter) getTargetList(ctx context.Context, w http.ResponseWriter, req *http.Request, vars map[string]string) error {
	service := scsi.NewSCSITargetService()
	tgts, err := service.GetTargetList()
	if err != nil {
		return err
	}
	return httputils.WriteJSON(w, http.StatusOK, tgts)
}

func (r *targetRouter) postTargetCreate(ctx context.Context, w http.ResponseWriter, req *http.Request, vars map[string]string) error {
	var opts api.TargetCreateRequest
	if err := json.NewDecoder(req.Body).Decode(&opts); err != nil {
		return fmt.Errorf("bad parameter: %v", err)
	}
	if opts.Name == "" {
		return fmt.Errorf("bad parameter: target name is required")
	}

	service := scsi.NewSCSITargetService()
	target, err := service.NewSCSITarget(len(service.Targets), "iscsi", opts.Name)
	if err != nil {
		return err
	}
	return httputils.WriteJSON(w, http.StatusCreated, target)
}

func (r *targetRouter) postTargetUp(ctx context.Context, w http.ResponseWriter, req *http.Request, vars map[string]string) error {
	return nil
}

func (r *targetRouter) deleteTarget(ctx context.Context, w http.ResponseWriter, req *http.Request, vars map[string]string) error {
	name := vars["name"]
	if name == "" {
		return fmt.Errorf("bad parameter: target name is required")
	}

	if err := httputils.ParseForm(req); err != nil {
		return err
	}
	force := httputils.BoolValue(req, "force")

	service := scsi.NewSCSITargetService()
	if err := service.DeleteTarget(name, force); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (r *targetRouter) getTargetTPGTList(ctx context.Context, w http.ResponseWriter, req *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(req); err != nil {
		return err
	}
	targetName := req.FormValue("target")
	if targetName == "" {
		return fmt.Errorf("bad parameter: target name is required")
	}

	service := scsi.NewSCSITargetService()
	tgts, err := service.GetTargetList()
	if err != nil {
		return err
	}

	for _, tgt := range tgts {
		if tgt.Name == targetName {
			var result []api.TpgtInfo
			for _, tpg := range tgt.TargetPortGroups {
				info := api.TpgtInfo{TPGT: tpg.GroupID}
				for _, port := range tpg.TargetPortGroup {
					info.Portals = append(info.Portals, port.TargetPortName)
				}
				result = append(result, info)
			}
			return httputils.WriteJSON(w, http.StatusOK, result)
		}
	}
	return fmt.Errorf("target %q not found", targetName)
}
