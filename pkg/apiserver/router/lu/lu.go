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
package lu

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/apiserver/httputils"
	"github.com/gostor/gotgt/pkg/apiserver/router"
	"github.com/gostor/gotgt/pkg/config"
	"github.com/gostor/gotgt/pkg/scsi"
	"golang.org/x/net/context"
)

// luRouter is a router to talk with the LU controller
type luRouter struct {
	routes []router.Route
}

// NewRouter initializes a new LU router
func NewRouter() router.Router {
	r := &luRouter{}
	r.initRoutes()
	return r
}

// Routes returns the available routers to the LU controller
func (r *luRouter) Routes() []router.Route {
	return r.routes
}

// initRoutes initializes the routes in lu router
func (r *luRouter) initRoutes() {
	r.routes = []router.Route{
		// GET
		router.NewGetRoute("/lu/list", r.getLuList),
		router.NewGetRoute("/lu/{id:.*}", r.getLu),
		// POST
		router.NewPostRoute("/lu/create", r.postLuCreate),
		// DELETE
		router.NewDeleteRoute("/lu/delete", r.deleteLu),
	}
}

func (r *luRouter) getLuList(ctx context.Context, w http.ResponseWriter, req *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(req); err != nil {
		return err
	}
	targetName := req.FormValue("target")
	if targetName == "" {
		return fmt.Errorf("bad parameter: target name is required")
	}

	lunMap := scsi.GetTargetLUNMap(targetName)
	var result []api.LuInfo
	for lun, lu := range lunMap {
		if lu == nil {
			continue
		}
		info := api.LuInfo{
			LUN:    lun,
			Path:   lu.Path,
			Online: lu.Attrs.Online,
			Size:   lu.Size,
		}
		result = append(result, info)
	}
	return httputils.WriteJSON(w, http.StatusOK, result)
}

func (r *luRouter) getLu(ctx context.Context, w http.ResponseWriter, req *http.Request, vars map[string]string) error {
	return nil
}

func (r *luRouter) postLuCreate(ctx context.Context, w http.ResponseWriter, req *http.Request, vars map[string]string) error {
	var opts api.LuCreateRequest
	if err := json.NewDecoder(req.Body).Decode(&opts); err != nil {
		return fmt.Errorf("bad parameter: %v", err)
	}
	if opts.TargetName == "" {
		return fmt.Errorf("bad parameter: target name is required")
	}
	if opts.Path == "" {
		return fmt.Errorf("bad parameter: path is required")
	}

	bs := config.BackendStorage{
		DeviceID:   opts.DeviceID,
		Path:       opts.Path,
		Online:     true,
		BlockShift: opts.BlockShift,
	}
	if err := scsi.AddBackendStorage(bs); err != nil {
		return err
	}

	m := scsi.LUNMapping{
		TargetName: opts.TargetName,
		LUN:        opts.LUN,
		DeviceID:   opts.DeviceID,
	}
	if err := scsi.AddLUNMapping(m); err != nil {
		return err
	}

	// Refresh target's device map
	service := scsi.NewSCSITargetService()
	service.RereadTargetLUNMap()

	w.WriteHeader(http.StatusCreated)
	return nil
}

func (r *luRouter) deleteLu(ctx context.Context, w http.ResponseWriter, req *http.Request, vars map[string]string) error {
	var opts api.LuRemoveOptions
	if err := json.NewDecoder(req.Body).Decode(&opts); err != nil {
		return fmt.Errorf("bad parameter: %v", err)
	}
	if opts.TargetName == "" {
		return fmt.Errorf("bad parameter: target name is required")
	}

	scsi.DelLUNMapping(scsi.LUNMapping{
		TargetName: opts.TargetName,
		LUN:        opts.LUN,
	})

	// Refresh target's device map
	service := scsi.NewSCSITargetService()
	service.RereadTargetLUNMap()

	w.WriteHeader(http.StatusNoContent)
	return nil
}
