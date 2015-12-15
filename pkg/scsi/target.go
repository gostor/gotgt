/*
Copyright 2015 The GoStor Authors All rights reserved.

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

package scsi

type SCSITargetState int

var (
	TargetOnline SCSITargetState = 1
	TargetReady  SCSITargetState = 2
)

const (
	PR_SPECIAL = (1 << 5)
	PR_WE_FA   = (1 << 4)
	PR_EA_FA   = (1 << 3)
	PR_RR_FR   = (1 << 2)
	PR_WE_FN   = (1 << 1)
	PR_EA_FN   = (1 << 0)
)

type SCSITarget struct {
	Name  string
	TID   int
	LID   int
	State SCSITargetState
}
