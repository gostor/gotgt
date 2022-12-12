/*
Copyright 2017 The GoStor Authors All rights reserved.

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

import (
	"bytes"
	"container/list"
	"fmt"
	"io"

	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/util"
	log "github.com/sirupsen/logrus"
)

type BaseBackingStore struct {
	Name            string
	DataSize        uint64
	OflagsSupported int
}

type BackingStoreFunc func() (api.BackingStore, error)

var registeredBSPlugins = map[string](BackingStoreFunc){}

func RegisterBackingStore(name string, f BackingStoreFunc) {
	registeredBSPlugins[name] = f
}

func NewBackingStore(name string) (api.BackingStore, error) {
	if name == "" {
		return nil, nil
	}
	f, ok := registeredBSPlugins[name]
	if !ok {
		return nil, fmt.Errorf("Backend storage %s is not found.", name)
	}
	return f()
}

func bsPerformCommand(bs api.BackingStore, cmd *api.SCSICommand) (err error, key byte, asc SCSISubError) {
	var (
		scb        = cmd.SCB
		offset     = cmd.Offset
		opcode     = api.SCSICommandType(scb[0])
		lu         = cmd.Device
		length     int
		doVerify   bool = false
		doWrite    bool = false
		ok         bool = false
		rbuf, wbuf []byte
		wbufList   *list.List
		tl         int64 = int64(cmd.TL)
	)

	key = HARDWARE_ERROR
	asc = ASC_INTERNAL_TGT_FAILURE
	switch opcode {
	case api.ORWRITE_16:
		err = bs.ReadAt(cmd.InSDBBuffer.Buffer, int64(offset))
		if err != nil {
			key = MEDIUM_ERROR
			asc = ASC_READ_ERROR
			break
		}
		if cmd.OutSDBBuffer != nil {
			wbufList = cmd.OutSDBBuffer.BufferList
		}
		doWrite = true
		goto write
	case api.COMPARE_AND_WRITE:
		// TODO
		doWrite = true
		goto write
	case api.SYNCHRONIZE_CACHE, api.SYNCHRONIZE_CACHE_16:
		if tl == 0 {
			tl = int64(lu.Size - offset)
		}
		if err = bs.DataSync(int64(offset), tl); err != nil {
			key = MEDIUM_ERROR
			asc = ASC_READ_ERROR
			break
		}
		break
	case api.WRITE_VERIFY, api.WRITE_VERIFY_12, api.WRITE_VERIFY_16:
		doVerify = true
		fallthrough
	case api.WRITE_6, api.WRITE_10, api.WRITE_12, api.WRITE_16:
		// For stupid client which does not set WRITE flag
		if cmd.OutSDBBuffer != nil {
			wbufList = cmd.OutSDBBuffer.BufferList
		}
		doWrite = true
		goto write
	case api.WRITE_SAME, api.WRITE_SAME_16:
		// TODO
		break
	case api.READ_6, api.READ_10, api.READ_12, api.READ_16:
		err = bs.ReadAt(cmd.InSDBBuffer.Buffer, int64(offset))
		if err != nil && err != io.EOF {
			key = MEDIUM_ERROR
			asc = ASC_READ_ERROR
			break
		}

		if (opcode != api.READ_6) && (scb[1]&0x10 != 0) {
			bs.DataAdvise(int64(offset), int64(length), util.POSIX_FADV_NOREUSE)
		}
		cmd.InSDBBuffer.Resid = uint32(length)
		if cmd.InSDBBuffer.Length < uint32(length) {
			key = ILLEGAL_REQUEST
			asc = ASC_INVALID_FIELD_IN_CDB
			goto sense
		}
	case api.PRE_FETCH_10, api.PRE_FETCH_16:
		err = bs.DataAdvise(int64(offset), tl, util.POSIX_FADV_WILLNEED)
		if err != nil {
			key = MEDIUM_ERROR
			asc = ASC_READ_ERROR
		}
	case api.VERIFY_10, api.VERIFY_12, api.VERIFY_16:
		// For stupid client which does not set WRITE flag
		if cmd.OutSDBBuffer != nil {
			wbufList = cmd.OutSDBBuffer.BufferList
		}
		doVerify = true
		goto verify
	default:
		break
	}
write:
	if doWrite {
		var write_offset = offset
		for e := wbufList.Front(); e != nil; e = e.Next() {
			wbuf, ok = e.Value.([]byte)
			if !ok {
				continue
			}

			err = bs.Write(wbuf, int64(write_offset))
			if err != nil {
				log.Error(err)
				key = MEDIUM_ERROR
				asc = ASC_WRITE_ERROR
				goto sense
			}

			write_offset += uint64(len(wbuf))
		}
		log.Debugf("write data at 0x%x for length %d", offset, len(wbuf))
		var pg *api.ModePage
		for _, p := range lu.ModePages {
			if p.PageCode == 0x08 && p.SubPageCode == 0 {
				pg = &p
				break
			}
		}
		if pg == nil {
			key = ILLEGAL_REQUEST
			asc = ASC_INVALID_FIELD_IN_CDB
			goto sense
		}
		if ((opcode != api.WRITE_6) && (scb[1]&0x8 != 0)) || (pg.Data[0]&0x04 == 0) {
			if err = bs.DataSync(int64(offset), tl); err != nil {
				key = MEDIUM_ERROR
				asc = ASC_WRITE_ERROR
				goto sense
			}
		}

		if (opcode != api.WRITE_6) && (scb[1]&0x10 != 0) {
			bs.DataAdvise(int64(offset), int64(length), util.POSIX_FADV_NOREUSE)
		}
	}
verify:
	if doVerify {
		rbuf = make([]byte, int(tl))
		err = bs.ReadAt(rbuf, int64(offset))
		if err != nil {
			log.Errorf("failed to ReadAt at offset=%d, %v", offset, err)
			key = MEDIUM_ERROR
			asc = ASC_READ_ERROR
			goto sense
		}
		var tmp_offset = 0
		for e := wbufList.Front(); e != nil; e = e.Next() {
			wbuf, ok = e.Value.([]byte)
			if !ok {
				continue
			}

			if !bytes.Equal(wbuf, rbuf[tmp_offset:tmp_offset+len(wbuf)]) {
				err = fmt.Errorf("verify fail between out buffer[length=%d] and read buffer[length=%d]", len(wbuf), len(rbuf))
				log.Error(err)
				key = MISCOMPARE
				asc = ASC_MISCOMPARE_DURING_VERIFY_OPERATION
				goto sense
			}

			tmp_offset += len(wbuf)
		}
		if len(rbuf) != tmp_offset {
			err = fmt.Errorf("verify fail between out buffer[length=%d] and read buffer[length=%d]", len(wbuf), len(rbuf))
			log.Error(err)
			key = MISCOMPARE
			asc = ASC_MISCOMPARE_DURING_VERIFY_OPERATION
			goto sense
		}
		if scb[1]&0x10 != 0 {
			bs.DataAdvise(int64(offset), int64(length), util.POSIX_FADV_WILLNEED)
		}
	}
	return nil, key, asc
sense:
	if err != nil {
		return err, key, asc
	}

	err = fmt.Errorf("sense data encounter, key: %v, asc: %v", key, asc)
	return err, key, asc
}
