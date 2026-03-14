# SCSI Commands Support

This document lists all SCSI commands supported by gotgt iSCSI target implementation.

## Overview

gotgt implements SCSI Primary Commands (SPC-3/4) and SCSI Block Commands (SBC-2/3) to provide a complete iSCSI target solution for block storage devices.

## Supported SCSI Commands

### SPC Commands (Primary Commands)

| Opcode | Command Name | Description | Status |
|--------|--------------|-------------|--------|
| 0x00 | TEST UNIT READY | Check if device is ready | ✅ Supported |
| 0x03 | REQUEST SENSE | Request sense data | ✅ Supported |
| 0x12 | INQUIRY | Get device information | ✅ Supported |
| 0x1A | MODE SENSE (6) | Get device parameters | ✅ Supported |
| 0x5A | MODE SENSE (10) | Get device parameters | ✅ Supported |
| 0x15 | MODE SELECT (6) | Set device parameters | ✅ Supported |
| 0x55 | MODE SELECT (10) | Set device parameters | ✅ Supported |
| 0x1B | START STOP UNIT | Control device power state | ✅ Supported |
| 0x1E | PREVENT ALLOW MEDIUM REMOVAL | Control media removal | ✅ Supported |
| 0xA0 | REPORT LUNS | Report LUN inventory | ✅ Supported |
| 0x1D | SEND DIAGNOSTIC | Run diagnostics | ✅ Supported |
| 0x5E | PERSISTENT RESERVE IN | Read reservation info | ✅ Supported |
| 0x5F | PERSISTENT RESERVE OUT | Modify reservations | ✅ Supported |
| 0xA3 | MAINTENANCE IN | Maintenance commands | ✅ Supported (Report Supported Operation Codes) |

### SBC Commands (Block Commands)

| Opcode | Command Name | Description | Status |
|--------|--------------|-------------|--------|
| 0x08 | READ (6) | Read data (21-bit LBA) | ✅ Supported |
| 0x28 | READ (10) | Read data (32-bit LBA) | ✅ Supported |
| 0xA8 | READ (12) | Read data (32-bit LBA) | ✅ Supported |
| 0x88 | READ (16) | Read data (64-bit LBA) | ✅ Supported |
| 0x0A | WRITE (6) | Write data (21-bit LBA) | ✅ Supported |
| 0x2A | WRITE (10) | Write data (32-bit LBA) | ✅ Supported |
| 0xAA | WRITE (12) | Write data (32-bit LBA) | ✅ Supported |
| 0x8A | WRITE (16) | Write data (64-bit LBA) | ✅ Supported |
| 0x2E | WRITE AND VERIFY (10) | Write and verify | ✅ Supported |
| 0xAE | WRITE AND VERIFY (12) | Write and verify | ✅ Supported |
| 0x8E | WRITE AND VERIFY (16) | Write and verify | ✅ Supported |
| 0x41 | WRITE SAME (10) | Write same pattern | ✅ Supported |
| 0x93 | WRITE SAME (16) | Write same pattern | ✅ Supported |
| 0x8B | ORWRITE (16) | OR write operation | ✅ Supported |
| 0x89 | COMPARE AND WRITE | Atomic compare and write | ✅ Supported |
| 0x25 | READ CAPACITY (10) | Get device capacity | ✅ Supported |
| 0x9E | SERVICE ACTION IN (16) | Read capacity (16) | ✅ Supported |
| 0x2F | VERIFY (10) | Verify data integrity | ✅ Supported |
| 0xAF | VERIFY (12) | Verify data integrity | ✅ Supported |
| 0x8F | VERIFY (16) | Verify data integrity | ✅ Supported |
| 0x34 | PRE-FETCH (10) | Cache data | ✅ Supported |
| 0x90 | PRE-FETCH (16) | Cache data | ✅ Supported |
| 0x35 | SYNCHRONIZE CACHE (10) | Flush cache | ✅ Supported |
| 0x91 | SYNCHRONIZE CACHE (16) | Flush cache | ✅ Supported |
| 0x42 | UNMAP | Deallocate blocks | ✅ Supported |
| 0x04 | FORMAT UNIT | Format media | ✅ Supported |
| 0x16 | RESERVE (6) | Reserve device | ✅ Supported |
| 0x17 | RELEASE (6) | Release device | ✅ Supported |

### Persistent Reservation Service Actions

#### PR IN Service Actions

| Service Action | Name | Description | Status |
|----------------|------|-------------|--------|
| 0x00 | READ KEYS | Read reservation keys | ✅ Supported |
| 0x01 | READ RESERVATION | Read current reservation | ✅ Supported |
| 0x02 | REPORT CAPABILITIES | Report PR capabilities | ✅ Supported |

#### PR OUT Service Actions

| Service Action | Name | Description | Status |
|----------------|------|-------------|--------|
| 0x00 | REGISTER | Register reservation key | ✅ Supported |
| 0x01 | RESERVE | Reserve device | ✅ Supported |
| 0x02 | RELEASE | Release reservation | ✅ Supported |
| 0x03 | CLEAR | Clear all reservations | ✅ Supported |
| 0x04 | PREEMPT | Preempt reservation | ✅ Supported |
| 0x06 | REGISTER AND IGNORE EXISTING KEY | Register new key | ✅ Supported |
| 0x07 | REGISTER AND MOVE | Register and move | ✅ Supported |

## Supported VPD Pages

The INQUIRY command supports the following Vital Product Data (VPD) pages:

| Page Code | Name | Description | Status |
|-----------|------|-------------|--------|
| 0x00 | Supported VPD Pages | List of supported VPD pages | ✅ Supported |
| 0x80 | Unit Serial Number | Device serial number | ✅ Supported |
| 0x83 | Device Identification | Device identifiers | ✅ Supported |
| 0xB0 | Block Limits | Block device limits | ✅ Supported |
| 0xB2 | Logical Block Provisioning | Thin provisioning info | ✅ Supported |

## Supported Mode Pages

The MODE SENSE command supports the following mode pages:

| Page Code | Name | Description | Status |
|-----------|------|-------------|--------|
| 0x02 | Disconnect-Reconnect | Disconnect/reconnect parameters | ✅ Supported |
| 0x08 | Caching | Cache control parameters | ✅ Supported |
| 0x0A | Control | Control mode parameters | ✅ Supported |
| 0x0A/0x01 | Control Extension | Extended control parameters | ✅ Supported |
| 0x1C | Informational Exceptions | SMART control parameters | ✅ Supported |

## iSCSI Protocol Features

| Feature | Description | Status |
|---------|-------------|--------|
| Login Authentication | CHAP authentication | ✅ Supported |
| Multiple Connections | Multiple TCP connections per session | ✅ Supported |
| Header Digest | CRC32C header integrity | ✅ Supported |
| Data Digest | CRC32C data integrity | ✅ Supported |
| Immediate Data | Immediate data delivery | ✅ Supported |
| Unsolicited Data | Unsolicited data-out PDUs | ✅ Supported |
| Error Recovery Level | Error recovery mechanisms | Level 0 Supported |

## Tested with libiscsi

All commands have been tested with the libiscsi test suite. The following test categories are fully supported:

- ✅ Inquiry commands (including EVPD handling)
- ✅ Read operations (6/10/12/16 byte CDBs)
- ✅ Write operations (6/10/12/16 byte CDBs)
- ✅ Write and Verify operations
- ✅ Verify operations
- ✅ Capacity reporting
- ✅ Mode Sense/Select operations
- ✅ Persistent Reservation operations
- ✅ Unmap/Trim operations
- ✅ Synchronize Cache operations
- ✅ iSCSI protocol compliance

### Test Results

```
Total Tests: 38
Passed: 38
Failed: 0
Pass Rate: 100%
```

Tested with libiscsi test suite covering all major SCSI command categories.

### Recent Fixes

#### Bug Fix: SCSICDBBufXLength Function (2025-03-10)

Fixed incorrect Allocation Length calculation for 6-byte CDB commands:

1. **INQUIRY (0x12) and REQUEST_SENSE (0x03)**: Use bytes 3-4 for Allocation Length
2. **Other Group 0 commands (READ_6, WRITE_6, etc.)**: Return `ok=false` since these commands don't have Allocation Length field in their CDB. This prevents incorrect truncation of sense data buffer.

#### Bug Fix: CDB Group ID Comparison (2025-03-10)

Fixed incorrect comparison between CDB length constants and group IDs:
- Original: Used CDB length constants (6, 10, 12, 16) which were incorrect
- Fixed: Use actual group IDs (0-7) for switch statement

#### Bug Fix: PERSISTENT_RESERVE_IN/OUT (0x5E/0x5F) (2025-03-10)

Fixed Allocation Length position for these commands:
- Use bytes 6-7 instead of bytes 7-8
- Added manual BigEndian conversion for correct byte order

## Notes

### Block Device Characteristics VPD Page (0xB1)

This VPD page is currently not supported. The INQUIRY command will return a CHECK CONDITION status with ILLEGAL_REQUEST sense key when this page is requested. This is expected behavior and does not affect normal operations.

### Persistent Reservations

- All standard reservation types are supported: Write Exclusive, Exclusive Access, and their variants with registrants only.
- Reservation scopes: LU (Logical Unit) scope is supported.
- Persistent reservation operations require proper key registration before use.

### Thin Provisioning

- UNMAP command is fully supported for thin-provisioned LUNs.
- Logical Block Provisioning VPD page (0xB2) reports thin provisioning capabilities.

## Version Information

- SPC Version: SPC-3 (with some SPC-4 features)
- SBC Version: SBC-2 (with some SBC-3 features)
- iSCSI Protocol: RFC 3720 compliant

## References

- [SCSI Primary Commands - 4 (SPC-4)](https://www.t10.org/cgi-bin/ac.pl?t=f&f=spc4r11.pdf)
- [SCSI Block Commands - 3 (SBC-3)](https://www.t10.org/cgi-bin/ac.pl?t=f&f=sbc3r35.pdf)
- [iSCSI Protocol (RFC 3720)](https://tools.ietf.org/html/rfc3720)
- [libiscsi Test Suite](https://github.com/gostor/libiscsi)
