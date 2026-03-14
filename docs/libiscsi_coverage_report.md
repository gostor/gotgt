# libiscsi Test Coverage Report

## 概述

本报告分析了 libiscsi 测试对 gotgt 项目的覆盖情况。

## 测试用例清单 (37个)

### Inquiry 测试 (6个)
- ALL.Inquiry.Standard
- ALL.Inquiry.AllocLength  
- ALL.Inquiry.MandatoryVPDSBC
- ALL.Inquiry.SupportedVPD
- ALL.Inquiry.VersionDescriptors
- ALL.Inquiry.EVPD

### Read 测试 (4个)
- ALL.Read6, ALL.Read10, ALL.Read12, ALL.Read16

### Write 测试 (6个)
- ALL.Write10, ALL.Write12, ALL.Write16
- ALL.WriteVerify10, ALL.WriteVerify12, ALL.WriteVerify16

### Verify 测试 (3个)
- ALL.Verify10, ALL.Verify12, ALL.Verify16

### Write Same 测试 (2个)
- ALL.WriteSame10.Simple, ALL.WriteSame16.Simple

### Capacity 测试 (2个)
- ALL.ReadCapacity10, ALL.ReadCapacity16

### iSCSI 协议测试 (2个)
- ALL.iSCSITMF (Task Management)
- ALL.iSCSIcmdsn (Command SN)

### 其他测试 (12个)
- ALL.Mandatory, ALL.ModeSense6, ALL.NoMedia
- ALL.Prefetch10/16, ALL.PreventAllow
- ALL.ReportSupportedOpcodes.Simple
- ALL.Reserve6.Simple, ALL.StartStopUnit
- ALL.TestUnitReady, ALL.ReadOnly
- ALL.Unmap.Simple/VPD/ZeroBlocks

## 覆盖率统计

| 模块 | 总命令数 | 已测试 | 覆盖率 |
|-----|---------|-------|-------|
| iSCSI PDU | 13 | 11 | 85% |
| SBC 命令 | 26 | 16 | 62% |
| SPC 命令 | 13 | 10 | 77% |

## 未覆盖功能

### SCSI 命令 (未测试)
- FORMAT_UNIT (0x04)
- WRITE_6 (0x0A)
- SYNCHRONIZE_CACHE_10/16
- COMPARE_AND_WRITE (0x89)
- ORWRITE_16 (0x8B)
- PERSISTENT_RESERVE_IN/OUT

### iSCSI 功能 (未实现)
- SNACK PDU
- Async PDU
- 多连接 Session (MC/S)
- Error Recovery Level 1/2

## 估计整体覆盖率: 60%
