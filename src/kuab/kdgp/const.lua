---
--- Generated by EmmyLua(https://github.com/EmmyLua)
--- Created by luxizhu.
--- DateTime: 2021/5/28 16:28
---

local kProtocolLen = 4
local kHeadLenFieldLen = 8
local kBodyLenFieldLen = 8
local kCRCFieldLen = 8
local kHeadFormatFieldLen = 4
local kCRCBeginPos = kProtocolLen + kHeadLenFieldLen + kBodyLenFieldLen
local kHeadFormatBeginPos = kCRCBeginPos + kCRCFieldLen
local kHeadBeginPos = kHeadFormatBeginPos + kHeadFormatFieldLen

return {
    kProtocolLen = 4,
    kHeadLenFieldLen = 8,
    kBodyLenFieldLen = 8,
    kCRCFieldLen = 8,
    kHeadFormatFieldLen = 4,
    kBodyFormatFieldLen = 4,
    kCRCBeginPos = kCRCBeginPos,
    kHeadFormatBeginPos = kHeadFormatBeginPos,
    kHeadBeginPos = kHeadBeginPos,


    MsgType_Logon = "session_logon",
    MsgType_Heartbeat = "session_heartbeat",

    --- 包头属性值名称
    KDGB_Protocol = "Protocol", -- 业务协议名称，FS接口固定填STD
    KDGB_Version = "Version", -- KDGP版本
    KDGB_MsgType = "MsgType", -- 功能号
    KDGB_SendingTime = "SendingTime", -- 客户端发送时间 "2009-2-27 18:02:15.123"
    KDGB_Context = "Context", -- 客户端会话序号，上下文关联使用，网关反射不处理
    KDGB_ReplyCode = "ReplyCode", -- 处理结果代码
    KDGB_ReplyMsg = "ReplyMsg", -- 处理结果信息
    KDGB_ReplyLevel = "ReplyLevel", -- 处理结果类型
    KDGB_AppID = "AppID", -- 签入时设置的开发者ID号
    KDGB_AppSecret = "AppSecret", -- 签入时设置的应用授权号
    KDGB_AppIP = "AppIP", -- 请求时设置的IP地址
    KDGB_AppMAC = "AppMAC", -- 请求时设置的MAC地址
    KDGB_AppName = "AppName", -- 请求时设置的应用名称
    KDGB_AppSign = "AppSign", -- 请求时设置的应用签名(MD5值)
    KDGB_ApiName = "ApiName", -- 请求时设置api名称
    KDGB_ApiVersion = "ApiVersion", -- 请求时设置api版本
    KDGB_Charset = "Charset", -- 编码格式 GBK|UTF8
    KDGB_FLG_TRAN = "FLG_WantTran", -- 接口转换标志 FS接口固定填Y
    KDGB_FLG_Encrypt = "FLG_Encrypt", -- 加密标志 0:使用后台加密方式 1:表示采用统一接入标准密码加密方式

}