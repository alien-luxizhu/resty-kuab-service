---
--- Generated by EmmyLua(https://github.com/EmmyLua)
--- Created by luxizhu.
--- DateTime: 2021/5/31 14:22
---

local require = require
local cjson = require("cjson")
local setmetatable = setmetatable
local table = table
local builder = {}

function builder.RsNewTable(self)
    self.curr_table_ = {}
    return self
end

function builder.RsNewTableRow(self)
    self.curr_table_row_ = {}
    return self
end

function builder.RsSetValue(self, key, value)
    self.curr_table_row_[key] = value
    return self
end

function builder.RsSaveRow(self)
    table.insert(self.curr_table_, self.curr_table_row_)
    return self
end

function builder.RsSaveTable(self)
    table.insert(self.body, self.curr_table_)
    return self
end

function builder.SetValue(self, key, value)
    self.body[key] = value
    return self
end

function builder.GetValue(self, key)
    return self.body[key]
end

function builder.apply(self)
    return self.body
end

function builder.new()
    local self = {
        body = {},
    }
    setmetatable(self.body, {
        __tostring = function()
            return cjson.encode(self.body)
        end,
    })
    setmetatable(self, {
        __index = builder,
        __call = builder.apply,
    })
    return self
end

local _M = {
    builder = builder
}
return _M
