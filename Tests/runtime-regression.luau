-- Run with Lune. These tests execute the real merged functions with local mocks;
-- they do not connect to Roblox, run game scripts, or need Studio.
local fs = require("@lune/fs")
local source = fs.readFile("saveinstance.luau")
assert(loadstring(source), "The merged saver must compile")
assert(fs.readFile("saveinstance.lua") == source, "Both entry points must match")

local function section(first, last)
    local start = assert(source:find(first, 1, true))
    local finish = assert(source:find(last, start, true))
    return source:sub(start, finish - 1)
end

local sourceFor = assert(loadstring([[
local RecoverScriptsFromAssets = false
local Enum = {RunContext = {Server = "server", Client = "client"}}
local dumpCalls, decompileCalls = 0, 0
local DumpBytecode = function() dumpCalls += 1; return "-- USSI_BYTECODE_BASE64: YWJj" end
local function ldecompile() decompileCalls += 1; return "decompiled" end
local function index(instance, key) return instance[key] end
]] .. section("local function sourceFor(instance, ldIgnoring)", "local function replaceClassName(instance, InstanceName, ClassName)") .. [[
return function()
    local function script(class, context)
        return {LinkedSource = "", RunContext = context, IsA = function(_, expected) return class == expected end}
    end
    for _, object in {script("LocalScript", "client"), script("ModuleScript", "client"), script("Script", "client")} do
        assert(sourceFor(object, false):find("USSI_BYTECODE_BASE64", 1, true))
    end
    assert(dumpCalls == 3 and decompileCalls == 0, "DumpBytecode must bypass decompilation")
    assert(sourceFor(script("Script", "server"), false):find("FilteringEnabled", 1, true))
    assert(dumpCalls == 3, "Server scripts must not be dumped")
    assert(sourceFor(script("LocalScript", "client"), true) == "-- Ignored")
    DumpBytecode = nil
    assert(sourceFor(script("LocalScript", "client"), false):find("decompiled", 1, true))
    assert(decompileCalls == 1)
end
]]))()
sourceFor()

local dump = assert(loadstring([[
local OPTIONS = {DumpBytecode = true, DumpBytecodeZip = true}
local getscriptbytecode = true
local function getbytecode() return true, "abc" end
local function sanitizeFileName(name) return name end
]] .. section("local DumpBytecode, DumpedBytecode", "local crc32Table") .. [[
return function()
    local script = {ClassName = "ModuleScript", Name = "Test", GetFullName = function() return "ReplicatedStorage.Test" end}
    local first, second = DumpBytecode(script), DumpBytecode(script)
    assert(first == second)
    assert(#DumpedBytecode.files == 1, "ZIP mode must deduplicate bytecode")
    assert(#DumpedBytecode.scripts == 2)
    assert(DumpedBytecode.files[1].data == "abc")
end
]]))()
dump()
print("PASS: merged syntax, bytecode routing, ZIP deduplication")
