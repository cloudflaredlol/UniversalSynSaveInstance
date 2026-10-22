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

local readProperty = assert(loadstring([[
local __BREAK = "SKIPPED"
local InstancesOverrides = {}
local nativeCalls = 0
local function gethiddenproperty() nativeCalls += 1; error("Unsafe native getter called") end
local function anonymize(raw) return raw end
]] .. section("local function readProperty(instance, property)", "local function GetInheritedProps(className)") .. [[
return function()
    local instance = setmetatable({Name = "VFX"}, {__index = function(_, key)
        if key == "Tags" then error("Tags must use the public fallback") end
    end})
    local property = {Name = "Tags", ValueType = "SharedString", Special = true,
        Fallback = function() return "effect\0beam" end}
    assert(readProperty(instance, property) == "effect\0beam")
    property.Special, property.CanRead = false, true
    assert(readProperty(instance, property) == "effect\0beam", "Readable tags must also avoid native reads")
    property.Fallback = function() return "" end
    assert(readProperty(instance, property) == "", "Empty tags must stay empty")
    InstancesOverrides[instance] = {Properties = {Tags = "override"}}
    assert(readProperty(instance, property) == "override", "Overrides must keep precedence")
    InstancesOverrides[instance] = nil
    property.Fallback = function() error("Public API failed") end
    assert(readProperty(instance, property) == __BREAK, "Failed public reads must not enter the native getter")
    assert(nativeCalls == 0)
    assert(readProperty(instance, {Name = "Name", ValueType = "string", CanRead = true}) == "VFX")
end
]]))()
readProperty()

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

local quiesce = section("if OPTIONS.KillAllScripts and not USSI.KillAllScripts then", "\n\tif IsolateStarterPlayer then")
local capture = section("local ok, err = xpcall(function()", "\n\tif OPTIONS.BoostFPS then")
local snapshot = assert(loadstring([[
return function(mode)
    local gameThread = coroutine.create(function() end)
    local oldHeartbeat = coroutine.create(function() end)
    local newHeartbeat
    local ownFunction, gameFunction = function() end, function() end
    local hooked = false
    local self = coroutine.running()
    local OPTIONS, USSI = {KillAllScripts = true}, {}
    local SaveCacheInterval = 0x1600 * 10
    local game = {GetService = function() return {SetTimeout = function() end} end}
    local getreg = function() return {self, gameThread, oldHeartbeat, ownFunction, gameFunction} end
    local getallthreads, getgc = getreg, getreg
    local debug = {traceback = debug.traceback}
    local isexecutorclosure = function(f) return f == ownFunction end
    local hookfunction = function(f) assert(f == gameFunction); hooked = true end
    local collected = false
    if mode ~= "no-hook" then
        OPTIONS.BeforeSave = function()
            assert(coroutine.status(gameThread) == "dead", "Client threads must stop before preparation")
            assert(coroutine.status(oldHeartbeat) == "dead", "The sweep also stops the prior heartbeat")
            newHeartbeat = coroutine.create(function() end)
            if mode == "error" then error("preparation failed") end
        end
    end
    local function save_game()
        assert(hooked, "Client functions must be stopped before collection")
        if mode ~= "no-hook" then assert(newHeartbeat) end
        collected = true
    end
]] .. quiesce .. "\n" .. capture .. [[
    return ok, err, collected
end
]]))()
for _, mode in {"ok", "no-hook"} do
    local ok, err, collected = snapshot(mode)
    assert(ok and collected, tostring(err))
end
local ok, err, collected = snapshot("error")
assert(not ok and not collected and err:find("preparation failed", 1, true))
print("PASS: merged syntax, Tags fallback, bytecode routing/ZIP, stop-before-prepare ordering, heartbeat restart, preparation failure")
