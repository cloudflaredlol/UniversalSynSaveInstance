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
print("PASS: merged syntax, public Tags fallback, override/error handling, bytecode routing, ZIP deduplication")
