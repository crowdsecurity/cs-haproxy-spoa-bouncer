-- Dynamically set package.path based on the script location
local function get_script_dir()
    local info = debug.getinfo(1, "S") -- "S" = source
    local source = info.source
    if source:sub(1, 1) == "@" then
        local path = source:sub(2) -- remove the "@"
        return path:match("(.*/)")
    end
    return "./"
end

local script_dir = get_script_dir()
package.path = package.path .. ";" .. script_dir .. "?.lua"

local utils = require "utils"
local template = require "template"

-- Template
-- @param path the path to the template
-- @return object with template and render function
local function NewTemplate(path)
    local self = {}
    self.template = utils.read_file(path)
    self.render = function(data)
        return template.compile(self.template, data)
    end
    return self
end

-- @param prefix the prefix to add to the log
-- @return object with log, info, error, warning and debug functions
local function NewLogger(prefix)
    local self = {}
    self.prefix = prefix
    self.log = function(level, message)
        core.log(level, self.prefix .. message)
    end
    self.info = function(message)
        core.Info("[INFO] " .. message)
    end
    self.error = function(message)
        core.log(core.err, "[ERROR] " .. message)
    end
    self.warning = function(message)
        core.Warning("[WARN] " .. message)
    end
    self.debug = function(message)
        core.Debug("[DEBUG] " .. message)
    end
    return self
end


local runtime = {}

-- Loads the configuration
local function init()
    BAN_TEMPLATE_PATH = os.getenv("CROWDSEC_BAN_TEMPLATE_PATH")
    CAPTCHA_TEMPLATE_PATH = os.getenv("CROWDSEC_CAPTCHA_TEMPLATE_PATH")
    CROWDSEC_LOG_LEVEL = os.getenv("CROWDSEC_LOG_LEVEL")
    runtime.logger = NewLogger("[crowdsec] ")
    runtime.logger.info("initialising lua modules")

    if BAN_TEMPLATE_PATH == nil then
        runtime.logger.warning("CROWDSEC_BAN_TEMPLATE_PATH env is not set trying default")
        BAN_TEMPLATE_PATH =  "/var/lib/crowdsec-haproxy-spoa-bouncer/html/ban.html"
        if not utils.file_exist(BAN_TEMPLATE_PATH) then
            runtime.logger.error("Default ban template not found at " .. BAN_TEMPLATE_PATH)
            return
        end
    end

    runtime.ban = NewTemplate(BAN_TEMPLATE_PATH)

    if CAPTCHA_TEMPLATE_PATH == nil then
        runtime.logger.warning("CROWDSEC_CAPTCHA_TEMPLATE_PATH env is not set using default")
        CAPTCHA_TEMPLATE_PATH = "/var/lib/crowdsec-haproxy-spoa-bouncer/html/captcha.html"
        if not utils.file_exist(CAPTCHA_TEMPLATE_PATH) then
            runtime.logger.error("Default captcha template not found at " .. CAPTCHA_TEMPLATE_PATH)
            return
        end
    end

    runtime.captcha = NewTemplate(CAPTCHA_TEMPLATE_PATH)
    runtime.logger.info("lua modules initialised")
end

-- Helper function to get a transaction variable
-- @param txn the transaction https://www.arpalert.org/src/haproxy-lua-api/2.9/index.html#txn-class
-- @param key the key to get
-- @return the value of the key or an empty string
local function get_txn_var(txn, key)
    local var = txn:get_var("txn."..key)
    if var == nil then
        return ""
    end
    return var
end

-- AppSec challenge bodies can exceed the 64KB SPOE frame limit.
-- In the shipped haproxy-*.cfg examples, challenge responses are therefore served
-- by routing the request to the bouncer's HTTP challenge backend
-- (see /crowdsec-challenge/ and challenge_http_listen).
-- unlike SPOE variables and isn't subject to their size limit.
-- @param txn the transaction
-- @return nil
function runtime.CollectChunk(txn)
    local chunk = get_txn_var(txn, "crowdsec.challenge_chunk")
    local buf = txn:get_priv()
    if buf == nil then
        buf = {}
    end
    table.insert(buf, chunk)
    txn:set_priv(buf)
end

-- Render the remediation page
-- @param txn the transaction https://www.arpalert.org/src/haproxy-lua-api/2.9/index.html#txn-class
-- @return nil
function runtime.Handle(txn)
    local remediation = get_txn_var(txn, "crowdsec.remediation")
    local reply = txn:reply({ status = 403, body = "" })
    
    if remediation == "" then
        runtime.logger.error("No remediation found")
        return
    end

    -- Always disable cache
    reply:add_header("cache-control", "no-cache")
    reply:add_header("cache-control", "no-store")

    if remediation == "allow" then
        runtime.logger.warning("Lua handler called for 'allow' remediation - this should not happen with native redirects")
        return
    end

    if remediation == "challenge" then
        runtime.logger.error("Lua handler called for 'challenge' remediation - configure HAProxy to route to the bouncer HTTP challenge backend instead")
        return
    end

        -- Body was fetched in chunks by runtime.CollectChunk (see the fetch loop
        -- in the haproxy-*.cfg examples) and accumulated on transaction-private
        -- storage since it can be far larger than a single SPOE variable allows.
        local chunks = txn:get_priv()
        if chunks ~= nil then
            reply:set_body(table.concat(chunks))
        else
            reply:set_body("")
        end

        -- Every header AppSec returned is forwarded as-is (one "Name: value"
        -- per line), rather than singling out a fixed set of header names.
        local headers = get_txn_var(txn, "crowdsec.challenge_headers")
        if headers ~= "" then
            for _, line in ipairs(utils.split(headers, "\n")) do
                local name, value = line:match("^([^:]+):%s*(.*)$")
                if name ~= nil then
                    reply:add_header(name, value)
                end
            end
        end

        local cookies = get_txn_var(txn, "crowdsec.challenge_cookies")
        if cookies ~= "" then
            for _, cookie in ipairs(utils.split(cookies, "\n")) do
                reply:add_header("Set-Cookie", cookie)
            end
        end

        reply:add_header("Content-Length", #reply.body)
        txn:done(reply)
        return
    end

    if remediation == "captcha" then
        reply:set_status(200)
        reply:set_body(runtime.captcha.render({
            ["captcha_site_key"]=get_txn_var(txn, "crowdsec.captcha_site_key"),
            ["captcha_frontend_key"]=get_txn_var(txn, "crowdsec.captcha_frontend_key"),
            ["captcha_frontend_js"]=get_txn_var(txn, "crowdsec.captcha_frontend_js"),
        }))
        -- Note: Cookie management is now handled by HAProxy via http-after-response rules
        -- using the captcha_status and captcha_cookie variables set by the SPOA bouncer
    end

    if remediation == "ban" then
        reply:set_body(runtime.ban.render({
            ["contact_us_url"]=get_txn_var(txn, "crowdsec.contact_us_url"),
        }))
    end

    local hdr = txn.http:req_get_headers()
    if hdr ~= nil and utils.accept_html(hdr) == false then
        reply:set_body("Forbidden")
        reply:add_header("Content-Type", "text/plain")
    else
        reply:add_header("Content-Type", "text/html")
    end
    reply:add_header("Content-Length", #reply.body)
    txn:done(reply)
end

-- Registers
core.register_init(init)
core.register_action("crowdsec_handle", {"http-req"}, runtime.Handle)
core.register_action("crowdsec_collect_chunk", {"http-req"}, runtime.CollectChunk)
