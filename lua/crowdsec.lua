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
        local redirect_uri = get_txn_var(txn, "crowdsec.redirect")
        if redirect_uri ~= "" then
            reply:set_status(302)
            reply:add_header("Location", redirect_uri)
        else
            return
        end
    end

    if remediation == "captcha" then
        reply:set_status(200)
        reply:set_body(runtime.captcha.render({
            ["captcha_site_key"]=get_txn_var(txn, "crowdsec.captcha_site_key"),
            ["captcha_frontend_key"]=get_txn_var(txn, "crowdsec.captcha_frontend_key"),
            ["captcha_frontend_js"]=get_txn_var(txn, "crowdsec.captcha_frontend_js"),
        }))
        local cookie = get_txn_var(txn, "crowdsec.captcha_cookie")
        if cookie ~= "" then
            reply:add_header("Set-Cookie", cookie)
        end
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
