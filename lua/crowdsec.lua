package.path = package.path .. ";./?.lua"

local utils = require "utils"

local captcha = {
    template = ""
}

function captcha.New(path)
    local self = {}
    self.template = utils.read_file(path)
    return self
end

local ban = {
    template = ""
}

function ban.New(path)
    local self = {}
    self.template = utils.read_file(path)
    return self
end

local runtime = {}

-- Called after the configuration is parsed.
-- Loads the configuration
local function init()
    ban_template_path = os.getenv("CROWDSEC_BAN_TEMPLATE_PATH")
    captcha_template_path = os.getenv("CROWDSEC_CAPTCHA_TEMPLATE_PATH")

    runtime.captcha = captcha.New(captcha_template_path)
    runtime.ban = ban.New(ban_template_path)
end

-- Registers
core.register_init(init)