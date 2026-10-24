local utils = require "utils"

local template = {}

function template.compile(template_str, args)

    -- Single pass: a value is never searched for further "{{...}}" markers, and a function is used as
    -- replacement so that "%" in a value (e.g. in a URL or attribute) is inserted literally instead of
    -- being interpreted as a capture reference. Unknown markers (e.g. "{{ if ... }}") are left untouched.
    template_str = template_str:gsub("{{([%w_]+)}}", function(name)
        local value = args[name]
        if value == nil then
            return nil
        end
        return tostring(value)
    end)

    return findIfStatements(template_str, args)
end

-- This function finds if statements in the template and removes the lines that are not needed
-- BEAWARE nested if statements are not currently supported
function findIfStatements(inputString, args)
    -- Split the input string into lines
    local lines = {}
    for line in inputString:gmatch("[^\r\n]+") do
        table.insert(lines, line)
    end
    local finalLines = {}
    toAdd = true
    for _, line in ipairs(lines) do
        local trimLine = utils.trim(line)
        if utils.starts_with(trimLine, "{{ if") then
            local elements = utils.split(trimLine, " ")
            local comparee = ""
            local comparer = ""
            local against = ""
            for _, el in ipairs(elements) do
                if el == "{{" or el == "if" or el == "}}" or el == "then" then
                    goto con
                end
                if comparee ~= "" and comparer ~= "" and against ~= "" then
                    break
                end
                if comparee == "" then
                    for k, v in pairs(args) do
                        if el == k then
                            comparee = v
                            goto con
                        end
                    end
                end
                if comparer == "" then
                    if el == "==" or el == "!=" then
                        comparer = el 
                        goto con
                    end
                end
                if comparee ~= "" and comparer ~= "" then
                    against = el:match('^"(.*)"$') or el
                end
                ::con::
            end
            if comparer == "==" then
                if comparee ~= against then
                    toAdd = false
                end
            end
            if comparer == "!=" then
                if comparee == against then
                    toAdd = false
                end
            end
            goto continue
        end
        if utils.starts_with(trimLine, "{{ else") then
            toAdd = not toAdd
            goto continue
        end
        if utils.starts_with(trimLine, "{{ end") then
            toAdd = true
            goto continue
        end
        if toAdd then
            table.insert(finalLines, line)
        end
        ::continue::
    end

    return table.concat(finalLines, "\n")
end

return template