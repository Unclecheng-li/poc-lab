-- ============================================================================
-- php2shell — OpenResty / Nginx Lua WAF Rules
-- CVE-2026-109618 / CVE-2026-109619
--
-- Drop this into your OpenResty access_by_lua_block or reference it via
-- access_by_lua_file. Blocks the primary php2shell attack vector at the
-- reverse proxy layer before requests reach PHP.
--
-- Author: Qi Deng (@ikow)
-- Reference: https://github.com/ikow/php2shell-poc
-- ============================================================================

local _M = {}

-- Check if request is a multipart POST
local function is_multipart_post()
    if ngx.req.get_method() ~= "POST" then
        return false
    end
    local ct = ngx.req.get_headers()["content-type"]
    if not ct then
        return false
    end
    return ct:find("multipart/form%-data", 1, false) ~= nil
end

-- Read request body (up to limit)
local function get_body(max_size)
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        -- body might be in a temp file if too large
        local file = ngx.req.get_body_file()
        if file then
            local fh = io.open(file, "r")
            if fh then
                body = fh:read(max_size or 65536)
                fh:close()
            end
        end
    end
    return body
end

function _M.check(opts)
    opts = opts or {}
    local max_body_read = opts.max_body_read or 65536  -- 64KB default
    local log_only = opts.log_only or false

    if not is_multipart_post() then
        return  -- not a multipart POST, skip
    end

    local body = get_body(max_body_read)
    if not body then
        return  -- no body to inspect
    end

    -- Rule 1: Block PHP_SESSION_UPLOAD_PROGRESS
    -- Primary trigger for both CVEs. Near-zero legitimate use.
    if body:find("PHP_SESSION_UPLOAD_PROGRESS", 1, true) then
        ngx.log(ngx.WARN,
            "php2shell: blocked PHP_SESSION_UPLOAD_PROGRESS from ",
            ngx.var.remote_addr, " uri=", ngx.var.request_uri)

        if not log_only then
            ngx.status = 403
            ngx.header["X-Blocked-By"] = "php2shell-detection"
            ngx.say("Forbidden")
            return ngx.exit(403)
        end
    end

    -- Rule 2: Detect PHPSESSID in POST body (session fixation)
    -- Normal browsers send this as a Cookie, never as a form field.
    if body:find('name="PHPSESSID"', 1, true) or
       body:find("name=PHPSESSID", 1, true) then
        ngx.log(ngx.WARN,
            "php2shell: PHPSESSID in POST body from ",
            ngx.var.remote_addr, " uri=", ngx.var.request_uri)

        -- Alert only — some legacy apps may do this legitimately
    end

    -- Rule 3: Detect PHP code in multipart body (session injection)
    if body:find("<?php", 1, true) or body:find("<?=", 1, true) then
        local has_filename = body:find('filename="', 1, true)
        if has_filename then
            ngx.log(ngx.WARN,
                "php2shell: PHP code in upload filename from ",
                ngx.var.remote_addr, " uri=", ngx.var.request_uri)

            if not log_only then
                ngx.status = 403
                ngx.header["X-Blocked-By"] = "php2shell-detection"
                ngx.say("Forbidden")
                return ngx.exit(403)
            end
        end
    end
end

return _M

-- ============================================================================
-- Usage in nginx.conf:
--
--   # Option A: Inline
--   access_by_lua_block {
--       require("php2shell").check()
--   }
--
--   # Option B: Log-only mode (detect without blocking)
--   access_by_lua_block {
--       require("php2shell").check({ log_only = true })
--   }
--
--   # Option C: Custom body inspection size
--   access_by_lua_block {
--       require("php2shell").check({ max_body_read = 131072 })  -- 128KB
--   }
-- ============================================================================
