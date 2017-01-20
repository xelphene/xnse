
local http = require('http')
local shortport = require('shortport')
local stdnse = require('stdnse')

categories = { "default", "safe", "vuln" }
author = "Steve Benson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
dependencies = {"http-enum"}

portrule = shortport.http

local session_cookie_patterns = {
	'PHPSESSID',
	'[Ss][Ee][Ss][Ss][Ii][Oo][Nn][Ii][Dd]'
}

local is_session_cookie = function(cookieName)
	for _, pattern in ipairs(session_cookie_patterns) do
		if string.find(cookieName, pattern) then
			return true
		end
	end
	return false
end

local check_path = function(host, port, path)
	stdnse.debug1("start check of %s %s %s", host.ip, port.number, path)
	local path_issues = stdnse.output_table()
	local resp = http.get(host, port, path)

	for _,cookie in ipairs(resp.cookies) do
		stdnse.debug1('  cookie: %s', cookie.name)
		local issues = stdnse.output_table()
		if is_session_cookie(cookie.name) then
			stdnse.debug1('    IS a session cookie')
			if port.service=='https' and not cookie.secure then
				stdnse.debug1('    * no secure flag and https')
				issues[#issues+1] = 'secure flag not set and HTTPS in use'
			end
			if not cookie.httponly then
				stdnse.debug1('    * no httponly')
				issues[#issues+1] = 'httponly flag not set'
			end
		end
		
		if #issues>0 then
			path_issues[cookie.name] = issues
		end
			
	end

	stdnse.debug1("end check of %s %s %s : %d issues found", host.ip, port.number, path, #path_issues)
	if #path_issues>0 then
		return path_issues
	else
		return nil
	end
end

action = function(host, port)
	local all_issues = stdnse.output_table()

	all_issues['/'] = check_path(host, port, '/')

	-- check all interesting paths found by http-enum.nse if it was run
	local all_pages = stdnse.registry_get({host.ip, 'www', port.number, 'all_pages'})
	if all_pages then
		for _,path in ipairs(all_pages) do
			all_issues[path] = check_path(host, port, path)
		end
	end

	if #all_issues>0 then
		return all_issues
	else
		return nil
	end
	
end
