
local http = require('http')
local shortport = require('shortport')
local stdnse = require('stdnse')

categories = { "default", "safe", "vuln" }
author = "Steve Benson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
dependencies = {"http-enum"}

portrule = shortport.http

local sessionCookiePatterns = {
	'PHPSESSID',
	'ASPSESSIONID'
}

local isSessionCookie = function(cookieName)
	for _, pattern in ipairs(sessionCookiePatterns) do
		if string.find(cookieName, pattern) then
			return true
		end
	end
	return false
end

local check_path = function(host, port, path)
	stdnse.debug1("check_path: %s %s %s", host.ip, port.number, path)
	local path_issues = stdnse.output_table()
	local resp = http.get(host, port, path)

	for _,cookie in ipairs(resp.cookies) do
		stdnse.debug1('  %s', cookie.name)
		local issues = stdnse.output_table()
		if isSessionCookie(cookie.name) then
			stdnse.debug1('    IS a session cookie')
			if port.service=='https' and not cookie.secure then
				stdnse.debug1('    NO secure flag')
				issues[#issues+1] = 'Secure flag not set and HTTPS in use'
			end
			if not cookie.httponly then
				stdnse.debug1('    NO httponly')
				issues[#issues+1] = 'httponly flag not set'
			end
		end
		
		if #issues>0 then
			path_issues[cookie.name] = issues
		end
			
	end

	if #path_issues>0 then
		return path_issues
	else
		return nil
	end
end

action = function(host, port)
	local all_issues = stdnse.output_table()

	all_issues['/'] = check_path(host, port, '/')

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
