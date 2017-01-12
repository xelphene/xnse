local nmap = require "nmap"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"

-- this code depends on nmap adding an "extensions" field to the SSL Cert.
-- this was only added to nmap 9 days ago:
-- https://github.com/nmap/nmap/blob/master/nse_ssl_cert.cc

description = [[
Test
]]

author = "Steve Benson"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

portrule = function(host, port)
	return shortport.ssl(host, port) or sslcert.isPortSupported(port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

action = function(host, port)
	local ok, cert = sslcert.getCertificate(host, port)
	nmap.log_write("stdout","TEST")
	nmap.log_write("stdout",cert.asdf)
	if ok then
		for k,v in pairs(cert.issuer) do
			nmap.log_write("stdout", k)
		end
		return "Hello World"
	else
		return "Unable to get certificate"
	end
end
