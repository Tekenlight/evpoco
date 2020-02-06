local function new_request(request_instance)
	local req = platform.new_request();
	return req;
end

return {
	new = new_request;
};
