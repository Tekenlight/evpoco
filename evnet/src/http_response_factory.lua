local function new_request(request_instance)
	local response = platform.new_response();
	return response;
end

return {
	new = new_response
};
