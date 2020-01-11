local function new_request(request_instance)
	local response = context.new_response();
	return response;
end

return {
	new = new_response
};
