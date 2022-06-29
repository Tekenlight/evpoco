

platform.ev_dbg_pthread_self("init_async_task.lua");
print(debug.getinfo(1).source, debug.getinfo(1).currentline);

platform.async_run_lua_script("async_task.lua", "hello", "world");
--platform.ev_dbg_pthread_self("init_async_task.lua");
print(debug.getinfo(1).source, debug.getinfo(1).currentline);
print(debug.getinfo(1).source, debug.getinfo(1).currentline);
platform.ev_hibernate(2);

print(debug.getinfo(1).source, debug.getinfo(1).currentline);

