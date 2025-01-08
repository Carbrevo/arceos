define sid
si
if $argc == 1
   disass/r $pc-$arg0, +0x50
else
   disass/r $pc,+0x50
end
end
	
define ii 
if $argc == 1
   disass/r $arg0, +0x50
else
   disass/r $pc,+0x50
end
end

define dd 
if $argc == 2 
   p/z ((long*)$arg0)@$arg1
else if $argc == 1
   p/z *(long*)$arg0)
end
end
