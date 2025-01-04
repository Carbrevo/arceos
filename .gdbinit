define sid
si
if $argc == 1
   disass $pc-$arg0, +0x50
else
   disass $pc,+0x50
end
end
	
