global testTB : table[addr] of set[string] = table();
event http_header (c: connection, is_orig: bool, name: string, value: string)
{
    if(name=="USER-AGENT")
    {
        if(c$id$orig_h in testTB)
        {
            if(to_lower(value) !in testTB[c$id$orig_h])
            {
                add testTB[c$id$orig_h][to_lower(value)];
            }
        }
        else
        {
            testTB[c$id$orig_h]=set(to_lower(value));
        }
    }
}
event zeek_done()
{
	for (Addr, Set in testTB)
	{
		if(|Set|>=3)
		{
			print fmt("%s is a proxy",Addr);
		}
	}
}
