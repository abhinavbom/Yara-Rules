
//PlugX APT Malware

rule PlugXXOR
{
meta:
description = "rule for PlugX XOR Routine"
ref1 = "7048add2873b08a9693a60135f978686"
strings:
$hex_string = { 05 ?? ?? 00 00 8A D8 2A DC 89 45 FC 32 5D FE 81 E9 ?? ?? 00 00 2A 5D FF 89 4D F8 32 D9 2A DD 32 5D FA 2A 5D FB 32 1C 37 88 1E 46 4A 75 D2 5F 5B }
condition:
all of them
}
 
