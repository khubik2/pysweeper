# BaryonSweeper - a JigKick internal service tool emulator

## How-to
To restore your PSP, follow a simple instruction: 
1. Get neccessary hardware to make a probe: 
    - a USB to TTL converter;
    - a 1n4148 diode; 
    - a 10kOhm resistor; 
    - a sacrificial battery you can rip the female connector from (or a way to substitute it)
    - of course, soldering equipment. 
2. Build your probe - one-wire UART (aka K-line) adapter. You can omit an external battery if you power your PSP with a DC charger. Be aware that adapter's power output alone is not sufficient to power the PSP.![Yoti's_schematic](https://user-images.githubusercontent.com/82090925/129186282-6d036e88-fab3-4fac-9b2a-7ac2bf7f9628.png) 
3. Create a Magic Memory Stick compatible with PSP-3000. You need to use either an official JigKick MS clone or balika011's DDCv9 - you can create both with my tool (https://github.com/khubik2/JigKick-Media-Creator)
4. Insert your memory stick and connect your adapter to computer running the emulator, select the COM port of your adapter and start the service.
5. Connect your probe to PSP's battery terminals. If done right, it should take one or two seconds for PSP to enter recovery mode and boot from MS. 

## Compatibility list
| Model (last digit does not matter) | DATE CODE                                  | Is compatible?                         |
|------------------------------------|--------------------------------------------|----------------------------------------|
| PSP-1000                           | Any                                        | Supported, any magic MS                |
| PSP-2000                           | Any besides 8C                             | Supported, any magic MS                |
| PSP-2000                           | 8C                                         | Supported, only JigKick clone or DDCv9 |
| PSP-3000                           | 8C 8D 9A 9B and some 9C                    | Supported, only JigKick clone or DDCv9 |
| PSP-3000                           | some 9C; 9D, any code starting with 0 or 1 | Not supported                          |
| PSPgo  (N1000)                     | Any                                        | Not supported                          |
| PSP Steet (E1000)                  | Any                                        | Not supported                          |

## About
- M4j0r - Syscon Voltage Fault Injection glitch help
- Wildcard - Syscon glitching and dumping
- Sean Shablack aka Kyp40 aka FBIsoBOT - Syscon glitching and dumping, simplest one wire UART adapter schematic ever
- Proxima - Firmware reverse engineering, battery authentication response generator script
- khubik - Emulator code, GUI design, authentication script porting
- dogecore - Authentication script porting, GUI code, C# emulator threading fix
- Mathieu Hervais - decrypt-sp & decrypt-OS2 homebrew code
- SSL/Zerotolerance - re-encryption for Math's homebrews
- zecoxao - decrypt-sp & decrypt-os2 PC ports, boards supply, authentication script porting help
- Yoti - decrypt-sp improvements, MSID Dumper, contribution to PSPx.ru's 3000 series JigKick hacking thread, PSP 3000 supplier (<3), PSP 3000 unbrick PoC
- ErikPshat - Useful intel about JigKick, PSPx.ru's 3000 series JigKick hacking thread contribution, creation of functional JigKick memcard clone from original dump, userguides for MSID dumping and JigKick memory card creation
- Boryan, lport3, dx3d and many others from PSPx.ru's 3000 JigKick hacking thread - battery communication dumps and protocol reversal, one wire UART adapter schematics and more!
- lolivera - PSP 3000 unbrick PoC, TA-095 testing
- 预见 (zakezzzz) - TA-092 testing
- dee008 - Portable PSP battery controller emulator, PSP Street K-line pin location
- Wr0zen - PSPgo boards donation
- VrOdin - PSPgo tracing
