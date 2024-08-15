# BaryonSweeper - a JigKick internal service tool emulator

## How-to
You can watch the video or follow a text instruction below.
[![Video Thumbnail](http://img.youtube.com/vi/ZiyRU0H7CU8/0.jpg)](http://www.youtube.com/watch?v=ZiyRU0H7CU8 "PSP-3000 Unbrick Guide")

To restore your monoblock PSP (1000-2000-3000), follow a simple instruction: 
1. Get neccessary hardware to make a probe: 
    - a USB to TTL converter;
    - a 1n4148 diode; 
    - a 10kOhm resistor (not required); 
    - a way to connect to battery contacts (anything from loose wires to connector from a sacrificial battery)
    - soldering equipment or breadboard with jumpers
2. Build your probe - one-wire UART (aka K-line) adapter. You can omit an external battery if you power your PSP with a DC charger. Be aware that adapter's power output alone is not sufficient to power the PSP. You can also omit 10kOhm resistor.
![Yoti's_schematic](https://user-images.githubusercontent.com/82090925/129186282-6d036e88-fab3-4fac-9b2a-7ac2bf7f9628.png)
3. Create a Magic Memory Stick compatible with PSP-3000. JigKick Media Creator is **OBSOLETE**. Please use [Despertar Del Cementerio v10](https://github.com/PSP-Archive/ARK-4/releases/), brought to you by Davee and all the heroes from the d__ARK__ side. [Instructions](https://wololo.net/2024/04/20/release-new-cipl-and-despertar-del-cementerio-v10-for-every-psp/)
4. To start the emulator, install necessary pip packages: `pycryptodome`, `tk` and `pyserial`./
5. Insert your memory stick and connect your adapter to computer running the emulator, select the COM port of your adapter and start the service.
6. Connect your probe to PSP's battery terminals. If done right, it should take one or two seconds for PSP to enter recovery mode and boot from MS.
   
To restore your PSP Street, reuse the hardware assembly from steps 1-2. 
Instead of connecting your hardware assembly to PSP battery terminals, wire it to a Mini-USB male jack.
Connect the hardware assembly to your PSP, insert the recovery medium, start Baryon Sweeper. Cold boot your PSP, but **hold both shoulder buttons, D-Pad Left and Circle** as you flick the power switch. 
![Yoti's schematic, modified](https://github.com/user-attachments/assets/0d80cb8f-d2e0-42c8-9ee2-c789f4692f82)

To restore your PSPgo, follow the wiring diagram to create the hardware assembly from a PSPgo data cable.
It does involve soldering to bare connector pins that haven't been broken out (and potentially desoldering the connector from the breakout board and relocating the pins, if your cable doesn't have them in neccessary places)
![PSPgo schematic](https://github.com/user-attachments/assets/3e7a5df9-0837-4502-9997-49df0f25354f)

## Compatibility
Baryon Sweeper is compatible with all consumer PSP hardware revisions.
To create a compatible recovery medium, please use [Despertar Del Cementerio v10](https://github.com/PSP-Archive/ARK-4/releases/), brought to you by Davee and all the heroes from the d__ARK__ side. [Instructions](https://wololo.net/2024/04/20/release-new-cipl-and-despertar-del-cementerio-v10-for-every-psp/)

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
- balika077 - DDCv9
- dee008 - Portable PSP battery controller emulator, PSP Street K-line pin location
- Wr0zen - PSPgo boards donation
- VrOdin - PSPgo tracing
- Davee - Aiserigh, syscon hardware hacking 
- Acid_Snake, krazynez, [all the contributors](https://github.com/PSP-Archive/ARK-4/graphs/contributors) - ARK-4 and DDCv10
- The_Zett - DDCv10 recovery media creation guide
