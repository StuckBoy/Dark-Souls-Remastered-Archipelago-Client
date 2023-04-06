# Dark-Souls-Remastered-Archipelago-Client

Dark Souls Remastered client made for Archipelago multiworld randomizer. See [archipelago.gg](https://archipelago.gg/)

## How to install

- Download the lastest version available [here](https://github.com/Marechal-L/Dark-Souls-III-Archipelago-client/releases).
- Extract d8input.dll into your Dark Souls Remastered install folder
- Generate a game using Archipelago
- Launch the game through Steam

## Commands
- All client commands start with "/" and archipelago commands start with "!" :
	- /help : Prints this help message.
	- !help : to retrieve all archipelago commands
	- /connect {SERVER_IP}:{SERVER_PORT} {USERNAME} [password:{PASSWORD}]  
	Connect by entering SERVER_IP, SERVER_PORT and USERNAME. You can additionaly add a PASSWORD if requested by the server.
	
## Troubleshoots
- The provided dll requires other dependencies so if you encounter a crash when launching the game,
installing the latest Microsoft Visual C++ Redistributable version could fix it : https://aka.ms/vs/17/release/vc_redist.x64.exe.
- The Windows console tends to freeze preventing you from sending or receiving any items. You must Alt+Tab, click on the console and press enter to refresh it.

## Credits
https://github.com/LukeYui/DS3-Item-Randomiser-OS by LukeYui  
https://github.com/black-sliver/apclientpp by black-sliver  
https://github.com/Marechal-L/Dark-Souls-III-Archipelago-client by Marechal-L

