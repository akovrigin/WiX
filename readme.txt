“Time guard” is a solution that includes client and server installations. Both of them were created with WiX toolset and localized on English and Russian. To realize some complex actions, which cannot be realized by WiX, it was developed “Custom Action” on C#.net (DLL) that was executed from installer.  To automatically build the project, prepare the file structure and third party libraries were used MSBuild.

Server side components: 
WebUI (ASP.NET WebForms), Processing server (Windows service, C#), Database (MSSQL)

Client side components:
Statistics collection server (Windows service, C++), 

In the installers were realized next possibilities:

1.	Prerequisites
1.1.	Set up Upgrade possibility for subsequent installers
1.2.	Check if MSSQL is installed and it’s version 2008 or higher 
1.3.	Check if IIS is installed and it’s version is 6 or higher
1.4.	Check if .net framework 4.0 is installed 
1.5.	Check if Windows version is XP or later
1.6.	Get info from computer (computer name, system drive, SQL server instances, IP-address, etc.)
1.7.	Get info from user with dialogs (login and password, license code)
1.8.	Connect to license service (on our server in internet), check license code (and activate license on our server), get and store user key to DB
1.9.	Create windows user
1.10.	Grand rights for user on ASP.NET temporary folder
1.11.	Only for client installer: Install “VCRedist” (Visual C++ 2010 x86)
2.	WebUI (ASP.NET WebForms)
2.1.	Configure IIS (.net version, app pool, virtual directory)
2.2.	Copy files to virtual directory
2.3.	Modify web.config with user data
2.4.	Encode web.config to protect user  data
3.	Processing server (windows service)
3.1.	Set Registry entries with system data
3.2.	Modify “config” file (XML) with user data (VB-script)
3.3.	Set firewall exception (VB-script)
3.4.	Create folder in programs and shortcut
3.5.	Copy files to app folder
3.6.	Start the windows service
4.	Database (MSSQL)
4.1.	Create login, user
4.2.	Create new DB if there is no DB
4.3.	Update DB structure with patches if there is an used  one
4.4.	Insert preset application data
