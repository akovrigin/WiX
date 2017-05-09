Sub AddException()
	Const NET_FW_PROFILE_DOMAIN = 0
	Const NET_FW_PROFILE_STANDARD = 1
	Const NET_FW_SCOPE_ALL = 0
	Const NET_FW_IP_VERSION_ANY = 2
	Const NET_FW_IP_PROTOCOL_TCP = 6

	Dim folder
	folder = Session.Property("ProcessingServerFolder")

	' allow processing server

	Dim app
	Set app = CreateObject("HNetCfg.FwAuthorizedApplication")
	app.ProcessImageFileName = folder + "processingserver.exe"
	app.Name = "MFCOM TimeGuard Processing Server"
	app.Scope = NET_FW_SCOPE_ALL
	app.IpVersion = NET_FW_IP_VERSION_ANY
	app.Enabled = True

	Dim fwMgr
	Set fwMgr = CreateObject("HNetCfg.FwMgr")

	Dim profile
	Set profile = fwMgr.LocalPolicy.CurrentProfile

	' allow web server

	On Error Resume Next
	profile.AuthorizedApplications.Add app

	Dim port
	Set port = CreateObject("HNetCfg.FWOpenPort")

	port.Name = "HTTP"
	port.Protocol = NET_FW_IP_PROTOCOL_TCP
	port.Port = 80
	port.Scope = NET_FW_SCOPE_ALL
	port.Enabled = True

	profile.GloballyOpenPorts.Add port
End Sub