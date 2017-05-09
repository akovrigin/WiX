Sub GetIpAddressFromConfig
       strXmlConfigFile = Session.Property("XMLCONFIG")
       Dim objDoc, appSettingsElement
       Set objDoc = CreateObject("msxml2.DOMDocument.3.0")
       objDoc.Load(strXmlConfigFile)
       Set appSettingsElement = objDoc.SelectSingleNode("//configuration/appSettings/add[@key='IpAddress']")
       If Not IsNull(appSettingsElement) AND Not (appSettingsElement Is Nothing) Then
         Session.Property("CURRENT_IP_ADDRESS") = appSettingsElement.Attributes.getNamedItem("value").Text
       End If
       Set objDoc = Nothing
End Sub

Sub GetWinUserNameFromWebConfig
       strXmlConfigFile = Session.Property("WEBXMLCONFIG")
       Dim objDoc, appSettingsElement, userName, password
       Set objDoc = CreateObject("msxml2.DOMDocument.3.0")
       objDoc.Load(strXmlConfigFile)
       Set appSettingsElement = objDoc.SelectSingleNode("//configuration/system.web/identity")
       If Not IsNull(appSettingsElement) AND Not (appSettingsElement Is Nothing) Then
            Set userName = appSettingsElement.Attributes.getNamedItem("userName")
            Set password = appSettingsElement.Attributes.getNamedItem("password")
            If Not IsNull(userName) AND Not (userName Is Nothing) AND Not IsNull(password) AND Not (password Is Nothing) Then
                Session.Property("USER_NAME") = userName.Text
                Session.Property("USER_PASSWORD") = password.Text
                Session.Property("WINDOWS_ACCOUNT_IS_NOT_SET") = userName.Text
            End If
       End If
       Set objDoc = Nothing
End Sub