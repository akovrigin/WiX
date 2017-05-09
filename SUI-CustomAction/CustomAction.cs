// --------------------------------------------------------------------
// Copyright (C) 2003-2011 The Mechanical Frog Project
// http://www.mfcom.ru
// --------------------------------------------------------------------

using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web.Helpers;
using System.Windows.Forms;
using Mfcom.Cactus809.Core.BusinessObjects;
using Mfcom.Cactus809.Interprocess.Constants;
using Mfcom.Cactus809.LsRas.Access;
using Mfcom.Cactus809.ProcessingServer;
using Mfcom.Cactus809.ProcessingServer.Config;
using Microsoft.Deployment.WindowsInstaller;

namespace SUI_CustomAction
{
	public class CustomActions
	{
#if DEBUG
		private static bool IsDebugMode(Session Session)
		{
			return Session["LICENSE_KEY"] == "debug";
		}
#endif

        [CustomAction]
        [Obsolete("This code works, but useless for now. Maybe in the future...")]
        public static ActionResult AddFirewallException(Session S)
        {
            /* Так надо прописывать использование AddFirewallException
                         
            <InstallExecuteSequence>
                <Custom Action="AllowFirewallException" After="InstallFinalize">WINDOWS_FIREWALL_RULE = 1 AND NOT Installed</Custom>
            </InstallExecuteSequence>

            А так скрипт другой вариант установки правила AllowFirewallException.vbs
            
            <Product>
                <Binary Id="AllowFirEx" SourceFile="AllowFirewallException.vbs" />
	        	<CustomAction Id="AllowFirewallException" BinaryKey="AllowFirEx" VBScriptCall="AddException" HideTarget="yes" Impersonate="no" />
            </Product>
            */

            try
            {
                string folder = S["ProcessingServerFolder"];

                dynamic app = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwAuthorizedApplication"));

                app.ProcessImageFileName = folder + "processingserver.exe";
                app.Name = "MFCOM TimeGuard Processing Server";
                app.Scope = 0;
                app.IpVersion = 2;
                app.Enabled = true;

                dynamic fwallManager = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwMgr"));

                dynamic profile = fwallManager.LocalPolicy.CurrentProfile;
                profile.AuthorizedApplications.Add(app);

                dynamic port = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWOpenPort"));
                port.Name = "HTTP";
                port.Protocol = 6;
                port.Port = 80;
                port.Scope = 0;
                port.Enabled = true;

                profile.GloballyOpenPorts.Add(port);

                return ActionResult.Success;
            }
            catch(Exception ex)
            {
                S.Log(string.Format("Firewall Exception:{0}", ex.Message));
            }

            return ActionResult.Failure;
        }

	    /// <summary>
		/// Активация серверной лицензии
		/// </summary>
		/// <param name="Session"></param>
		/// <returns></returns>
		[CustomAction]
		public static ActionResult CheckLicense(Session Session)
		{
			//Для проверки на вирт-машине проверку лицензии не осуществляем
#if DEBUG
			if (IsDebugMode(Session))
				return ActionResult.Success;
#endif
			SaveToLog(Session, "Check License start");

			Session.Log("LSIS: " + Constants.LSRAS);

			var t = new Transmitter
			        {
			        	RasServerAddress = Constants.LSRAS,
			        	ServerPort = Constants.REGSRV_PORT,
			        	LicNum = Session["LICENSE_NUMBER"],
			        	Otk = Session["LICENSE_KEY"]
			        };

			int ret = t.Transmit();
			Session.Log("LSIS-RET: " + ret);

			if (0 != ret)
			{
				SaveToLog(Session, "License check failure. Return value " + ret);
				return ActionResult.Failure;
			}

			SaveToLog(Session, "License check successful");

			return ActionResult.Success;
		}

        [CustomAction]
        public static ActionResult SetXmlConfigFileName(Session Session)
        {
            //Sessison.Log("XXXXX_ProcessingServerFolder: " + Sessison["ProcessingServerFolder"]);
            //Sessison.Log("XXXXX_XMLCONFIG: " + Sessison["XMLCONFIG"]);
            //Sessison.Log("XXXXX_STORED_IP_ADDRESS: " + Sessison["STORED_IP_ADDRESS"]);
           
            string filename = Session["ProcessingServerFolder"] + "ProcessingServer.exe.config";

            if (File.Exists(filename))
            {
                Session["XMLCONFIG"] = filename;

                Session.Log("Old processing server config file found: " + filename);
            }
            else
            {
                Session.Log("Old processing server config file not found: " + filename);
            }

            filename = Session["dir_Cactus809_1"] + "web.config";

            if (File.Exists(filename))
            {
                Session["WEBXMLCONFIG"] = filename;

                Session.Log("Old web config file found: " + filename);
            }
            else
            {
                Session.Log("Old web config file not found: " + filename);
            }


            return ActionResult.Success;
        }

		[CustomAction]
		public static ActionResult TryToUpdate(Session Sess)
		{
			SaveToLog(Sess, "Going to update the license");

            //return ActionResult.Success;

			try
			{
				Transmitter t = new Transmitter
				{
					RasServerAddress = Constants.LSRAS,
					ServerPort = Constants.REGSRV_PORT,
					LicNum = String.Empty,
					Otk = String.Empty
				};

                Sess.Log("LSRAS: " + Constants.LSRAS);
                Sess.Log("REGSRV_PORT: " + Constants.REGSRV_PORT);

				int upd = t.Update();
				Sess.Log("LSUP: " + upd);

				if (upd != 0)
				{
					SaveToLog(Sess, "Update failure " + upd);
					return ActionResult.Failure;
				}
			}
			catch(Exception ex)
			{
                SaveToLog(Sess, ex.Message);
                return ActionResult.Failure;
            }

            SaveToLog(Sess, "Update successfull");

            return ActionResult.Success;
        }

		[CustomAction]
		public static ActionResult GetPort(Session S)
		{
			S["ProcessingPort"] = Constants.PROC_PORT.ToString();

			SaveToLog(S, "PROC_PORT is " + S["ProcessingPort"]);

			return ActionResult.Success;
		}

		[CustomAction]
		public static ActionResult GetInternalAddress(Session Session)
		{
			SaveToLog(Session, "Getting internal address");

			try
			{
				Session["InternalAddress"] =
					string.IsNullOrEmpty(Session["IP_ADDRESS"]) || string.IsNullOrEmpty(Session["IP_ADDRESS"].Trim())
						? NetworkInterfaceEnumerator.InternalAddress
						: Session["IP_ADDRESS"];

				return ActionResult.Success;
			}
			catch(Exception exc)
			{
				SaveToLog(Session, "Getting internal address failure. " + exc.Message);
				return ActionResult.Failure;
			}
		}

		[CustomAction]
		public static ActionResult SetDefaultIpAddress(Session Session)
		{
			try
			{
				SaveToLog(Session, "Set default statistics server ip address");

                SaveToLog(Session, "Original IP_ADDRESS in custom action is " + Session["IP_ADDRESS"]);
                SaveToLog(Session, "In registry STORED_IP_ADDRESS in custom action is " + Session["STORED_IP_ADDRESS"]);

                //STORED_IP_ADDRESS - адрес из реестра, сохраненный туда от переустановки предыдущей версии.
                //Он будет использоваться, если установка прервалась по какой-либо причине и установка новой версии запущена заново.

                if ((string.IsNullOrEmpty(Session["IP_ADDRESS"]) || string.IsNullOrEmpty(Session["IP_ADDRESS"].Trim()))
                    &&
                    (!string.IsNullOrEmpty(Session["STORED_IP_ADDRESS"]) && !string.IsNullOrEmpty(Session["STORED_IP_ADDRESS"].Trim()))
                    )
                {
                    Session["IP_ADDRESS"] = Session["STORED_IP_ADDRESS"];
                }

                //Если же нет никаких данных об адресе вообще, то попробуем узнать адрес сервака, на котором сейчас устанавливается программа

			    if (string.IsNullOrEmpty(Session["IP_ADDRESS"]) || string.IsNullOrEmpty(Session["IP_ADDRESS"].Trim()))
				    Session["IP_ADDRESS"] = NetworkInterfaceEnumerator.InternalAddress;

                SaveToLog(Session, "Set defaulst IP_ADDRESS in custom action to " + Session["IP_ADDRESS"]);

                SetDefaultMachineName(Session);

				return ActionResult.Success;
			}
			catch(Exception exc)
			{
				SaveToLog(Session, "Set default statistics server ip address failure");
				SaveToLog(Session, exc.Message);
				return ActionResult.Failure;
			}
		}

        public static ActionResult SetDefaultMachineName(Session Session)
        {
            try
            {
                SaveToLog(Session, "Set default statistics server machine name");

                SaveToLog(Session, "Original MACHINE_NAME in custom action is " + Session["MACHINE_NAME"]);
                SaveToLog(Session, "In registry MACHINE_NAME in custom action is " + Session["STORED_MACHINE_NAME"]);

                //STORED_IP_ADDRESS - адрес из реестра, сохраненный туда от переустановки предыдущей версии.
                //Он будет использоваться, если установка прервалась по какой-либо причине и установка новой версии запущена заново.

                if ((string.IsNullOrEmpty(Session["MACHINE_NAME"]) || string.IsNullOrEmpty(Session["MACHINE_NAME"].Trim()))
                    &&
                    (!string.IsNullOrEmpty(Session["STORED_MACHINE_NAME"]) && !string.IsNullOrEmpty(Session["STORED_MACHINE_NAME"].Trim()))
                    )
                {
                    Session["MACHINE_NAME"] = Session["STORED_MACHINE_NAME"];
                }

                //Если же нет никаких данных об адресе вообще, то попробуем узнать адрес сервака, на котором сейчас устанавливается программа

                if (string.IsNullOrEmpty(Session["MACHINE_NAME"]) || string.IsNullOrEmpty(Session["MACHINE_NAME"].Trim()))
                    Session["MACHINE_NAME"] = Environment.MachineName;

                SaveToLog(Session, "Set defaulst MACHINE_NAME in custom action to " + Session["MACHINE_NAME"]);

                Session["INSTANCE_NAME"] = Environment.MachineName;

                SaveToLog(Session, "Set defaulst INSTANCE_NAME in custom action to " + Session["INSTANCE_NAME"]);

                return ActionResult.Success;
            }
            catch (Exception exc)
            {
                SaveToLog(Session, "Set default statistics server machine name failure");
                SaveToLog(Session, exc.Message);
                return ActionResult.Failure;
            }
        }


		[CustomAction]
		public static ActionResult WritePasswordFile(Session Session)
		{
			SaveToLog(Session, "Password file saving started");

			if (Session["SAVE_PASSWORDS"] == "yes")
			{
				string fileName = Session["ProcessingServerFolder"] + "passwords.txt";

				Directory.CreateDirectory(Session["ProcessingServerFolder"]);

				SaveToLog(Session, "FileName: " + fileName);
				try
				{
					using(TextWriter tw = new StreamWriter(fileName))
					{
						tw.WriteLine("Windows account information");
						tw.WriteLine("Login " + Session["USER_NAME"]);
						tw.WriteLine("Password " + Session["USER_PASSWORD"]);
						tw.WriteLine();

						tw.WriteLine("Cactus account information");
						tw.WriteLine("Login " + Session["AUTHDATA_LOGIN"]);
						tw.WriteLine("Password " + Session["AUTHDATA_PASSWORD"]);
						tw.Close();
					}

					SaveToLog(Session, "Password file saved");

					ProcessStartInfo psi = new ProcessStartInfo(@"notepad.exe") {Arguments = fileName};
					if (Environment.OSVersion.Version.Major >= 6)
					{
						psi.UseShellExecute = true;
						psi.Verb = "runas";
					}

					// Case 2701
					if (Environment.OSVersion.Version.Major < 6)
					{
						Process p = new Process {StartInfo = psi};
						p.Start();

						SaveToLog(Session, "Password file opened");
					}
				}
				catch(Exception e)
				{
					SaveToLog(Session, "Error: " + e.Message);
				}
			}

			return ActionResult.Success;
		}

		/// <summary>
		/// Получение лицензии с сервера лицензий и запись ее в БД частного сервера
		/// </summary>
		/// <param name="Session"></param>
		/// <returns></returns>
		[CustomAction]
		public static ActionResult ActivateLicense(Session Session)
		{
			SaveToLog(Session, "Activation begins");

			string pckey = new PcKey().Key;

#if DEBUG
			if (!IsDebugMode(Session))
			{
#endif
				var rls = new RemoteLicenseStore(
					Constants.LSRAS,
					Constants.LSRAS_PORT,
					pckey);

				SaveToLog(Session, "RemoteLicenseStore obtained");

				var list = rls.Enumerate();

				SaveToLog(Session, "Licenses have been enumerated");

				if (list == null || list.Count == 0)
					return ActionResult.Failure;

				SaveToLog(Session, "Licenses aren't empty");

				Session["PcKey"] = pckey;

				RawLicense rsl = list[list.Count - 1];

				DateTime ed = rsl.ExpirationDate;

				Session["SL_Address"] = Session["IP_ADDRESS"];
				Session["SL_IsActive"] = rsl.IsActive? "1": "0";
				Session["SL_ExpirationDate"] = ed.Year + ed.Month.ToString().PadLeft(2, '0') + ed.Day.ToString().PadLeft(2, '0');
				Session["SL_KeyHash"] = rsl.KeyHash;
				Session["SL_Number"] = rsl.Number;
				Session["SL_Type"] = ((int)rsl.Type).ToString();

				foreach(RawProperty p in rsl.Properties)
				{
					if (p.Property == LicensePropertyType.Owner)
						Session["SL_PV1"] = p.Value;
					else if (p.Property == LicensePropertyType.Email)
						Session["SL_PV2"] = p.Value;
					else if (p.Property == LicensePropertyType.Organization)
						Session["SL_PV3"] = p.Value;
				}

				SaveToLog(Session, "Try to set up statistics server address");
				rls.SetLicenseAddress(Session["IP_ADDRESS"]);
				SaveToLog(Session, "Statistics server address has been successfully set");
#if DEBUG
			}
#endif
			string login = Session["AUTHDATA_LOGIN"].Trim();
			string password = Session["AUTHDATA_PASSWORD"].Trim();

			if (login == password || login.Length < 6 || password.Length < 6)
			{
				SaveToLog(Session, "Login or password has less than 6 symbols");
				return ActionResult.Failure;
			}

			//Ну че, сочинение что-ли тут писать собрались?
			if (login.Length > 500 || password.Length > 500)
			{
				SaveToLog(Session, "Login or password contains more than 500 symbols");
				return ActionResult.Failure;
			}

			Session["EncryptedLogin"] = GetHash(login);
			Session["PasswordHash"] = GetHash(password);

			SaveToLog(Session, "Get License all properties has been set");

			return ActionResult.Success;
		}

		[CustomAction]
		public static ActionResult CreateLogin(Session Session)
		{
			SaveToLog(Session, "Inside of CreateLogin");

			try
			{
				Session["MEGAHASH"] = Crypto.HashPassword(Session["AUTHDATA_PASSWORD"]);
			}
			catch(Exception ex)
			{
				SaveToLog(Session, ex.Message);
				throw;
			}

			return ActionResult.Success;
		}

		private static string GetHash(string Input)
		{
			SHA512 hashAlg = SHA512.Create();
			return Convert.ToBase64String(hashAlg.ComputeHash(Encoding.UTF8.GetBytes(Input)));
		}

		private static void SaveToLog(Session Session, string Text)
		{
//#if  DEBUG
            //#endif
            Session.Log("MFCOM_LOG: " + Text);
		}
	}
}