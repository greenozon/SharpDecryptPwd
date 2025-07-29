using System;
using System.Reflection;
using SharpDecryptPwd.Domain;
using SharpDecryptPwd.Helpers;
using SharpDecryptPwd.Commands;
using System.Collections.Generic;

namespace SharpDecryptPwd
{
    class Program
    {
        static string FileName = Assembly.GetExecutingAssembly().GetName().Name;

        /// <summary>
        /// Add new feature here
        /// </summary>
        private static Dictionary<string, Func<ICommand>> AddDictionary()
        {
            Dictionary<string, Func<ICommand>> _availableCommands = new()
            {
                { Chrome.CommandName,       () => new Chrome() },
                { FileZilla.CommandName,    () => new FileZilla() },
                { Foxmail.CommandName,      () => new Foxmail() },
                { Navicat.CommandName,      () => new Navicat() },
                { RDCMan.CommandName,       () => new RDCMan() },
                { Xmanager.CommandName,     () => new Xmanager() },
                { TortoiseSVN.CommandName,  () => new TortoiseSVN() },
                { WinSCP.CommandName,       () => new WinSCP() },
                { Sunlogin.CommandName,     () => new Sunlogin() }
            };

            return _availableCommands;
        }

        /// <summary>
        /// Entry Point
        /// </summary>
        private static void MainExecute(string commandName, ArgumentParserContent parsedArgs)
        {
            Info.ShowLogo();

            try
            {
                Writer.Line($"------------------ {commandName} ------------------\r\n");
                var commandFound = new CommandCollection().ExecuteCommand(commandName, parsedArgs, AddDictionary());

                //If the command is not found, output the help
                if (commandFound == false)
                    Info.ShowUsage();
            }
            catch (Exception e)
            {
                Console.WriteLine($"\r\n[!] Unhandled {FileName} exception:\r\n");
                Console.WriteLine(e.Message);
            }
        }

        static void Main(string[] args)
        {
            var parsed = ArgumentParser.Parse(args);
            if (parsed.ParsedOk)
            {
                var commandName = args.Length != 0 ? args[0] : "";
                MainExecute(commandName.ToLower(), parsed.Arguments);
            }
            Info.ShowLogo();
            Info.ShowUsage();
        }
    }
}
