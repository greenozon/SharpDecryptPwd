using System;
using SharpDecryptPwd.Commands;
using System.Collections.Generic;

namespace SharpDecryptPwd.Domain
{
    public class CommandCollection
    {
        public bool ExecuteCommand(string commandName, ArgumentParserContent arguments, Dictionary<string, Func<ICommand>> _availableCommands)
        {
            bool commandWasFound = false;
            if (_availableCommands.ContainsKey(commandName))
            {
                var command = _availableCommands[commandName].Invoke();

                command.DecryptPwd(arguments);

                commandWasFound = true;
            }
            return commandWasFound;
        }
    }
}
