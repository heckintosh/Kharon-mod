from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .Utils.u import *

class ProcRunArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="command",
                cli_name="command",
                type=ParameterType.String,
                description="Command to execute",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Must supply command to execute")
            
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("command", self.command_line)
        self.add_arg("action", "run")

class ProcRunCommand(CommandBase):
    cmd = "proc-run"
    needs_admin = False
    help_cmd = 'proc-run -command [command]'
    description = \
    """
    Run a process directly

    Examples:
        run -command whoami.exe
        run -command HOSTNAME.exe
        run -command \"Get-Process -IncludeUserName\"

    Obs:
        This command behavior can be modified using:
            - "config -arg"  : to spoof the process createtion argument
            - "config -ppid" : to change parent process to spawn
            - "config -blockdlls" : to block non-microsoft dll for load in the process
            - "config -curdir" : to change current direct in the process information (dont change the execution path context) 
    """
    version = 1
    author = "@Oblivion"
    attackmapping = ["T1106"]
    argument_class = ProcRunArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        command = task.args.get_arg("command")
        task.args.add_arg("action", "run")
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            Success=True,
            DisplayParams=f"-command \"{command}\"",
            CommandName="proc"
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:

        RawResponse = bytes.fromhex(response)
        Psr = Parser(RawResponse, len(RawResponse))

        sub_id = int.from_bytes(Psr.Pad(1), byteorder="big")

        Output = Psr.Bytes();
        ProcID = Psr.Int32();
        TdID   = Psr.Int32();
        
        FinalOutput = f"[+] Process Created with ID: {ProcID} and Main Thread ID: {TdID}\n[+] Received {len(Output)} bytes from agent\n[+] Output:\n\n{Output.decode('utf-8')}"

        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
            TaskID=task.Task.ID,
            Response=FinalOutput
        ))

        return PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID,
            Success=True
        )

class ProcPwshArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="command",
                cli_name="command",
                type=ParameterType.String,
                description="Command to execute via powershell.exe",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Must supply command to execute")
            
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("command", self.command_line)
        self.add_arg("action", "pwsh")

class ProcPwshCommand(CommandBase):
    cmd = "proc-pwsh"
    needs_admin = False
    help_cmd = 'proc-pwsh -command [command]'
    description = \
    """
    Run a command via powershell.exe

    Examples:
        proc-pwsh -command ls

    Obs:
    This command behavior can be modified using:
        - "config -arg"  : to spoof the process createtion argument
        - "config -ppid" : to change parent process to spawn
        - "config -blockdlls" : to block non-microsoft dll for load in the process
        - "config -curdir" : to change current direct in the process information (dont change the execution path context) 
    """
    version = 1
    author = "@Oblivion"
    attackmapping = ["T1059", "T1059.001"]
    argument_class = ProcPwshArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        command = task.args.get_arg("command")
        task.args.add_arg("command", f"powershell.exe -c \"{command}\"")
        task.args.add_arg("action", "pwsh")
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            Success=True,
            DisplayParams=f"-command {command}",
            CommandName="proc"
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        
        RawResponse = bytes.fromhex(response)
        Psr = Parser(RawResponse, len(RawResponse))

        sub_id = int.from_bytes(Psr.Pad(1), byteorder="big")

        ProcID = Psr.Int32();
        TdID   = Psr.Int32();
        Output = Psr.Bytes();
        
        FinalOutput = f"[+] powershell.exe Created with ID: {ProcID} and Main Thread ID: {TdID}\n[+] Received {len(Output)} bytes from agent\n[+] Output:\n\n{Output.decode('cp850')}"

        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
            TaskID=task.Task.ID,
            Response=FinalOutput
        ))

        return PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID,
            Success=True
        )

class ProcListArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            raise ValueError("proc-list takes no arguments")
        self.add_arg("action", "list")

class ProcListCommand(CommandBase):
    cmd = "proc-list"
    needs_admin = False
    help_cmd = "proc-list"
    description = \
    """"
    List running processes with informations like:
        - Image Name
        - Image Path
        - Process ID
        - Parent ID
        - Handle Count
        - Session ID
        - User Token
        - Threads Quantity
        - Architecture
    """
    version = 1
    author = "@Oblivion"
    argument_class = ProcListArguments
    supported_ui_features = ["process_browser:list"]
    browser_script = BrowserScript(script_name="ps_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        task.args.add_arg("action", "list")
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            Success=True,
            DisplayParams="",
            CommandName="proc"
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        try:
            if not response:
                return PTTaskProcessResponseMessageResponse(
                    TaskID=task.Task.ID,
                    Success=True
                )
                
            RawResponse = bytes.fromhex(response)
            Psr = Parser(RawResponse, len(RawResponse))
            process_list = []
            mythic_process_list = []

            sub_id = int.from_bytes(Psr.Pad(1), byteorder="big")

            if sub_id == SB_PS_LIST:
                try:
                    while Psr.buffer and len(Psr.buffer) > 0:
                        process_info = {}
                        try:
                            ImagePath = Psr.Str()
                            ImageName = Psr.Wstr()
                            CommandLn = Psr.Wstr()
                            ProcessID = Psr.Int32()
                            ParentID  = Psr.Int32()
                            HandleCnt = Psr.Int32()
                            SessionID = Psr.Int32()
                            ThreadNbr = Psr.Int32()
                            TokenUser = Psr.Str()
                            Isx64     = Psr.Int32()

                            # Create process info for the response
                            process_info = {
                                "Image Name": ImageName,
                                "Image Path": ImagePath,
                                "Command Line": CommandLn,
                                "Process ID": ProcessID,
                                "Parent ID": ParentID,
                                "Handle Count": HandleCnt,
                                "Session ID": SessionID,
                                "User Token": TokenUser,
                                "Threads Quantity": ThreadNbr,
                                "Architecture": "x86" if Isx64 else "x64"
                            }
                            process_list.append(process_info)

                            mythic_process = MythicRPCProcessCreateData(
                                Host=task.Callback.Host,  
                                ProcessID=ProcessID,
                                ParentProcessID=ParentID,
                                Architecture="x86" if Isx64 else "x64",
                                Name=ImageName,
                                BinPath=ImagePath,
                                CommandLine=CommandLn,
                                User=TokenUser,
                                IntegrityLevel=SessionID
                            )
                            mythic_process_list.append(mythic_process)
                        except Exception as e:
                            continue

                    await SendMythicRPCProcessCreate(MythicRPCProcessesCreateMessage(
                        TaskID=task.Task.ID,
                        Processes=mythic_process_list
                    ))

                    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                        TaskID=task.Task.ID,
                        Response=json.dumps(process_list, indent=2, ensure_ascii=False).encode('utf-8')
                    ))
                except Exception as e:
                    raise ValueError(f"Error parsing process list: {str(e)}")
            else:
                RawData = Psr.Str()
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=RawData.encode('utf-8')
                ))

            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )
        except Exception as e:
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=f"Error processing response: {str(e)}".encode('utf-8')
            ))
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=str(e)
            )

class ProcKillArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                cli_name="pid",
                type=ParameterType.Number,
                description="Process ID to kill",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Must supply PID to kill")
            
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            try:
                pid = int(self.command_line)
                self.add_arg("pid", pid)
            except ValueError:
                raise ValueError("PID must be a number")
        self.add_arg("action", "kill")

class ProcKillCommand(CommandBase):
    cmd = "proc-kill"
    needs_admin = False
    help_cmd = 'proc-kill [pid]'
    description = "Kill a process by ID"
    version = 1
    author = "@Oblivion"
    attackmapping = ["T1057"]
    argument_class = ProcKillArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        pid = task.args.get_arg("pid")
        task.args.add_arg("action", "kill")
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            Success=True,
            DisplayParams=f"-pid {pid}",
            CommandName="proc"
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID,
            Success=True
        )

class ProcCmdArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="command",
                cli_name="command",
                type=ParameterType.String,
                description="Command to execute via cmd.exe",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
            raise ValueError("Must supply command to execute")

        # Handle JSON input
        if self.command_line.strip().startswith("{"):
            self.load_args_from_json_string(self.command_line)
            return

        # Initialize variables
        command_value = ""
        using_command_param = False

        # Split while preserving quoted strings
        parts = []
        current_part = []
        in_quote = False
        quote_char = None
        
        for char in self.command_line:
            if char in ('"', "'") and not in_quote:
                in_quote = True
                quote_char = char
            elif char == quote_char and in_quote:
                in_quote = False
                quote_char = None
            elif char == ' ' and not in_quote:
                if current_part:
                    parts.append(''.join(current_part))
                    current_part = []
            else:
                current_part.append(char)
        
        if current_part:
            parts.append(''.join(current_part))

        # Parse the parts
        i = 0
        while i < len(parts):
            part = parts[i]
            if part == "-command":
                if i + 1 < len(parts):
                    command_value = parts[i+1]
                    # Remove surrounding quotes if present
                    if (command_value.startswith('"') and command_value.endswith('"')) or \
                       (command_value.startswith("'") and command_value.endswith("'")):
                        command_value = command_value[1:-1]
                    using_command_param = True
                    i += 2
                else:
                    raise ValueError("No value provided after -command")
            else:
                if not using_command_param:
                    # Treat as direct command
                    command_value = ' '.join(parts[i:])
                    break
                i += 1

class ProcCmdCommand(CommandBase):
    cmd = "proc-cmd"
    needs_admin = False
    help_cmd = 'proc-cmd -command [command]'
    description = \
    """
    Run a command via cmd.exe

    Examples:
        proc-cmd -command dir

    Obs:
        This command behavior can be modified using:
            - "config -ppid" : to change parent process to spawn
            - "config -blockdlls" : to block non-microsoft dll for load in the process
    """
    version = 1
    author = "@Oblivion"
    argument_class = ProcCmdArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        command = task.args.get_arg("command")
        task.args.add_arg("command", f"cmd.exe /c {command}")
        task.args.add_arg("action", "cmd")
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            Success=True,
            DisplayParams=f"-command {command}",
            CommandName="proc"
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:

        RawResponse = bytes.fromhex(response)
        Psr = Parser(RawResponse, len(RawResponse))

        sub_id = int.from_bytes(Psr.Pad(1), byteorder="big")

        ProcID = Psr.Int32();
        TdID   = Psr.Int32();
        Output = Psr.Bytes();
        
        FinalOutput = f"[+] cmd.exe Created with ID: {ProcID} and Main Thread ID: {TdID}\n[+] Received {len(Output)} bytes from agent\n[+] Output:\n\n{Output.decode('cp850')}"
    
        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
            TaskID=task.Task.ID,
            Response=FinalOutput
        ))

        return PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID,
            Success=True
        )

class ProcHandlesArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                cli_name="pid",
                display_name="pid",
                type=ParameterType.String,
                description="Target Process ID to enumerate handles",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split()
                if len(args) >= 1:
                    self.add_arg("pid", args[0])

    async def parse_dictionary(self, dictionary):
        self.load_args_from_dictionary(dictionary)


class ProcHandlesCommand(CommandBase):
    cmd = "proc-handles"
    needs_admin = False
    help_cmd = "proc-handles -pid [pid]"
    description = \
    """
    List handles for target process
    
    Behavior: Beacon Object File
    """
    version = 1
    author = "@Oblivion"
    argument_class = ProcHandlesArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_pslist_handles.x64.o", task.Task.ID)

        proc_id = task.args.get_arg("pid")
        display_params = ""

        if proc_id :
            display_params += f" -pid {proc_id}"

        bof_args = [
            {"type": "int32", "value": int(proc_id)},
        ]

        task.args.remove_arg("proc_id")

        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))

        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName="exec-bof",
            TokenID=task.Task.TokenID,
            DisplayParams=display_params
        )
  
    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
