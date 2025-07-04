from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .Utils.u import *
import json
import logging
import sys
import shlex

logging.basicConfig(level=logging.INFO)

class ExecbofArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="bof_name",
                cli_name="file",
                display_name="file",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_files,
                description="Already existing Beacon Object File to execute (e.g. whoami.x64.o)",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=1
                    )
                ]
            ),
            CommandParameter(
                name="bof_file",
                display_name="new",
                type=ParameterType.File,
                description="A new BOF to execute. After uploading once, you can just supply the bof_name parameter",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False, 
                        group_name="New", 
                        ui_position=1,
                    )
                ]
            ),
            CommandParameter(
                name="bof_args",
                cli_name="args",
                display_name="args",
                type=ParameterType.TypedArray,
                default_value=[],
                choices=["int16", "int32", "char", "wchar", "base64"],
                description="""
                Arguments to pass to the BOF via the following way:
                -s:123 or int16:123
                -i:123 or int32:123
                -z:hello or string:hello
                -Z:hello or wchar:hello
                -b:abc== or base64:abc==
                """,
                typedarray_parse_function=self.get_arguments,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
                        ui_position=4
                    ),
                    ParameterGroupInfo(
                        required=False,
                        group_name="New",
                        ui_position=4
                    ),
                ]),
        ]
        
    async def parse_arguments(self):
        if len(self.command_line) == 0:
            # Accept execution with no arguments
            return
        elif self.command_line[0] == "{":
            # JSON-style arguments
            try:
                dictionary = json.loads(self.command_line)
                await self.parse_dictionary(dictionary)
            except json.JSONDecodeError:
                raise ValueError("Invalid JSON format")
        else:
            # CLI-style arguments (-file x.o -args "arg1 arg2")
            try:
                argv = shlex.split(self.command_line)
                args = {}
                i = 0
                while i < len(argv):
                    if argv[i] == "-file" and i + 1 < len(argv):
                        args["bof_name"] = argv[i+1]
                        i += 2
                    elif argv[i] == "-args" and i + 1 < len(argv):
                        args["bof_arguments"] = argv[i+1].split()
                        i += 2
                    elif argv[i].startswith("-"):
                        # Skip unknown flags
                        i += 1
                    else:
                        i += 1
                await self.parse_dictionary(args)
            except Exception as e:
                raise ValueError(f"Failed to parse CLI arguments: {str(e)}")

    async def parse_dictionary(self, dictionary_arguments):
        # Convert all keys to the internal parameter names
        converted_args = {}
        for k, v in dictionary_arguments.items():
            if k == "file":  # CLI name for bof_name
                converted_args["bof_name"] = v
            elif k == "args":  # CLI name for bof_arguments
                converted_args["bof_arguments"] = v
            else:
                converted_args[k] = v

        expected_args = {"bof_arguments", "bof_file", "bof_name"}
        
        # Filter out any None values
        converted_args = {k: v for k, v in converted_args.items() if v is not None}
        
        invalid_keys = set(converted_args.keys()) - expected_args
        if invalid_keys:
            raise ValueError(f"Invalid arguments provided: {', '.join(invalid_keys)}")
        
        self.load_args_from_dictionary(converted_args)   

    async def get_arguments(self, arguments: PTRPCTypedArrayParseFunctionMessage) -> PTRPCTypedArrayParseFunctionMessageResponse:
        argumentSplitArray = []
        for argValue in arguments.InputArray:
            argSplitResult = argValue.split(" ")
            for spaceSplitArg in argSplitResult:
                argumentSplitArray.append(spaceSplitArg)
        bof_arguments = []
        for argument in argumentSplitArray:
            argType,value = argument.split(":",1)
            value = value.strip("\'").strip("\"")
            if argType == "":
                pass
            elif argType == "int16" or argType == "-s" or argType == "s":
                bof_arguments.append(["int16", int(value)])
            elif argType == "int32" or argType == "-i" or argType == "i":
                bof_arguments.append(["int32", int(value)])
            elif argType == "char" or argType == "-z" or argType == "z":
                bof_arguments.append(["char",value])
            elif argType == "wchar" or argType == "-Z" or argType == "Z":
                bof_arguments.append(["wchar",value])
            elif argType == "base64" or argType == "-b" or argType == "b":
                bof_arguments.append(["base64",value])
            else:
                return PTRPCTypedArrayParseFunctionMessageResponse(Success=False,
                                                                   Error=f"Failed to parse argument: {argument}: Unknown value type.")

        argumentResponse = PTRPCTypedArrayParseFunctionMessageResponse(Success=True, TypedArray=bof_arguments)
        return argumentResponse

    async def get_files(self, callback: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
        response = PTRPCDynamicQueryFunctionMessageResponse()
        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            CallbackID=callback.Callback,
            LimitByCallback=False,
            IsDownloadFromAgent=False,
            IsScreenshot=False,
            IsPayload=False,
            Filename="",
        ))
        if file_resp.Success:
            file_names = []
            for f in file_resp.Files:
                if f.Filename not in file_names and f.Filename.endswith(".o"):
                    file_names.append(f.Filename)
            response.Success = True
            response.Choices = file_names
            return response
        else:
            await SendMythicRPCOperationEventLogCreate(MythicRPCOperationEventLogCreateMessage(
                CallbackId=callback.Callback,
                Message=f"Failed to get files: {file_resp.Error}",
                MessageLevel="warning"
            ))
            response.Error = f"Failed to get files: {file_resp.Error}"
            return response


class ExecbofCommand(CommandBase):
    cmd = "exec-bof"
    needs_admin = False
    help_cmd = \
    """
    exec-bof -file file.o [-args "arg1 arg2"]
    exec-bof (with no arguments for default behavior)
    """
    description = \
    """
    Execute beacon object file in the current process memory
    
    Supports both CLI-style (-file) and JSON-style arguments.
    When executed with no arguments, will use default BOF if implemented.
    """
    version = 1
    author = "@Oblivion"
    attackmapping = []
    argument_class = ExecbofArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
        suggested_command=False
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        
        try:
            if not taskData.args.has_arg("bof_name") and not taskData.args.has_arg("bof_file"):
                response.DisplayParams = "Executing with no arguments - default behavior"
                return response
                
            groupName = taskData.args.get_parameter_group_name()
            if groupName == "New":
                file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                    TaskID=taskData.Task.ID,
                    AgentFileID=taskData.args.get_arg("bof_file")
                ))
                if file_resp.Success:
                    if len(file_resp.Files) > 0:
                        pass
                    else:
                        raise Exception("Failed to find that file")
                else:
                    raise Exception("Error from Mythic trying to get file: " + str(file_resp.Error))
            elif groupName == "Default":
                file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                    TaskID=taskData.Task.ID,
                    Filename=taskData.args.get_arg("bof_name"),
                    LimitByCallback=False,
                    MaxResults=1
                ))
                if file_resp.Success:
                    if len(file_resp.Files) > 0:
                        file_contents = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
                          AgentFileId=file_resp.Files[0].AgentFileId
                        ))
                        
                        logging.info(f"Found existing BOF file replacing with file_id: {file_resp.Files[0].AgentFileId}")
                        taskData.args.remove_arg("bof_file")
                        taskData.args.add_arg("bof_file", file_contents.Content.hex())
                        taskData.args.remove_arg("bof_name") 
                        taskData.args.add_arg("bof_id", 0, ParameterType.Number) 
                        
                        file_name = file_resp.Files[0].Filename
                        file_id   = file_resp.Files[0].AgentFileId

                        console_out = f"[+] Sending \"{file_name}\" with {len(file_contents.Content)} bytes\n"
                        display_prm = f"-file {file_name}"

                        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                            TaskID=taskData.Task.ID,
                            Response=console_out
                        ))

                        if taskData.args.get_arg("bof_args"):
                            display_prm += f" -args {taskData.args.get_arg('bof_args')}"

                        response.DisplayParams = display_prm

                    elif len(file_resp.Files) == 0:
                        raise Exception("Failed to find the named file. Have you uploaded it before? Did it get deleted?")
                else:
                    raise Exception("Error from Mythic trying to search files:\n" + str(file_resp.Error))
        except Exception as e:
            raise Exception("Error from Mythic:" + str(e))
        
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
    
        RawResponse = bytes.fromhex( response )

        Psr = Parser( RawResponse, len( RawResponse ) )

        BofCommandID = Psr.Int32()
        CallbackType = Psr.Int32()
        CallbackOut  = Psr.Str()

        logging.info(CallbackType)

        MessageOut = f""

        bof_command_ids = {cmd["sub"] for cmd in Commands["bof"].values()}

        if BofCommandID not in bof_command_ids:
            if CallbackType == KH_CALLBACK_OUTPUT:
                MessageOut = f"[+] Received Output:\n{CallbackOut}"
            elif CallbackType == KH_CALLBACK_ERROR:
                MessageOut = f"[x] Received Error:\n{CallbackOut}"
            else:
                MessageOut = f"[?] Received Unknown Callback:\n{CallbackOut}"

        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
            TaskID=task.Task.ID,
            Response=MessageOut
        ))

        return resp

class ExecScArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                cli_name="file",
                type=ParameterType.File,
                description="Shellcode file ID in Mythic to inject",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="pid",
                cli_name="pid",
                type=ParameterType.Number,
                description="Process ID to inject into (optional)",
                default_value=0,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="args",
                cli_name="args",
                type=ParameterType.String,
                description="Arguments for shellcode execution (optional)",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Arguments required")
            
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.split()
            if len(parts) < 1:
                raise ValueError("Usage: exec-sc -file <file_id> -pid [pid] -args [args]")
            
            self.add_arg("file", parts[0])
            
            if len(parts) > 1 and parts[1].isdigit():
                self.add_arg("pid", int(parts[1]))
                if len(parts) > 2:
                    self.add_arg("args", " ".join(parts[2:]))
            elif len(parts) > 1:
                self.add_arg("args", " ".join(parts[1:]))

class ExecScCommand(CommandBase):
    cmd = "exec-sc"
    needs_admin = False
    help_cmd = "exec-sc <file_id> [pid] [args]"
    description = "Execute shellcode in memory"
    version = 1
    author = "@Oblivion"
    attackmapping = ["T1055", "T1064"]
    argument_class = ExecScArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        file_name = task.args.get_arg("file")
        pid       = task.args.get_arg("pid")
        args      = task.args.get_arg("args")
        
        bof_content = await get_content_by_name("kh_exec-sc.x64.o", task.Task.ID)
        sc_content  = await get_content_by_name( file_name, task.Task.ID)
            
        output  = f"Executing shellcode file: {file_name}"
        display = f"-file {file_name}"

        if pid > 0:
            display += f" -pid {pid}"
        if args:
            display += f" -args {args}"
        
        task.args.remove_arg("file")
        task.args.remove_arg("pid")
        task.args.remove_arg("args")
    
        AgentData = StorageExtract( task.Callback.AgentCallbackID )

        alloc_type = AgentData["injection"]["write_method"]
        write_type = AgentData["injection"]["alloc_method"]

        bof_args = [
            {"type": "bytes", "value": sc_content.hex()},
            {"type": "int"  , "value": pid},
            {"type": "char" , "value": args},            
            {"type": "int"  , "value": alloc_type},       
            {"type": "int"  , "value": write_type},
        ]

        task.args.add_arg("bof_file", bof_content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))

        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=f"-file {file_name}"
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        if not response:
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )

        return PTTaskProcessResponseMessageResponse(
            TaskID=task.Task.ID,
            Success=True
        )