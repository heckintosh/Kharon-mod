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
                choices=["int16", "int32", "char", "wchar", "bytes", "base64"],
                description="""
                Arguments to pass to the BOF via the following way:
                - int16:123
                - int32:123
                - char:hello
                - wchar:hello
                - base64:abc==
                """,
                typedarray_parse_function=self.get_arguments,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        group_name="Default",
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
        sc_arguments = []
        for argument in argumentSplitArray:
            argType,value = argument.split(":",1)
            value = value.strip("\'").strip("\"")
            if argType == "":
                pass
            elif argType == "int16" or argType == "-s" or argType == "s":
                sc_arguments.append(["int16", int(value)])
            elif argType == "int32" or argType == "-i" or argType == "i":
                sc_arguments.append(["int32", int(value)])
            elif argType == "char" or argType == "-c" or argType == "z":
                sc_arguments.append(["char",value])
            elif argType == "wchar" or argType == "-w" or argType == "Z":
                sc_arguments.append(["wchar",value])
            elif argType == "base64" or argType == "-b" or argType == "b":
                sc_arguments.append(["base64",value])
            else:
                return PTRPCTypedArrayParseFunctionMessageResponse(Success=False,
                                                                   Error=f"Failed to parse argument: {argument}: Unknown value type.")

        argumentResponse = PTRPCTypedArrayParseFunctionMessageResponse(Success=True, TypedArray=sc_arguments)
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
    exec-bof -file file.o [-args "char:\"arg1\" int32:20"]
    """
    description = \
    """
    Execute beacon object file in the current process memory
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
            TaskID=taskData.task.ID,
            Success=True,
        )
        
        try:
            if not taskData.args.has_arg("bof_name") and not taskData.args.has_arg("bof_file"):
                response.DisplayParams = "Executing with no arguments - default behavior"
                return response
                
            groupName = taskData.args.get_parameter_group_name()
            if groupName == "New":
                file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                    TaskID=taskData.task.ID,
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
                    TaskID=taskData.task.ID,
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
                            TaskID=taskData.task.ID,
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

        await write_console( task.Task.ID, MessageOut )

        return resp

class ExecScArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                cli_name="file",
                type=ParameterType.String,
                dynamic_query_function=self.get_bin_files,
                description="Shellcode file name in Mythic to inject",
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
                description="""
                Arguments to pass to the BOF via the following way:
                - int16:123
                - int32:123
                - char:hello
                - wchar:hello
                - base64:abc==
                """,
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def get_bin_files(self, callback: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
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
                if f.Filename not in file_names and f.Filename.endswith(".bin"):
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

    async def get_arguments(self, arguments: PTRPCTypedArrayParseFunctionMessage) -> PTRPCTypedArrayParseFunctionMessageResponse:
        argumentSplitArray = []
        for argValue in arguments.InputArray:
            argSplitResult = argValue.split(" ")
            for spaceSplitArg in argSplitResult:
                argumentSplitArray.append(spaceSplitArg)
        sc_arguments = []
        for argument in argumentSplitArray:
            argType,value = argument.split(":",1)
            value = value.strip("\'").strip("\"")
            if argType == "":
                pass
            elif argType == "int16" or argType == "-s" or argType == "s":
                sc_arguments.append(["int16", int(value)])
            elif argType == "int32" or argType == "-i" or argType == "i":
                sc_arguments.append(["int32", int(value)])
            elif argType == "char" or argType == "-c" or argType == "c":
                sc_arguments.append(["char",value])
            elif argType == "wchar" or argType == "-w" or argType == "w":
                sc_arguments.append(["wchar",value])
            elif argType == "base64" or argType == "-b" or argType == "b":
                sc_arguments.append(["base64",value])
            else:
                return PTRPCTypedArrayParseFunctionMessageResponse(Success=False,
                                                                   Error=f"Failed to parse argument: {argument}: Unknown value type.")

        argumentResponse = PTRPCTypedArrayParseFunctionMessageResponse(Success=True, TypedArray=sc_arguments)
        return argumentResponse 

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Arguments required")
            
        if self.command_line[0] == "{":
            dictionary = json.loads(self.command_line)
            await self.parse_dictionary(dictionary)
        else:
            try:
                argv = shlex.split(self.command_line)
                args = {}
                i = 0
                while i < len(argv):
                    if argv[i] == "-file" and i + 1 < len(argv):
                        args["file"] = argv[i+1]
                        i += 2
                    if argv[i] == "-pid" and i + 1 < len(argv):
                        args["file"] = argv[i+1]
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
            if k == "file":
                converted_args["file"] = v
            elif k == "pid":
                converted_args["pid"] = v
            elif k == "args":
                converted_args["args"] = v
            else:
                converted_args[k] = v

        # These are all our valid parameters
        expected_args = {"file", "pid", "args"}
        
        # Filter out any None values
        converted_args = {k: v for k, v in converted_args.items() if v is not None}
        
        # Check for required arguments
        if "file" not in converted_args:
            raise ValueError("'file' argument is required")
        
        # Check for invalid arguments
        invalid_keys = set(converted_args.keys()) - expected_args
        if invalid_keys:
            raise ValueError(f"Invalid arguments provided: {', '.join(invalid_keys)}")
        
        self.load_args_from_dictionary(converted_args)
        
class ExecScCommand(CommandBase):
    cmd = "exec-sc"
    needs_admin = False
    help_cmd = "exec-sc -file <file_name> -pid [pid] -args [args]"
    description = "Execute shellcode in memory"
    version = 1
    author = "@Oblivion"
    argument_class = ExecScArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            Success=True,
        )
        
        try:           
            file_name = task.args.get_arg("file")
            sc_content = await get_content_by_name( file_name, task.Task.ID )
            
            if sc_content is None:
                raise Exception("Failed to get shellcode content")
            
            # Prepare arguments
            pid = task.args.get_arg("pid") or 0
            args = task.args.get_arg("args")
                        
            # Set display parameters for the UI
            display_params = f"-file {file_name}"
            if pid > 0:
                display_params += f" -pid {pid}"
            if args:
                display_params += f" -args \"{args}\""
            
            response.DisplayParams = display_params
            
            task.args.remove_arg("file")
            task.args.remove_arg("pid")
            task.args.remove_arg("args")
            
            task.args.add_arg("sc_file", sc_content.hex())
            task.args.add_arg("sc_args", args, ParameterType.TypedArray)
            task.args.add_arg("pid", pid, ParameterType.Number )
            
        except Exception as e:
            raise Exception(f"Error preparing shellcode task: {str(e)}")
        
        return response
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