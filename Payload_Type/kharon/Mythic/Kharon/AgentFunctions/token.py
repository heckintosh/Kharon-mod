from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from mythic_container.PayloadBuilder import *

from .Utils.u import *

class TokenUseArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="id",
                cli_name="id",
                type=ParameterType.Number,
                description="Token from Mythic table to use",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("id", int(self.command_line.strip()))

class TokenUseCommand(CommandBase):
    cmd = "token-use"
    needs_admin = False
    help_cmd = "token-use [id]"
    description = "Usa um token da tabela do Mythic no agente atual"
    version = 1
    author = "@Oblivion"
    attackmapping = ["T1134.001"]
    argument_class = TokenUseArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        task.args.add_arg("action", "use")
        task.args.add_arg("token_id", task.args.get_arg("id"))
        
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=f"id: {task.args.get_arg('id')}",
            CommandName="token"
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        try:
            if not response:
                return PTTaskProcessResponseMessageResponse(
                    TaskID=task.Task.ID,
                    Success=False,
                    Error="Not response from agent",
                    Completed=True
                )
            
            # A resposta deve ser apenas um booleano (true/false)
            success = bool(response)
            
            message = "Token impersonated" if success else "Failure to impersonate token"
            
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=message.encode()
            ))

            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=success,
                Completed=True
            )

        except Exception as e:
            error_msg = f"Error to process response: {str(e)}"
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=error_msg.encode()
            ))
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=error_msg,
                Completed=True
            )

class TokenStealArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                cli_name="pid",
                type=ParameterType.Number,
                description="Process ID to steal token from",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="use",
                cli_name="use",
                type=ParameterType.Boolean,
                default_value=True,
                description="Automatically use the stolen token",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                try:
                    parts = self.command_line.split()
                    if len(parts) >= 2 and parts[0] == "-pid":
                        self.add_arg("pid", int(parts[1]))
                        if len(parts) >= 4 and parts[2] == "-use":
                            self.add_arg("use", parts[3].lower() in ("true", "1", "yes"))
                except Exception as e:
                    raise ValueError(f"Failed to parse command line: {str(e)}")

class TokenStealCommand(CommandBase):
    cmd = "token-steal"
    needs_admin = False
    help_cmd = "token-steal -pid <PID> [-use <true|false>]"
    description = "Steal an access token from a specified process and optionally use it"
    version = 1
    author = "@Oblivion"
    argument_class = TokenStealArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=f"-pid {task.args.get_arg('pid')} -use {task.args.get_arg('use')}",
            CommandName="token"
        )
        
        task.args.add_arg("action", "steal")
        task.args.add_arg("pid", task.args.get_arg('pid'), ParameterType.Number)
        task.args.add_arg("use", int(task.args.get_arg('use')), ParameterType.Number)
        
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        try:
            if not response:
                return PTTaskProcessResponseMessageResponse(
                    TaskID=task.Task.ID,
                    Success=True,
                    Completed=True
                )
            
            # Parse the binary response
            raw_response = bytes.fromhex(response)
            psr = Parser(raw_response, len(raw_response))
            
            success = psr.Int32()
            token_id = psr.Int32()
            proc_id = psr.Int32()
            username = psr.Str()
            hostname = psr.Str()
            handle = psr.Int64()

            # Create token in Mythic
            token_message =  f"Stolen token from PID {proc_id}\n"
            token_message += f"Username: {username}\n"
            token_message += f"Hostname: {hostname}\n"
            token_message += f"Token Handle: 0x{handle:x}\n"
            
            token_list = Token( 
                TokenID=token_id, 
                User=username, 
                Handle=handle, 
                ProcessID=proc_id 
            )

            await SendMythicRPCTokenCreate(MythicRPCTokenCreateMessage(
                TaskID=task.Task.ID,
                Tokens=token_list
            ))
            
            # Send detailed response to operator
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=token_message.encode('utf-8')
            ))

            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=bool(success),
                Completed=True
            )

        except Exception as e:
            error_msg = f"Error processing token steal response: {str(e)}"
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=error_msg.encode('utf-8')
            ))
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=error_msg,
                Completed=True
            )

class TokenRemoveArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="id",
                cli_name="id",
                type=ParameterType.Number,
                description="ID of the token to remove from Mythic table",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("id", int(self.command_line.strip()))

class TokenRemoveCommand(CommandBase):
    cmd = "token-rm"
    needs_admin = False
    help_cmd = "token-rm -id [id]"
    description = "Remove token from store"
    version = 1
    author = "@Oblivion"
    attackmapping = []
    argument_class = TokenRemoveArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        task.display_params = f"id: {task.args.get_arg('id')}"
        task.args.add_arg("action", "rm")
        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=task.display_params,
            CommandName="token"
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        try:
            if not response:
                return PTTaskProcessResponseMessageResponse(
                    TaskID=task.Task.ID,
                    Success=False,
                    Error="No response from agent",
                    Completed=True
                )
            
            agent_success = bool(response)
            token_id = task.args.get_arg("id")
            token_list = Token( TokenID=token_id )

            if agent_success:
                remove_response = await SendMythicRPCTokenRemove(MythicRPCTokenRemoveMessage(
                    TaskID=task.Task.ID,
                    Tokens=token_list
                ))
                
                if remove_response.Success:
                    message = f"Successfully removed token {token_id}"
                    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                        TaskID=task.Task.ID,
                        Response=message.encode()
                    ))
                    return PTTaskProcessResponseMessageResponse(
                        TaskID=task.Task.ID,
                        Success=True,
                        Completed=True
                    )
                else:
                    error_msg = f"Agent removed token but failed to remove from Mythic table: {remove_response.Error}"
                    await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                        TaskID=task.Task.ID,
                        Response=error_msg.encode()
                    ))
                    return PTTaskProcessResponseMessageResponse(
                        TaskID=task.Task.ID,
                        Success=False,
                        Error=error_msg,
                        Completed=True
                    )
            else:
                error_msg = "Agent failed to remove token locally"
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=error_msg.encode()
                ))
                return PTTaskProcessResponseMessageResponse(
                    TaskID=task.Task.ID,
                    Success=False,
                    Error=error_msg,
                    Completed=True
                )

        except Exception as e:
            error_msg = f"Error processing response: {str(e)}"
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=error_msg.encode()
            ))
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=error_msg,
                Completed=True
            )

class TokenUUIDArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                try:
                    parts = self.command_line.split()
                except Exception as e:
                    raise ValueError(f"Failed to parse command line: {str(e)}")

class TokenUUIDCommand(CommandBase):
    cmd = "token-rev2self"
    needs_admin = False
    help_cmd = "token-rev2self"
    description = "Revert token to self"
    version = 1
    author = "@Oblivion"
    attackmapping = ["T1070", "T1485", "T1134"]
    argument_class = TokenUUIDArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=f"",
            CommandName="token"
        )
        
        task.args.add_arg("action", "rev2self")
        
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        try:
            if not response:
                return PTTaskProcessResponseMessageResponse(
                    TaskID=task.Task.ID,
                    Success=True,
                    Completed=True
                )
            
            # Parse the binary response
            raw_response = bytes.fromhex(response)
            psr = Parser(raw_response, len(raw_response))
            
            success = psr.Int32()

            token_message = ""
            # Create token in Mythic
            if bool( success ) is True:
                token_message =  f"[+] Token reverted\n"
            else:
                token_message =  f"[x] Token fail to revert\n"

            # Send detailed response to operator
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=token_message.encode('utf-8')
            ))

            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True,
                Completed=True
            )

        except Exception as e:
            error_msg = f"Error processing token steal response: {str(e)}"
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=error_msg.encode('utf-8')
            ))
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=error_msg,
                Completed=True
            )

class TokenUUIDArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                try:
                    parts = self.command_line.split()
                except Exception as e:
                    raise ValueError(f"Failed to parse command line: {str(e)}")

class TokenUUIDCommand(CommandBase):
    cmd = "token-getuuid"
    needs_admin = False
    help_cmd = "token-getuuid"
    description = "Steal an access token from a specified process and optionally use it"
    version = 1
    author = "@Oblivion"
    attackmapping = ["T1070", "T1485", "T1134"]
    argument_class = TokenUUIDArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=f"",
            CommandName="token"
        )
        
        task.args.add_arg("action", "getuuid")
        
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        try:
            if not response:
                return PTTaskProcessResponseMessageResponse(
                    TaskID=task.Task.ID,
                    Success=True,
                    Completed=True
                )
            
            raw_response = bytes.fromhex(response)
            psr = Parser(raw_response, len(raw_response))
            
            process_uuid = psr.Bytes()
            thread_uuid  = psr.Bytes()

            token_message  =  f"Process Token: {process_uuid.decode('utf-8', 'ignore')}\n"
            token_message +=  f"Thread  Token: {thread_uuid.decode('utf-8', 'ignore')}\n"

            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=token_message
            ))

            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )

        except Exception as e:
            error_msg = f"Error processing token steal response: {str(e)}"
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=error_msg.encode('utf-8')
            ))
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=error_msg,
                Completed=True
            )
        

class TokenListPrivsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                try:
                    parts = self.command_line.split()
                except Exception as e:
                    raise ValueError(f"Failed to parse command line: {str(e)}")

class TokenListPrivsCommand(CommandBase):
    cmd = "token-listprivs"
    needs_admin = False
    help_cmd = "token-listprivs"
    description = "Steal an access token from a specified process and optionally use it"
    version = 1
    author = "@Oblivion"
    argument_class = TokenUUIDArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=f"",
            CommandName="token"
        )
        
        task.args.add_arg("action", "listprivs")
        
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        try:
            if not response:
                return PTTaskProcessResponseMessageResponse(
                    TaskID=task.Task.ID,
                    Success=True,
                    Completed=True
                )
            
            raw_response = bytes.fromhex(response)
            psr = Parser(raw_response, len(raw_response))
            token_message  = "[+]"
            
            list_priv_count = psr.Int32()
            
            for i in list_priv_count:
                priv_name = psr.Str()
                priv_attr = psr.Int32()
                token_message += f" {priv_name} | {priv_attr}"   

            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=token_message
            ))

            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )

        except Exception as e:
            error_msg = f"Error processing token steal response: {str(e)}"
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=error_msg.encode('utf-8')
            ))
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=error_msg,
                Completed=True
            )
        
class TokenGetPrivArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                try:
                    parts = self.command_line.split()
                except Exception as e:
                    raise ValueError(f"Failed to parse command line: {str(e)}")

class TokenGetPrivCommand(CommandBase):
    cmd = "token-getprivs"
    needs_admin = False
    help_cmd = "token-getprivs"
    description = "Enable all privilege tokens"
    version = 1
    author = "@Oblivion"
    argument_class = TokenGetPrivArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=f"",
            CommandName="token"
        )
        
        task.args.add_arg("action", "getprivs")
        
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        try:
            if not response:
                return PTTaskProcessResponseMessageResponse(
                    TaskID=task.Task.ID,
                    Success=True,
                    Completed=True
                )
            
            raw_response = bytes.fromhex(response)
            psr = Parser(raw_response, len(raw_response))
            token_message = ""
            
            boolean_resp = bool( psr.Int32() )

            if boolean_resp is True:
                token_message = f"[+] The all privilege token is enabled, run \"token-listprivs\" to see privileges"
            else:
                token_message = f"[x] Failed to enable all privilege tokens"

            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=token_message
            ))

            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=True
            )

        except Exception as e:
            error_msg = f"Error processing token steal response: {str(e)}"
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=error_msg.encode('utf-8')
            ))
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=error_msg,
                Completed=True
            )
        
class TokenMakeArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="username",
                cli_name="username",
                type=ParameterType.String,
                description="Username for token creation",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="password",
                cli_name="password",
                type=ParameterType.String,
                description="Password for token creation",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="domain",
                cli_name="domain",
                type=ParameterType.String,
                description="Domain for token creation (optional)",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                try:
                    # Parse command line arguments in format: -username value -password value [-domain value]
                    parts = self.command_line.split()
                    i = 0
                    while i < len(parts):
                        if parts[i] == "-username" and (i + 1) < len(parts):
                            self.add_arg("username", parts[i+1])
                            i += 2
                        elif parts[i] == "-password" and (i + 1) < len(parts):
                            self.add_arg("password", parts[i+1])
                            i += 2
                        elif parts[i] == "-domain" and (i + 1) < len(parts):
                            self.add_arg("domain", parts[i+1])
                            i += 2
                        else:
                            i += 1
                except Exception as e:
                    raise ValueError(f"Failed to parse command line: {str(e)}")


class TokenMakeCommand(CommandBase):
    cmd = "token-make"
    needs_admin = False
    help_cmd = "token-make -username <username> -password <password> [-domain <domain>]"
    description = "Create a new access token using provided credentials"
    version = 1
    author = "@Oblivion"
    argument_class = TokenMakeArguments
    browser_script = BrowserScript(
        script_name="token_make",
        author="@Oblivion",
        for_new_ui=True
    )
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        builtin=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        # Build display parameters for UI
        display_params = f"-username {task.args.get_arg('username')} -password {task.args.get_arg('username')}"
        if task.args.get_arg("domain"):
            display_params += f" -domain {task.args.get_arg('domain')}"

        response = PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=display_params,
            CommandName=self.cmd
        )
        
        # Set the action for the agent to know this is a "make" operation
        task.args.add_arg("action", "make")
        
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        try:
            if not response:
                return PTTaskProcessResponseMessageResponse(
                    TaskID=task.Task.ID,
                    Success=False,
                    Error="Empty response from agent",
                    Completed=True
                )
            
            raw_response = bytes.fromhex(response)
            psr = Parser(raw_response, len(raw_response))
            
            success = bool(psr.Int32())

            if success:
                token_list = []

                username = task.args.get_arg('username')
                password = task.args.get_arg('password')            
                
                await SendMythicRPCTokenCreate(MythicRPCTokenCreateMessage(
                    TaskID=task.Task.ID,
                    Tokens=token_list
                ))
                
                response_message = f"Successfully created {len(token_list)} token(s)"
            else:
                error_length = psr.Int32()
                error_message = psr.String(error_length)
                response_message = f"Token creation failed: {error_message}"

            # Send response to Mythic
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=response_message.encode('utf-8')
            ))

            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=success,
                Completed=True
            )

        except Exception as e:
            error_msg = f"Error processing token make response: {str(e)}"
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=error_msg.encode('utf-8')
            ))
            return PTTaskProcessResponseMessageResponse(
                TaskID=task.Task.ID,
                Success=False,
                Error=error_msg,
                Completed=True
            )