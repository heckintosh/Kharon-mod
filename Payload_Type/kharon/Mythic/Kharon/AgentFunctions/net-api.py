from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import logging
import json

from .Utils.u import *

class NetLocalGroupArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                cli_name="action",
                display_name="Action",
                type=ParameterType.ChooseOne,
                description="Action to perform",
                choices=["list_groups", "list_members"],
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="group",
                cli_name="group",
                display_name="Group Name",
                type=ParameterType.String,
                description="Group name (required for list_members action)",
            ),
            CommandParameter(
                name="server",
                cli_name="server",
                display_name="Target Server",
                type=ParameterType.String,
                description="Target server (default: localhost)",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split()
                if len(args) >= 1:
                    action = args[0].lower()
                    if action in ["list_groups", "list_members"]:
                        self.add_arg("action", action)
                    else:
                        raise ValueError("Invalid action. Use 'list_groups' or 'list_members'")
                    
                    if len(args) >= 2:
                        if action == "list_members":
                            self.add_arg("group", args[1])
                            if len(args) >= 3:
                                self.add_arg("server", args[2])
                        else:
                            self.add_arg("server", args[1])

    async def parse_dictionary(self, dictionary):
        self.load_args_from_dictionary(dictionary)


class NetLocalGroupCommand(CommandBase):
    cmd = "net-localgroup"
    needs_admin = False
    help_cmd = """
    net-localgroup list_groups [server]
    net-localgroup list_members <group> [server]
    """
    description = """
    Enumerate local groups or group members on a target system.
    
    Actions:
    list_groups   - List all local groups
    list_members  - List members of specified group
    
    MITRE ATT&CK Technique:
    T1069.001 - Permission Groups Discovery: Local Groups
    
    Behavior: Discovery
    """
    version = 1
    author = "@Oblivion"
    argument_class = NetLocalGroupArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_netlocalgroup.x64.o", task.Task.ID)

        action = task.args.get_arg("action")
        group = task.args.get_arg("group") or " "
        server = task.args.get_arg("server") or ""
        
        # Convert action to numeric type
        action_type = 0 if action == "list_groups" else 1

        display_params = f"-f {action}"
        if action == "list_members":
            display_params += f" -group {group}"
        elif group:
            display_params += f" -group {group}"
        if server:
            display_params += f" -server {server}"

        bof_args = [
            {"type": "int16", "value": action_type},  # 0=list groups, 1=list members
            {"type": "wchar", "value": server},
            {"type": "wchar", "value": group}
        ]

        task.args.remove_arg("action")
        task.args.remove_arg("group")
        task.args.remove_arg("server")
        
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
    
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import logging
import json

from .Utils.u import *

class NetSessionArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hostname",
                cli_name="hostname",
                display_name="Target Host",
                type=ParameterType.String,
                description="Target host to enumerate sessions (default: localhost)",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                if self.command_line.strip():
                    self.add_arg("hostname", self.command_line.strip())

    async def parse_dictionary(self, dictionary):
        self.load_args_from_dictionary(dictionary)


class NetSessionCommand(CommandBase):
    cmd = "net-session"
    needs_admin = False
    help_cmd = "net-session [hostname]"
    description = """
    Enumerate active sessions on the specified host using NetSessionEnum.
    
    Without arguments, enumerates sessions on localhost.
    
    Behavior: Beacon Object File
    """
    version = 1
    author = "@Oblivion"
    argument_class = NetSessionArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("get-netsession.x64.o", task.Task.ID)

        hostname = task.args.get_arg("hostname") or "localhost"

        display_params = ""
        
        if hostname:
            display_params = f"-hostname {hostname}"

        bof_args = [
            {"type": "wchar", "value": hostname}
        ]

        task.args.remove_arg("hostname")
        
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
    
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import logging
import json

from .Utils.u import *

class NetUserArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="username",
                cli_name="username",
                display_name="Username",
                type=ParameterType.String,
                description="Username to query (leave empty for all users)",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="domain",
                cli_name="domain",
                display_name="Domain",
                type=ParameterType.String,
                description="Domain to query (default: current domain)",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                args = self.command_line.split()
                if len(args) >= 1:
                    self.add_arg("username", args[0])
                if len(args) >= 2:
                    self.add_arg("domain", args[1])

    async def parse_dictionary(self, dictionary):
        self.load_args_from_dictionary(dictionary)


class NetUserCommand(CommandBase):
    cmd = "net-user"
    needs_admin = False
    help_cmd = "net-user -username [username] -domain [domain]"
    description = """
    Query user information from the domain or local system.
    
    Without arguments, lists all users.
    With username, shows detailed information about specific user.
    
    Behavior: Beacon Object File
    """
    version = 1
    author = "@Oblivion"
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    argument_class = NetUserArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_netuser.x64.o", task.Task.ID)

        username = task.args.get_arg("username") or ''
        domain   = task.args.get_arg("domain")   or 'localhost'

        display_params = ""
        if username:
            display_params += f" -username {username}"
        if domain:
            display_params += f" -domain {domain}"
        if not display_params:
            display_params = ""

        bof_args = [
            {"type": "wchar", "value": username},
            {"type": "wchar", "value": domain}
        ]

        task.args.remove_arg("username")
        task.args.remove_arg("domain")
        
        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))

        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            CommandName="exec-bof",
            TokenID=task.Task.TokenID,
            DisplayParams=display_params.strip()
        )
  
    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp