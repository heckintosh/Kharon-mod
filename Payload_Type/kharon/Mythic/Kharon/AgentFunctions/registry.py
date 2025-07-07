from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json
import base64

from .Utils.u import *

class RegQueryArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hive",
                cli_name="hive",
                display_name="Registry Hive",
                type=ParameterType.ChooseOne,
                choices=["HKCR", "HKCU", "HKLM", "HKU"],
                description="Registry hive to query (HKCR, HKCU, HKLM, HKU)",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="path",
                cli_name="path",
                display_name="Registry Path",
                type=ParameterType.String,
                description="Path to the registry key",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="key",
                cli_name="key",
                display_name="Value Name",
                type=ParameterType.String,
                description="Specific value name to query (leave empty for all values)",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="hostname",
                cli_name="hostname",
                display_name="Remote Host",
                type=ParameterType.String,
                description="Remote hostname to query (leave empty for local)",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                parts = self.command_line.split()
                if len(parts) < 2:
                    raise ValueError("Requires at least hive and path arguments")
                
                if parts[0].upper() not in ["HKCR", "HKCU", "HKLM", "HKU"]:
                    raise ValueError("First argument must be a valid registry hive (HKCR, HKCU, HKLM, HKU)")
                self.add_arg("hive", parts[0].upper())
                
                self.add_arg("path", parts[1])
                
                if len(parts) > 2:
                    if parts[2].startswith("-hostname"):
                        if len(parts) > 3:
                            self.add_arg("hostname", parts[3])
                    else:
                        self.add_arg("key", parts[2])
                        if len(parts) > 3 and parts[3].startswith("-hostname"):
                            if len(parts) > 4:
                                self.add_arg("hostname", parts[4])

    async def parse_dictionary(self, dictionary):
        self.load_args_from_dictionary(dictionary)


class RegQueryCommand(CommandBase):
    cmd = "reg-query"
    needs_admin = False
    help_cmd = "reg-query <hive> <path> [key] [-hostname <remote_host>]"
    description = """
    Query registry keys and values on the local or remote system.
    
    Supported hives:
    - HKCR (HKEY_CLASSES_ROOT)
    - HKCU (HKEY_CURRENT_USER)
    - HKLM (HKEY_LOCAL_MACHINE) 
    - HKU (HKEY_USERS)
    
    Examples:
    reg_query -hive HKLM -path "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    reg_query -hive HKLM -path "System\\CurrentControlSet\\Services\\SomeService" -key Start -hostname dc01
    
    Category: Beacon Object File
    """
    version = 1
    author = "@Oblivion"
    argument_class = RegQueryArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        hive = task.args.get_arg("hive")
        path = task.args.get_arg("path")
        key = task.args.get_arg("key")
        hostname = task.args.get_arg("hostname")

        display_params = f"-hive {hive} -path \"{path}\""
        if key:
            display_params += f" -key {key}"
        if hostname:
            display_params += f" -hostname {hostname}"

        hive_map = {
            "HKCR": 0,
            "HKCU": 1,
            "HKLM": 2,
            "HKU": 3
        }
        hive_num = hive_map[hive]

        bof_args = [
            {"type": "char",  "value": hostname if hostname else ""},
            {"type": "int32", "value": hive_num},
            {"type": "char",  "value": path},
            {"type": "char",  "value": key if key else ""},
            {"type": "int32", "value": int(False)}  
        ]

        for arg in ["hive", "path", "key", "hostname"]:
            task.args.remove_arg(arg)
        
        content: bytes = await get_content_by_name("kh_reg_query.x64.o", task.Task.ID)

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
        if response:
            # You may want to process the response data here
            # For example, if the BOF returns base64 encoded data:
            try:
                decoded_data = base64.b64decode(response).decode('utf-8', errors='ignore')
                await MythicRPC().execute("create_output", task_id=task.Task.ID, output=decoded_data)
            except:
                pass
        
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)

class RegDeleteArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hive",
                cli_name="hive",
                display_name="Registry Hive",
                type=ParameterType.ChooseOne,
                choices=["HKCR", "HKCU", "HKLM", "HKU"],
                description="Registry hive to delete from",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="path",
                cli_name="path",
                display_name="Registry Path",
                type=ParameterType.String,
                description="Path to the registry key",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="key",
                cli_name="key",
                display_name="Value Name",
                type=ParameterType.String,
                description="Specific value name to delete (leave empty to delete key)",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            ),
            CommandParameter(
                name="hostname",
                cli_name="hostname",
                display_name="Remote Host",
                type=ParameterType.String,
                description="Remote hostname to target (leave empty for local)",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                parts = self.command_line.split()
                if len(parts) < 2:
                    raise ValueError("Requires at least hive and path arguments")
                
                if parts[0].upper() not in ["HKCR", "HKCU", "HKLM", "HKU"]:
                    raise ValueError("First argument must be a valid registry hive")
                self.add_arg("hive", parts[0].upper())
                self.add_arg("path", parts[1])
                
                if len(parts) > 2:
                    if parts[2].startswith("-hostname"):
                        if len(parts) > 3:
                            self.add_arg("hostname", parts[3])
                    else:
                        self.add_arg("key", parts[2])
                        if len(parts) > 3 and parts[3].startswith("-hostname"):
                            if len(parts) > 4:
                                self.add_arg("hostname", parts[4])

class RegDeleteCommand(CommandBase):
    cmd = "reg-delete"
    needs_admin = False
    help_cmd = "reg-delete <hive> <path> [key] [-hostname <remote_host>]"
    description = "Delete a registry key or value"
    version = 1
    author = "@Oblivion"
    argument_class = RegDeleteArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        hive = task.args.get_arg("hive")
        path = task.args.get_arg("path")
        key = task.args.get_arg("key")
        hostname = task.args.get_arg("hostname")

        display_params = f"{hive} \"{path}\""
        if key:
            display_params += f" {key}"
        if hostname:
            display_params += f" -hostname {hostname}"

        hive_map = {"HKCR": 0, "HKCU": 1, "HKLM": 2, "HKU": 3}
        
        bof_args = [
            {"type": "char", "value": hostname if hostname else ""},
            {"type": "int32", "value": hive_map[hive]},
            {"type": "char", "value": path},
            {"type": "char", "value": key if key else ""},
            {"type": "int32", "value": 1 if key else 0}  # delkey flag
        ]

        for arg in ["hive", "path", "key", "hostname"]:
            task.args.remove_arg(arg)
        
        content: bytes = await get_content_by_name("kh_reg_delete.x64.o", task.Task.ID)

        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))

        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=display_params
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)

class RegSaveArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hive",
                cli_name="hive",
                display_name="Registry Hive",
                type=ParameterType.ChooseOne,
                choices=["HKCR", "HKCU", "HKLM", "HKU"],
                description="Registry hive to save from",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="path",
                cli_name="path",
                display_name="Registry Path",
                type=ParameterType.String,
                description="Path to the registry key",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="filepath",
                cli_name="filepath",
                display_name="Output File Path",
                type=ParameterType.String,
                description="Path to save the registry data",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                parts = self.command_line.split()
                if len(parts) < 3:
                    raise ValueError("Requires hive, path and filepath arguments")
                
                if parts[0].upper() not in ["HKCR", "HKCU", "HKLM", "HKU"]:
                    raise ValueError("First argument must be a valid registry hive")
                self.add_arg("hive", parts[0].upper())
                self.add_arg("path", parts[1])
                self.add_arg("filepath", parts[2])

class RegSaveCommand(CommandBase):
    cmd = "reg-save"
    needs_admin = False
    help_cmd = "reg-save <hive> <path> <filepath>"
    description = "Save a registry key to a file"
    version = 1
    author = "@Oblivion"
    argument_class = RegSaveArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        hive = task.args.get_arg("hive")
        path = task.args.get_arg("path")
        filepath = task.args.get_arg("filepath")

        display_params = f"{hive} \"{path}\" \"{filepath}\""

        hive_map = {"HKCR": 0, "HKCU": 1, "HKLM": 2, "HKU": 3}
        
        bof_args = [
            {"type": "char", "value": path},
            {"type": "char", "value": filepath},
            {"type": "int32", "value": hive_map[hive]}
        ]

        for arg in ["hive", "path", "filepath"]:
            task.args.remove_arg(arg)
        
        content: bytes = await get_content_by_name("kh_reg_save.x64.o", task.Task.ID)

        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_id", 0, ParameterType.Number)
        task.args.add_arg("bof_args", json.dumps(bof_args))

        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=display_params
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)

class RegSetArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="hive",
                cli_name="hive",
                display_name="Registry Hive",
                type=ParameterType.ChooseOne,
                choices=["HKCR", "HKCU", "HKLM", "HKU"],
                description="Registry hive to modify",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="path",
                cli_name="path",
                display_name="Registry Path",
                type=ParameterType.String,
                description="Path to the registry key",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="key",
                cli_name="key",
                display_name="Value Name",
                type=ParameterType.String,
                description="Value name to set",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="type",
                cli_name="type",
                display_name="Value Type",
                type=ParameterType.ChooseOne,
                choices=["REG_SZ", "REG_EXPAND_SZ", "REG_DWORD", "REG_QWORD", "REG_MULTI_SZ"],
                description="Type of registry value",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="data",
                cli_name="data",
                display_name="Value Data",
                type=ParameterType.String,
                description="Data to set (for REG_MULTI_SZ, separate values with spaces)",
                parameter_group_info=[ParameterGroupInfo(required=True)]
            ),
            CommandParameter(
                name="hostname",
                cli_name="hostname",
                display_name="Remote Host",
                type=ParameterType.String,
                description="Remote hostname to target (leave empty for local)",
                parameter_group_info=[ParameterGroupInfo(required=False)]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == '{':
                self.load_args_from_json_string(self.command_line)
            else:
                parts = self.command_line.split(" -", 1)
                if len(parts) < 2:
                    raise ValueError("Requires at least hive, path, key, type and data arguments")
                
                main_parts = parts[0].split()
                if len(main_parts) < 5:
                    raise ValueError("Requires at least hive, path, key, type and data arguments")
                
                if main_parts[0].upper() not in ["HKCR", "HKCU", "HKLM", "HKU"]:
                    raise ValueError("First argument must be a valid registry hive")
                self.add_arg("hive", main_parts[0].upper())
                self.add_arg("path", main_parts[1])
                self.add_arg("key", main_parts[2])
                self.add_arg("type", main_parts[3].upper())
                self.add_arg("data", " ".join(main_parts[4:]))
                
                if len(parts) > 1:
                    for part in parts[1].split(" -"):
                        if part.startswith("hostname"):
                            self.add_arg("hostname", part.split(maxsplit=1)[1])

class RegSetCommand(CommandBase):
    cmd = "reg-set"
    needs_admin = False
    help_cmd = "reg-set <hive> <path> <key> <type> <data> [-hostname <remote_host>]"
    description = "Set a registry value"
    version = 1
    author = "@Oblivion"
    argument_class = RegSetArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, task: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        hive = task.args.get_arg("hive")
        path = task.args.get_arg("path")
        key = task.args.get_arg("key")
        regtype = task.args.get_arg("type")
        data = task.args.get_arg("data")
        hostname = task.args.get_arg("hostname")

        display_params = f"-hive {hive} -path \"{path}\" -key {key} -type {regtype} -data \"{data}\""
        if hostname:
            display_params += f" -hostname {hostname}"

        hive_map = {"HKCR": 0, "HKCU": 1, "HKLM": 2, "HKU": 3}
        type_map = {
            "REG_SZ": 1,
            "REG_EXPAND_SZ": 2,
            "REG_DWORD": 4,
            "REG_QWORD": 11,
            "REG_MULTI_SZ": 7
        }
        
        bof_args = [
            {"type": "char", "value": f"\\\\{hostname}" if hostname else ""},
            {"type": "int32", "value": hive_map[hive]},
            {"type": "char", "value": path},
            {"type": "char", "value": key},
            {"type": "int32", "value": type_map[regtype]}
        ]

        if regtype in ["REG_DWORD", "REG_QWORD"]:
            try:
                int_data = int(data)
                bof_args.append({"type": "int32", "value": int_data})
            except ValueError:
                raise ValueError("For REG_DWORD/REG_QWORD, data must be an integer")
        elif regtype == "REG_MULTI_SZ":
            words = data.split()
            bin_data = b""
            for word in words:
                bin_data += word.encode('utf-8') + b'\x00'
            bof_args.append({"type": "bytes", "value": base64.b64encode(bin_data).decode()})
        else:  # REG_SZ, REG_EXPAND_SZ
            bof_args.append({"type": "char", "value": data})

        for arg in ["hive", "path", "key", "type", "data", "hostname"]:
            task.args.remove_arg(arg)
        
        content: bytes = await get_content_by_name("kh_reg_set.x64.o", task.Task.ID)

        task.args.add_arg("bof_file", content.hex())
        task.args.add_arg("bof_args", json.dumps(bof_args))

        return PTTaskCreateTaskingMessageResponse(
            TaskID=task.Task.ID,
            DisplayParams=display_params
        )

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)