from .Utils.u import *

class ExitArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="method",
                type=ParameterType.ChooseOne,
                choices=["thread", "process"],
                description="Termination method (thread or process)",
                default_value="process",
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("method", self.command_line.split()[0])

class ExitCommand(CommandBase):
    cmd = "exit"
    needs_admin = False
    help_cmd = "exit [-method thread|process]"
    description = "Terminate agent using either thread or process method"
    version = 1
    author = "@ Oblivion"
    argument_class = ExitArguments
    attackmapping = []

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        method = taskData.args.get_arg("method", "process")
        method_id = 0
        if method == "process":
            method_id = "21"
        else:
            method_id = "20"

        await StorageExtract( taskData.Callback.AgentCallbackID )
        await DeleteStorage( taskData.Callback.AgentCallbackID )

        taskData.args.remove_arg("method")
        taskData.args.add_arg("method", method_id, ParameterType.Number)
            
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)