from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import sys


class UploadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                cli_name="file",
                display_name="Filename within Mythic",
                description="Supply existing filename in Mythic to upload",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_files
            ),
            CommandParameter(
                name="remote_path",
                cli_name="remote_path",
                display_name="Upload path (with filename)",
                type=ParameterType.String,
                description="Provide the path where the file will go (include new filename as well)"
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Must supply arguments")
        raise ValueError("Must supply named arguments or use the modal")

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)

    async def get_files(self, callback: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
        response = PTRPCDynamicQueryFunctionMessageResponse()
        file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            CallbackID=callback.Callback,
            LimitByCallback=False,
            IsDownloadFromAgent=False,
            IsScreenshot=False,
            IsPayload=False,
            Filename=""
        ))
        if file_resp.Success:
            file_names = list({f.Filename for f in file_resp.Files})
            response.Success = True
            response.Choices = file_names
        else:
            await SendMythicRPCOperationEventLogCreate(MythicRPCOperationEventLogCreateMessage(
                CallbackId=callback.Callback,
                Message=f"Failed to get files: {file_resp.Error}",
                MessageLevel="warning"
            ))
            response.Error = f"Failed to get files: {file_resp.Error}"
        return response


class UploadCommand(CommandBase):
    cmd = "upload"
    needs_admin = False
    help_cmd = "upload"
    description = (
        "Upload a file to the target machine by selecting a file already uploaded to Mythic."
    )
    version = 1
    author = "@Oblivion"
    supported_ui_features = ["file_browser:upload"]
    argument_class = UploadArguments
    attributes = CommandAttributes(
        builtin=False,
        supported_os=[SupportedOS.Windows],
        suggested_command=True
    )

    async def create_go_tasking(self, taskData: MythicCommandBase.PTTaskMessageAllData) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(TaskID=taskData.task.ID, Success=True)
        try:
            filename = taskData.args.get_arg("file")
            file_resp = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
                TaskID=taskData.task.ID,
                Filename=filename,
                LimitByCallback=False,
                MaxResults=1
            ))

            if not file_resp.Success:
                raise Exception("Error from Mythic trying to search files:\n" + str(file_resp.Error))

            if len(file_resp.Files) == 0:
                raise Exception("Failed to find the named file. Have you uploaded it before? Was it deleted?")

            file = file_resp.Files[0]
            taskData.args.remove_arg("file")
            taskData.args.add_arg("file", file.AgentFileId)

            remote_path = taskData.args.get_arg("remote_path")
            response.DisplayParams = f"-file {file.Filename} -remote_path {remote_path}"

        except Exception as e:
            raise Exception("Error from Mythic: " + str(sys.exc_info()[-1].tb_lineno) + " : " + str(e))

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
