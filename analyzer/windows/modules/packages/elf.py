from lib.common.abstracts import Package


class ELF(Package):
    """Generic analysis package.
    The sample is started using START command in a cmd.exe prompt.
    """
    PATHS = [
        ("SystemRoot", "system32", "cmd.exe"),
    ]

    def start(self, path):
        cmd_path = self.get_path("cmd.exe")
        cmd_args = "/c start /wait \"\" \"echo This is a Linux ELF file.\""
        return self.execute(cmd_path, cmd_args, path)
