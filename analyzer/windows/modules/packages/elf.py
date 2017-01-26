from lib.common.abstracts import Package


class ELF(Package):
    """ Dump linux ELF file information to file.

    """
    PATHS = [
        ("SystemRoot", "system32", "cmd.exe"),
    ]

    def start(self, path):
        cmd_path = self.get_path("cmd.exe")
        dump_cmd = "bin/dumpbin.exe"
        cmd_args = "/c start /wait \"\" \"{0} {1}\"".format(dump_cmd, path)
        return self.execute(cmd_path, cmd_args, path)
