from lib.common.abstracts import Package


class ELF(Package):
    """ Dump linux ELF file information to file.

    """
    def start(self, path):
        out_file = "readelf_output.txt"
        return self.execute("bin\\readelf.exe", "-a {0} > {1}".format(path, out_file), path)
