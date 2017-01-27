from lib.common.abstracts import Package


class ELF(Package):
    """ Dump linux ELF file information to file.

    """
    def start(self, path):
        return self.execute("bin\\readelf.exe", "-a {0}".format(path), path)
