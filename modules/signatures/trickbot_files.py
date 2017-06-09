from lib.cuckoo.common.abstracts import Signature

class TrickBotTaskDelete(Signature):
    name = "TrickBotTaskDelete"
    description = "Exhibits behavior characteristic of TrickBot banking trojan"
    severity = 3
    weight = 3
    categories = ["banking", "trojan"]
    families = ["TrickBot"]
<<<<<<< HEAD
    authors = ["Eoin Miller", "Mark Parsons"]
=======
    authors = ["Eoin Miller"]
>>>>>>> ng/mydev
    minimum = "1.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["DeleteFileW"])

    def on_call(self, call, process):
<<<<<<< HEAD
        if call["api"] == ("DeleteFileW") and (self.get_argument(call, "FileName").endswith("TrickBot.job")
                                               or self.get_argument(call, "FileName").endswith("TrickBot") or
                                               self.get_argument(call, "FileName").endswith("Drivers update.job")
                                               or self.get_argument(call, "FileName").endswith("Tasks\\Bot.job")):
=======
        if call["api"] == ("DeleteFileW") and (self.get_argument(call, "FileName").endswith("TrickBot.job") or self.get_argument(call, "FileName").endswith("TrickBot")):
>>>>>>> ng/mydev
            self.data.append({"file" : self.get_argument(call, "FileName") })
            return True

        return None
