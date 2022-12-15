import idaapi
import idautils
import idc
from typing import *
import sqlite3
import pickle

"""
VulnDiff - An IDAPython script that helps you audit diff's between unpatched and patched versions of a binary.

It will display a list of all diffed functions as a result from a bindiff file and will check if any of them contain 
one of the target functions.
The output is supposed to be searched, sorted and filtered interactively using IDA's built-in methods.
You can track your progress by marking a "checked" function after you finished reversing it or "interesting" if you
think you should return to it later or share with another researcher by giving him your db file.


"""

__author__ = "Ilan Dudnik"

DIFF_PATH = "writeHere.BinDiff"
DB_PATH = "VulnDiff-db"
UPPER_BOUND = 0.99
LOWER_BOUND = 0.9
TARGET_FUNCTIONS = set(
    [
        "_recvfrom",
        "_recvmsg",
        "_memcpy",
        "_scanf",
        "_mempcpy",
        "_strstr",
        "_memmove",
        "_strcpy",
        "_stpcpy",
        "_strncpy",
        "_strcat",
        "_strncat",
        "_sprintf",
        "_vsprintf",
        "_snprintf",
        "_vsnprintf",
        "_gets",
    ]
)


class DiffFunction:
    def __init__(self, ea, name, similarity, vulnMethod, interesting, checked):
        self.ea = ea
        self.name = name
        self.similarity = similarity
        self.vulnMethod = vulnMethod
        self.interesting = interesting
        self.checked = checked


class DiffViewer(idaapi.Choose):
    def __init__(
        self, title, flags=0, width=None, height=None, embedded=False, modal=False
    ):
        idaapi.Choose.__init__(
            self,
            title,
            [ 
                ["Function Name", 20 | idaapi.CHCOL_FNAME],
                ["Address", 8 | idaapi.CHCOL_FNAME],
                ["Similarity", 8 | idaapi.CHCOL_FNAME],
                ["Vuln Method", 20 | idaapi.CHCOL_FNAME],
                ["Checked", 20 | idaapi.CHCOL_FNAME],
                ["Interesting", 20 | idaapi.CHCOL_FNAME],
            ],
            flags=flags
            | idaapi.Choose.CH_CAN_EDIT  # Used for interesting option
            | idaapi.Choose.CH_CAN_REFRESH 
            | idaapi.Choose.CH_CAN_INS  # Used for checked option
            | idaapi.Choose.CH_CAN_DEL,  # Save
            width=width,
            height=height,
            embedded=embedded,
        )
        self.items = []
        self.popup_names = ["Checked", "Save", "Interesting?", "Refresh"]

    def OnClose(self):
        self.items = []

    def OnSelectLine(self, n: int):
        idaapi.jumpto(self.items[n].ea)

    def OnGetLine(self, n: int):
        return self._make_choser_entry(n)

    def OnRefresh(self, n):
        return None

    def OnEditLine(self, n: int):
        """set the interesting field"""

        if self.items[n].interesting:
            self.items[n].interesting = ""
        else:
            self.items[n].interesting = "*"        
        return (idaapi.Choose.ALL_CHANGED, n)

    def OnInsertLine(self, n: int):
        """set the checked field"""

        if self.items[n].checked:
            self.items[n].checked = ""
        else:
            self.items[n].checked = "*"
        return (idaapi.Choose.ALL_CHANGED, n)

    def OnDeleteLine(self, n): 
        """save the progress"""

        with open(DB_PATH, "wb") as f:
            modified = {}
            for item in diffedFunctions:
                if item.checked == "*" or item.interesting == "*":
                    # f.write(item)
                    modified[item.ea] = (item.checked, item.interesting)
            pickle.dump(modified, f, protocol=pickle.HIGHEST_PROTOCOL)
            print("Content Saved")

    def OnGetSize(self):
        n = len(self.items)
        return n

    def feed(self, data: DiffFunction):
        """feed the item and if address already exist in db set the relevant fields"""

        if data.ea in db:
            data.checked = db[data.ea][0]
            data.interesting = db[data.ea][1]
        self.items.append(data)
        self.Refresh()
        return

    def _make_choser_entry(self, n: int):
        """set the values in the row"""

        ea = str(hex(self.items[n].ea))
        name = "%s" % self.items[n].name
        similarity = "%.2f" % float(self.items[n].similarity)
        vulnMethod = "%s" % self.items[n].vulnMethod
        interesting = "%s" % self.items[n].interesting
        checked = "%s" % self.items[n].checked

        return [name, ea, similarity, vulnMethod, checked, interesting]


def get_calls_to_functions(func_ea: int) -> set:
    """Get all function calls inside a function"""

    function_calls = []
    for line_ea in list(
        idautils.FuncItems(func_ea)
    ):  # get list of all instructions of a function
        if ida_ua.ua_mnem(line_ea) == "call":
            operand = idc.print_operand(
                line_ea, 0
            )  # get the call address(left operand)
            function_calls.append(operand)
    return set(function_calls)


AddressNamePair = Tuple[int, str, float]

class BinDiffParser:
    """Parses the bindiff database"""

    def __init__(self, bindiff_db_path: str):
        self.con = sqlite3.connect(bindiff_db_path)
        self.cur = self.con.cursor()

    def get_different_functions(self) -> List[AddressNamePair]:
        query_result = self.cur.execute(
            f"SELECT address1, name1, similarity FROM function WHERE similarity >= {LOWER_BOUND} AND similarity <= {UPPER_BOUND}"
        )
        return query_result.fetchall()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.cur.close()
        self.con.close()


# -----------------------------------------------------------------------------

print("\n" + "=" * 40)
print(r" __      __    _       _____  _  __  __")
print(r" \ \    / /   | |     |  __ \(_)/ _|/ _|")
print(r"  \ \  / /   _| |_ __ | |  | |_| |_| |_ ")
print(r"   \ \/ / | | | | '_ \| |  | | |  _|  _|")
print(r"    \  /| |_| | | | | | |__| | | | | |  ")
print(r"     \/  \__,_|_|_| |_|_____/|_|_| |_|  ")
print("=" * 40)

aborted = False
db = {}
with open(DB_PATH, "rb") as f:
    db = pickle.load(f)

diffedFunctions = []

"""Get the diffed functions"""
with BinDiffParser(DIFF_PATH) as bindiff:
    for ea, func_name, similarity in bindiff.get_different_functions():
        calls = set(get_calls_to_functions(ea))
        if i := calls.intersection(TARGET_FUNCTIONS):
            diffedFunctions.append(
                DiffFunction(ea, idc.get_func_name(ea), str(similarity), list(i), "", "")
                    )
        else:
            diffedFunctions.append(
                DiffFunction(ea, idc.get_func_name(ea), str(similarity), None, "", "")
                )

diffedLen = len(diffedFunctions)
msg("Found %d Diffed Functions." % (diffedLen))

choser = DiffViewer("DiffViewer")
choser.Show()

idaapi.show_wait_box("Working...")
for idx, item in enumerate(diffedFunctions):
    choser.feed(item)

    if idaapi.user_cancelled():
        aborted = True
        break

idaapi.hide_wait_box()
if aborted:
    idaapi.warning("Aborted.")
