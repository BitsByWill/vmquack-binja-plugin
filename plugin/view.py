from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.enums import SegmentFlag
from struct import unpack


class vmquack_view(BinaryView):
    name = 'vmquack'
    long_name = 'my CISC vm for corctf 2021'

    @classmethod
    def is_valid_for_data(self, binaryView):
        sample = binaryView.read(0, 8)
        return b'vmquack' in sample

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.data = data

    def init(self):
        self.arch = Architecture['vmquack']
        self.platform = Architecture['vmquack'].standalone_platform
        vmdata = unpack('Q', self.data[7:15])[0]
        datalen = unpack('Q', self.data[15:23])[0]
        vmtext = unpack('Q', self.data[23:31])[0]
        textlen = unpack('Q', self.data[31:39])[0]
        dataoffset = 39
        textoffset = dataoffset + datalen
        self.add_auto_segment(
            vmdata, datalen + (0x1000 - datalen % 0x1000), dataoffset, datalen,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)
        self.add_auto_segment(
            vmtext, textlen + (0x1000 - textlen % 0x1000), textoffset, textlen,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
        self.add_entry_point(vmtext)
        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return unpack('Q', self.data[23:31])[0]