import pickle

import scapy.plist
from scapy.all import *
from snap7 import util
import snap7


#本机中的snap7.dll路径，该动态库为西门子上位机开发中最常用的开源库
from snap7.exceptions import Snap7Exception
from snap7.types import S7DataItem, S7AreaDB, WordLen, buffer_type, Areas, buffer_size

#定义Snap7.dll的位置
from utils.utils import get_time_str

SNAP7_DLL_PATH = 'C:\ProgramData\Miniconda3\envs\My_SCADA\Lib\site-packages\snap7\lib\snap7.dll'
#定义被测试的PLC信息，包括ip、型号
#MY_PLC_INFO = {'ip':'192.168.3.11', 'type':'Fake', 'rack':0, 'slot':0, 'tcpport':102, 'interface':'以太网'}
MY_PLC_INFO = {'ip':'192.168.0.1', 'type':'200 smart', 'rack':0, 'slot':0, 'tcpport':102, 'interface':'以太网'}



#定义抓包保存路径
OUTPUT_DIR = '.\\'+ MY_PLC_INFO['type'] + '\\' + get_time_str() + '\\'
os.system('mkdir "' + OUTPUT_DIR+'"')
#定义pickle导入路径（需要fuzzing的文件夹）
INPUT_DIR = 'D:\\Siemens\\Simatic s7-200 SMART\\2022-03-07-14_32_17\\'


# 自定义抓包装饰器，修饰MyTest类方法，方便对各功能进行抓包和其他处理
def capture(func):
    def wrapper(self):
        sniff_work = AsyncSniffer(iface=MY_PLC_INFO['interface'])
        sniff_work.start()
        time.sleep(2.5)
        func(self)
        time.sleep(1)
        sniff_work.stop()
        print(func.__name__, end=': ')
        print(sniff_work.results)
        # 保存pcap
        wrpcap(filename=OUTPUT_DIR + func.__name__ + get_time_str() +'.pcap', pkt = sniff_work.results)
        # 序列化PacketList对象
        with open(OUTPUT_DIR + func.__name__ + get_time_str() + ".pickle", 'wb') as f:  # 打开文件
            pickle.dump(sniff_work.results, f)
            f.close()
    return wrapper



def connect_smart200(ip:str, rack = 0, slot = 0, tcpport = 102):
    client = snap7.client.Client(lib_location = SNAP7_DLL_PATH)
    client.set_connection_type(2)
    client.connect(ip, rack, slot, tcpport)
    is_successful = client.get_connected()
    assert is_successful == True
    return client

def load_pickle():
    path = INPUT_DIR
    filenames = os.listdir(path)
    picklenames = filter(lambda  x : x.endswith('.pickle'), filenames)
    pickles_dict: Dict[str, scapy.plist.PacketList] = {} #返回类型为字典，键值对为<序列化文件名>:<PacketList>
    for picklename in picklenames: #遍历文件夹
        with open( path + picklename, 'rb') as f:
            pickle_loaded = pickle.load(f)
            pickles_dict[picklename] = pickle_loaded
    return pickles_dict

class MyTest:
    @capture
    def __init__(self):
        ip = MY_PLC_INFO['ip']
        rack = MY_PLC_INFO['rack']
        slot = MY_PLC_INFO['slot']
        tcpport = MY_PLC_INFO['tcpport']
        self.client = snap7.client.Client(lib_location=SNAP7_DLL_PATH)
        self.client.set_connection_type(2)
        self.client.connect(ip, rack, slot, tcpport)
        is_successful = self.client.get_connected()
        assert is_successful == True
        print("* MyTest:connection successful! * ", get_time_str())

    @capture
    def test_db_read(self):
        size = random.randint(1, 40)
        start = random.randint(0, 30)
        db = 1
        data = bytearray([random.randint(0,127) for elem in range(size)])
        self.client.db_write(db_number=db, start=start, data=data)
        result = self.client.db_read(db_number=db, start=start, size=size)
        assert all(data[i] == result[i] for i in range(len(result))), 'They aren\'t always equal'

    @capture
    def test_db_write(self):
        size = 40
        data = bytearray(size)
        self.client.db_write(db_number=1, start=0, data=data)

    @capture
    def test_db_get(self):
        try:
            self.client.db_get(db_number=0)
        except Snap7Exception:
            print('CPU : Item not available')

    @capture
    def test_read_multi_vars(self):
        db = 1
        # build and write test values
        test_value_1 = 129.5
        test_bytes_1 = bytearray(struct.pack('>f', test_value_1))
        self.client.db_write(db, 0, test_bytes_1)

        test_value_2 = -129.5
        test_bytes_2 = bytearray(struct.pack('>f', test_value_2))
        self.client.db_write(db, 4, test_bytes_2)

        test_value_3 = 123
        test_bytes_3 = bytearray([0, 0])
        util.set_int(test_bytes_3, 0, test_value_3)
        self.client.db_write(db, 8, test_bytes_3)

        test_values = [test_value_1, test_value_2, test_value_3]

        # build up our requests
        data_items = (S7DataItem * 3)()

        data_items[0].Area = ctypes.c_int32(S7AreaDB)
        data_items[0].WordLen = ctypes.c_int32(WordLen.Byte.value)
        data_items[0].Result = ctypes.c_int32(0)
        data_items[0].DBNumber = ctypes.c_int32(db)
        data_items[0].Start = ctypes.c_int32(0)
        data_items[0].Amount = ctypes.c_int32(4)

        data_items[1].Area = ctypes.c_int32(S7AreaDB)
        data_items[1].WordLen = ctypes.c_int32(WordLen.Byte.value)
        data_items[1].Result = ctypes.c_int32(0)
        data_items[1].DBNumber = ctypes.c_int32(db)
        data_items[1].Start = ctypes.c_int32(4)
        data_items[1].Amount = ctypes.c_int32(4)

        data_items[2].Area = ctypes.c_int32(S7AreaDB)
        data_items[2].WordLen = ctypes.c_int32(WordLen.Byte.value)
        data_items[2].Result = ctypes.c_int32(0)
        data_items[2].DBNumber = ctypes.c_int32(db)
        data_items[2].Start = ctypes.c_int32(8)
        data_items[2].Amount = ctypes.c_int32(2)

        for di in data_items:
            dataBuffer = ctypes.create_string_buffer(di.Amount)
            pBuffer = ctypes.cast(ctypes.pointer(dataBuffer),
                                  ctypes.POINTER(ctypes.c_uint8))
            di.pData = pBuffer

        result, data_items = self.client.read_multi_vars(data_items)

        result_values = []
        byte_to_value = [util.get_real, util.get_real, util.get_int]

        for i in range(len(data_items)):
            btv = byte_to_value[i]
            di = data_items[i]
            value = btv(di.pData, 0)
            result_values.append(value)

        assert result_values[0] == test_values[0]
        assert result_values[1] == test_values[1]
        assert result_values[2] == test_values[2]

    @capture
    def test_upload(self):
        try:
            self.client.upload(1)
        except Snap7Exception:
            print('test_as_upload')

    @capture
    def test_as_upload(self):
        _buffer = buffer_type()
        size = ctypes.c_int(ctypes.sizeof(_buffer))
        self.client.as_upload(1, _buffer, size)
        try:
            self.client.wait_as_completion(500)
        except Snap7Exception:
            print("test_as_upload")

    @capture
    def test_download(self):
        data = bytearray(64)
        try:
            self.client.download(block_num=1, data=data)
        except Snap7Exception:
            print('CLI : Invalid block size')


    @capture
    def test_read_area(self):
        amount = 1
        start = 1

        # DB
        area = Areas.DB
        dbnumber = 1
        data = bytearray(b'\x11')
        self.client.write_area(area, dbnumber, start, data)
        res = self.client.read_area(area, dbnumber, start, amount)
        assert all(data[i] == bytearray(res)[i] for i in range(len(data))), 'They aren\'t always equal'

        # TTM
        area = Areas.TM
        dbnumber = 0
        data = bytearray(b'\x12\x34')
        try:
            self.client.write_area(area, dbnumber, start, data)
            res = self.client.read_area(area, dbnumber, start, amount)
            assert all(data[i] == bytearray(res)[i] for i in range(len(data))), 'They aren\'t always equal'
        except Snap7Exception:
            print('CLI : function refused by CPU (Unknown error)')

        # CT
        area = Areas.CT
        dbnumber = 0
        data = bytearray(b'\x13\x35')
        try:
            self.client.write_area(area, dbnumber, start, data)
            res = self.client.read_area(area, dbnumber, start, amount)
            assert all(data[i] == bytearray(res)[i] for i in range(len(data))), 'They aren\'t always equal'
        except Snap7Exception:
            print('CLI : function refused by CPU (Unknown error)')

    @capture
    def test_write_area(self):
        # DB
        area = Areas.DB
        dbnumber = 1
        start = 1
        data = bytearray(b'\x11')
        self.client.write_area(area, dbnumber, start, data)
        res = self.client.read_area(area, dbnumber, start, 1)
        assert all(data[i] == bytearray(res)[i] for i in range(len(data))), 'They aren\'t always equal'

        # TM
        area = Areas.TM
        dbnumber = 0
        timer = bytearray(b'\x12\x00')

        try:
            res = self.client.write_area(area, dbnumber, start, timer)
            res = self.client.read_area(area, dbnumber, start, 1)
            assert all(timer[i] == bytearray(res)[i] for i in range(len(timer))), 'They aren\'t always equal'
        except:
            print('CLI : function refused by CPU (Unknown error)')

        # CT
        area = Areas.CT
        dbnumber = 0
        timer = bytearray(b'\x13\x00')
        try:
            res = self.client.write_area(area, dbnumber, start, timer)
            res = self.client.read_area(area, dbnumber, start, 1)
            assert all(timer[i] == bytearray(res)[i] for i in range(len(timer))), 'They aren\'t always equal'
        except:
            print('CLI : function refused by CPU (Unknown error)')

    @capture
    def test_list_blocks(self):
        self.client.list_blocks()

    @capture
    def test_list_blocks_of_type(self):
        self.client.list_blocks_of_type('DB', 10)

    @capture
    def test_get_block_info(self):
        """test Cli_GetAgBlockInfo"""
        self.client.get_block_info('DB', 1)

    @capture
    def test_get_cpu_state(self):
        """this tests the get_cpu_state function"""
        print(self.client.get_cpu_state())

    @capture
    def test_set_session_password(self):
        password = 'abcdefgh'
        try:
            self.client.set_session_password(password)
        except Snap7Exception:
            print('set_session_password failed!')

    @capture
    def test_clear_session_password(self):
        try:
            self.client.clear_session_password()
        except Snap7Exception:
            print('clear_session_password failed!')

    @capture
    def test_set_connection_params(self):
        self.client.set_connection_params("10.0.0.2", 10, 10)

    @capture
    def test_set_connection_type(self):
        self.client.set_connection_type(1)
        self.client.set_connection_type(2)
        self.client.set_connection_type(3)
        self.client.set_connection_type(20)

    @capture
    def test_get_connected(self):
        self.client.get_connected()

    @capture
    def test_ab_read(self):
        start = 1
        size = 1
        data = bytearray(size)
        self.client.ab_write(start=start, data=data)
        self.client.ab_read(start=start, size=size)

    @capture
    def test_ab_write(self):
        size = random.randint(1, 40)
        start = random.randint(0, 30)
        data = bytearray([random.randint(0, 127) for elem in range(size)])
        result = self.client.ab_write(start=start, data=data)


    @capture
    def test_as_ab_read(self):
        expected = b'\x10\x01'
        self.client.ab_write(0, bytearray(expected))

        wordlen = WordLen.Byte
        type_ = snap7.types.wordlen_to_ctypes[wordlen.value]
        buffer = (type_ * 2)()
        self.client.as_ab_read(0, 2, buffer)
        result = self.client.wait_as_completion(500)

    @capture
    def test_as_ab_write(self):
        data = b'\x01\x11'
        response = self.client.as_ab_write(0, bytearray(data))
        try:
            result = self.client.wait_as_completion(500)
        except Snap7Exception:
            print('CLI : function refused by CPU (Unknown error)')

    @capture
    def test_compress(self):
        time_ = 1000
        try:
            self.client.compress(time_)
        except Snap7Exception:
            print('CPU : Cannot compress')


    @capture
    def test_as_compress(self):
        time_ = 1000
        try:
            response = self.client.as_compress(time_)
            result = self.client.wait_as_completion(500)
        except Snap7Exception:
            print('CPU : Cannot as_compress')

    @capture
    def test_set_param(self):
        values = (
            (snap7.types.PingTimeout, 800),
            (snap7.types.SendTimeout, 15),
            (snap7.types.RecvTimeout, 3500),
            (snap7.types.SrcRef, 128),
            (snap7.types.DstRef, 128),
            (snap7.types.SrcTSap, 128),
            (snap7.types.PDURequest, 470),
        )
        for param, value in values:
            self.client.set_param(param, value)


    @capture
    def test_get_param(self):
        expected = (
            (snap7.types.RemotePort, MY_PLC_INFO['tcpport']),
            (snap7.types.PingTimeout, 750),
            (snap7.types.SendTimeout, 10),
            (snap7.types.RecvTimeout, 3000),
            (snap7.types.SrcRef, 256),
            (snap7.types.DstRef, 0),
            (snap7.types.SrcTSap, 256),
            (snap7.types.PDURequest, 480),
        )
        for param, value in expected:
            self.client.get_param(param)

    @capture
    def test_as_copy_ram_to_rom(self):
        try:
            response = self.client.as_copy_ram_to_rom(timeout=10)
            self.client.wait_as_completion(11000)
            assert response == 0
        except Snap7Exception:
            print(" b'CPU : Cannot copy RAM to ROM'")

    @capture
    def test_as_ct_read(self):
        # Cli_AsCTRead
        expected = b'\x10\x01'
        try:
            self.client.ct_write(0, 1, bytearray(expected))
            type_ = snap7.types.wordlen_to_ctypes[WordLen.Counter.value]
            buffer = (type_ * 1)()
            self.client.as_ct_read(0, 1, buffer)
            self.client.wait_as_completion(500)
            assert all(expected[i] == bytearray(buffer)[i] for i in range(len(expected))), 'They aren\'t always equal'
        except Snap7Exception:
            print('CLI : function refused by CPU (Unknown error)')



    @capture
    def test_as_ct_write(self):
        # Cli_CTWrite
        data = b'\x01\x11'
        try:
            response = self.client.as_ct_write(0, 1, bytearray(data))
            result = self.client.wait_as_completion(500)
        except Snap7Exception:
            print('CLI : function refused by CPU (Unknown error)')

    @capture
    def test_as_db_fill(self):
        filler = 31
        expected = bytearray(filler.to_bytes(1, byteorder='big') * 100)
        try:
            self.client.db_fill(1, filler)
            self.client.wait_as_completion(500)
            result = self.client.db_read(1, 0, 100)
            assert all(expected[i] == bytearray(result)[i] for i in range(len(expected))), 'They aren\'t always equal'
        except Snap7Exception:
            print('CLI : invalid param(s) supplied')

    @capture
    def test_as_db_get(self):
        db_number = 0
        _buffer = buffer_type()
        size = ctypes.c_int(buffer_size)
        self.client.as_db_get(db_number, _buffer, size)
        try:
            self.client.wait_as_completion(500)
            result = bytearray(_buffer)[:size.value]
            assert 100 == len(result)
        except Snap7Exception:
            print('CPU : Item not available')

    @capture
    def test_as_db_read(self):
        size = 40
        start = 0
        db = 1
        expected = bytearray(40)
        self.client.db_write(db_number=db, start=start, data=expected)

        wordlen = WordLen.Byte
        type_ = snap7.types.wordlen_to_ctypes[wordlen.value]
        data = (type_ * size)()
        self.client.as_db_read(db, start, size, data)
        self.client.wait_as_completion(500)
        assert all(expected[i] == bytearray(data)[i] for i in range(len(data))), 'They aren\'t always equal'

    @capture
    def test_as_db_write(self):
        size = 40
        data = bytearray([i for i in range(0,40)])
        wordlen = WordLen.Byte
        type_ = snap7.types.wordlen_to_ctypes[wordlen.value]
        size = len(data)
        result = (type_ * size).from_buffer_copy(data)
        self.client.as_db_write(db_number=1, start=0, size=size, data=result)
        self.client.wait_as_completion(500)
        # for i in range(0, len(result)):
        #     print(result[i], end=" ")
        assert all(result[i] == bytearray(data)[i] for i in range(len(data))), 'They aren\'t always equal'

    @capture
    def test_plc_stop(self):
        self.client.plc_stop()

    # 只有在有后备电池时才能实现真正的"热启动"，所有的数据都会保持其最后有效值。程序从断点处执行，
    @capture
    def test_plc_hot_start(self):
        self.client.plc_hot_start()

    @capture
    def test_plc_cold_start(self):
        self.client.plc_cold_start()

    @capture
    def test_get_pdu_length(self):
        pduRequested = self.client.get_param(10)
        pduSize = self.client.get_pdu_length()
        print('param10: ', pduRequested)
        print('pduSize: ', pduSize)

    @capture
    def test_get_cpu_info(self):
        expected = (
            ('ModuleTypeName', ''),
            ('SerialNumber', ''),
            ('ASName', ''),
            ('Copyright', ''),
            ('ModuleName', '')
        )
        try:
            cpuInfo = self.client.get_cpu_info()
            print(cpuInfo)
        except Snap7Exception:
            print("get_cpu_info b CPU: Item not available")

    @capture
    def test_get_plc_time(self):
        print(self.client.get_plc_datetime())

    @capture
    def test_set_plc_datetime(self):
        new_dt = datetime(2011, 1, 1, 1, 1, 1, 0)
        self.client.set_plc_datetime(new_dt)

    @capture
    def test_tm_read(self):
        # Cli_TMRead
        data = b'\x10\x01'
        try:
            result = self.client.tm_read(0, 1)
        except Snap7Exception:
            print('CLI : function refused by CPU (Unknown error)')

    @capture
    def test_tm_write(self):
        # Cli_TMWrite
        data = b'\x10\x01'
        try:
            assert 0 == self.client.tm_write(0, 1, bytearray(data))
        except Snap7Exception:
            print('CLI : function refused by CPU (Unknown error)')

    @capture
    def test_write_multi_vars(self):
        # Cli_WriteMultiVars
        items_count = 3
        items = []
        areas = [Areas.DB, Areas.CT, Areas.TM]
        expected_list = []
        for i in range(0, items_count):
            item = S7DataItem()
            item.Area = ctypes.c_int32(areas[i].value)
            wordlen = WordLen.Byte
            item.WordLen = ctypes.c_int32(wordlen.value)
            item.DBNumber = ctypes.c_int32(1)
            item.Start = ctypes.c_int32(0)
            item.Amount = ctypes.c_int32(4)
            data = (i + 1).to_bytes(1, byteorder='big') * 4
            array_class = ctypes.c_uint8 * len(data)
            cdata = array_class.from_buffer_copy(data)
            item.pData = ctypes.cast(cdata, ctypes.POINTER(array_class)).contents
            items.append(item)
            expected_list.append(data)
        result = self.client.write_multi_vars(items)


    # 测试用例编排，可以考虑后续引入有限状态机
    def test_orchestration(self):
        self.test_get_pdu_length()  #通过LLDP协商
        self.test_db_read()
        self.test_db_write()
        self.test_db_get() # s7 200 smart 可能不支持
        self.test_read_multi_vars()
        self.test_upload()  #s7 200 用到0x1d功能码，start upload，但是返回error
        self.test_as_upload()
        # self.test_download() # Invalid block size
        self.test_read_area() # function refused by CPU (Unknown error)
        self.test_write_area() # function refused by CPU (Unknown error)
        self.test_list_blocks()
        self.test_list_blocks_of_type()
        self.test_get_block_info()
        self.test_get_cpu_state() # s7 200 smart 可能不支持
        self.test_set_session_password() # s7 200 smart 可能不支持
        self.test_clear_session_password() # s7 200 smart 可能不支持
        # self.test_set_connection_params()
        # self.test_set_connection_type()
        # self.test_get_connected()
        self.test_ab_read()
        self.test_ab_write()
        self.test_as_ab_read()
        self.test_as_ab_write()
        self.test_compress()
        self.test_as_compress()
        # self.test_set_param()
        # self.test_get_param()
        self.test_as_copy_ram_to_rom() # s7 200 smart 可能不支持
        self.test_as_ct_read()
        self.test_as_ct_write()
        self.test_as_db_fill()
        self.test_as_db_get()
        self.test_as_db_read()
        self.test_as_db_write()
        #self.test_get_pdu_length()
        self.test_get_cpu_info() # s7 200 smart 可能不支持
        self.test_get_plc_time()
        self.test_set_plc_datetime() # 设置plc时间，会对业务造成影响!
        self.test_tm_read() #对于200 smart，会返回Accessing object is not allowed
        self.test_tm_write() #对于200 smart，会返回Accessing object is not allowed
        self.test_write_multi_vars()
        self.test_plc_stop()
        time.sleep(10)
        self.test_plc_hot_start()
        time.sleep(10)
        self.test_plc_cold_start()
        time.sleep(10)

class MyFuzz():
    def __init__(self):
        list_of_PacketList = load_pickle()


class WholeProcess:

    def __init__(self):
        self.test_process()

    @capture
    def test_process(self):
        my_test = MyTest()
        my_test.test_orchestration()

if __name__ == '__main__':
    WholeProcess()






