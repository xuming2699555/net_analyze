# -*- coding: UTF-8 -*-


# ip表示的辅助函数
class ipAddrConverter():
    def __init__(self, ip_addr):
        self.ip_addr = ip_addr

    @staticmethod
    def _get_bin(target):
        if not target.isdigit():
            raise Exception('bad ip address')
        target = int(target)
        assert target < 256, 'bad ip address'
        res = ''
        temp = target
        for t in range(8):
            a, b = divmod(temp, 2)
            temp = a
            res += str(b)
            if temp == 0:
                res += '0' * (7 - t)
                break
        return res[::-1]

    def to_32_bin(self):
        temp_list = self.ip_addr.split('.')
        assert len(temp_list) == 4, 'bad ip address'
        return ''.join(list(map(self._get_bin, temp_list)))
