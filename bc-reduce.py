#!/usr/bin/env python
# -*-coding:utf-8 -*

import sys
import json
txs = {}

for djs in sys.stdin:
        try:
                bk = json.loads(djs)
                txid = bk['hash_transaction']
                value = float(bk['output_value'])
                if txid not in txs.keys():
                        txs[txid] = {'count': 1.0, 'total_value': value}
                else:
                        txs[txid]['count'] += 1.0
                        txs[txid]['total_value'] = value + txs[txid]['total_value']
        except:
                continue

for k in txs.keys():
        print('%s\t%f\t%f' %(k, txs[k]['count'], txs[k]['total_value']))