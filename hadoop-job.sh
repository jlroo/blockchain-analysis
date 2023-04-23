#!/bin/bash
# -*-coding:utf-8 -*

hadoop jar /opt/cloudera/parcels/CDH-7.1.7-1.cdh7.1.7.p0.15945976/jars/hadoop-streaming-3.1.1.7.1.7.0-551.jar \
        -Dmapred.reduce.tasks=1 \
        -input /user/jlr/data/blk02800.dat \
        -output /user/jlr/data/blocks/ \
        -file bc-map.py \
        -file bc-reducer.py \
        -mapper "python bc-map.py" \
        -reducer "python bc-reducer.py"