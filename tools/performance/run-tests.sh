#!/bin/sh
#
# Modify the values below and then run script to do performance testing
#
DOMU_ID=winxpsp2               # domain id to use for testing
NUM_LOOPS=10                   # number of readings to get for each test
#
###########################################################################

echo "Pausing before first test..."
sleep 5
echo "Running kernel symbol test..."
sudo ./kern_sym $DOMU_ID $NUM_LOOPS
sleep 10
echo "Running virtual address test..."
sudo ./virt_addr $DOMU_ID $NUM_LOOPS
sleep 10
echo "Running read mem chunk test..."
sudo ./read_mem $DOMU_ID 10 $NUM_LOOPS 1
sleep 10
echo "Running read mem loop test..."
sudo ./read_mem $DOMU_ID 10 $NUM_LOOPS 2
echo "Done!"
