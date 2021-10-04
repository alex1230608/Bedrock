import argparse
from datetime import datetime

HDR_LEN = 14+20+8 # ethernet, ip, udp
INTERVAL = 100 # 100ms
def main(args):
    try:
        with open(args.pcap, "r") as fi:
            with open(args.output, "w") as fo:
                start = -1
                prev = 0
                if len(args.targetIpIds) != 0:
                    accBytes = {key: 0 for key in args.targetIpIds}
                if len(args.targetPorts) != 0:
                    accBytes = {key: 0 for key in args.targetPorts}
                for line in fi:
                    tokens = line.split(" ")
                    cur = int(datetime.strptime(tokens[0], "%H:%M:%S.%f").timestamp()*1000)
                    # print ("%d\t%d\t%d\t%d" % (start, cur, prev, cur-start))
                    if start == -1:
                        start = cur
                    dstIpStr = tokens[4]
                    curBytes = int(tokens[7]) + HDR_LEN
                    if cur - start - prev >= INTERVAL:
                        # collect all bytes for interval of time prev+1
                        intervalId = int((prev+1)/INTERVAL) + 1
                        # print ("%d" % intervalId)
                        fo.write ("%d\t" % (intervalId*INTERVAL))
                        for key in accBytes:
                            fo.write ("%d\t" % accBytes[key])
                            accBytes[key] = 0
                        fo.write ("\n")
                        for i in range(intervalId+1, int((cur-start)/INTERVAL)): # all intervals before current interval do not have any bytes
                            fo.write ("%d\t" % (i*INTERVAL))
                            for key in accBytes:
                                fo.write ("0\t")
                            fo.write ("\n")
                        prev = (cur-start)/INTERVAL * INTERVAL
                    if "ds01" in dstIpStr:
                        if len(args.targetIpIds) != 0:
                            srcId = int(tokens[2].split(".")[3])
                        if len(args.targetPorts) != 0:
                            srcId = int(tokens[2].split(".")[4])
                        if srcId in accBytes:
                            accBytes[srcId] += 1  # requesets
                fi.close()
                fo.close()
    except IOError as e:
        print ("Open file failed (%s)" % e)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = 'Get rate plot from pcap')
    parser.add_argument('-p', dest='pcap', required=True, type=str, help='parsed pcap file')
    parser.add_argument('-o', dest='output', required=True, type=str, help='output data for rate plot')
    parser.add_argument('-t', dest='targetIpIds', required=True, nargs='*', type=int, help='list of targeted ip id')
    parser.add_argument('-tp', dest='targetPorts', required=True, nargs='*', type=int, help='list of targeted ports')
    args = parser.parse_args()
    main(args)
