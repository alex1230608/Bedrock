import numpy as np
import cdfscript.func

class MyZipf:
    """ My implementation of zipf to support a <= 1 """
    def __init__(self, a = 1, N = 10):
        self.a = a
        self.N = N
        self.cdf = [0]*N
        for i in range(1, N+1):
            self.cdf[i-1] = 1./float(i**a)
        for i in range(1, N):
            self.cdf[i] += self.cdf[i-1]
        # print (self.cdf)
    def sample(self, m):
        rands = np.random.uniform(0, self.cdf[self.N-1], m)
        # print (rands)
        ret = [0]*m
        for j in range(0, m):
            for i in range(0, self.N):
                if rands[j] < self.cdf[i]:
                    ret[j] = i+1
                    break
        return ret
    def test(self):
        print (self.sample(100))

def checkOverlap(range1, range2):
    if max(range1[0], range2[0]) < min(range1[1], range2[1]): # [1, 2], [2, 3] are not considered overlapped when comparing two types
        return True
    return False


class DistrSampler:
    def get_samples(self, count):
        pass

class ZipfSampler(DistrSampler):
    def __init__(self, a, maxObjSize):
        self.generator = np.random.default_rng()
        self.a = a
        self.maxObjSize = maxObjSize

    def get_samples(self, count):
        ret = self.generator.zipf(self.a, count)
        for i in range(0, count):
            while ret[i] > self.maxObjSize:
                ret[i] = self.generator.zipf(self.a)
        return ret

class OsdiTwemSampler(DistrSampler):
    def __init__(self, unit):
        self.unit = unit

    def get_samples(self, count):
        ret = [int(cdfscript.func.osdi_twem_f()/self.unit) for i in range(count)]
        return ret

class IdiadaSampler(DistrSampler):
    def __init__(self, unit):
        self.unit = unit

    def get_samples(self, count):
        ret = [int(cdfscript.func.idiada_f()/self.unit) for i in range(count)]
        return ret

class ArcturSampler(DistrSampler):
    def __init__(self, unit):
        self.unit = unit

    def get_samples(self, count):
        ret = [int(cdfscript.func.arctur_f()/self.unit) for i in range(count)]
        return ret


def gen_ranges(sampler: DistrSampler, m, ACL_UNIT, addrSpace, rwRatio):
    policy_spec = [[], []]
    # myZipf = MyZipf(a, maxObjSize)
    # objSizes = myZipf.sample(m)
    objSizes = sampler.get_samples(m)
    for i in range(0, m):
        # print ("%d %d %d" %(addrSpace[0], addrSpace[1]-objSizes[i], objSizes[i]))
        objStart = np.random.randint(addrSpace[0], addrSpace[1]-objSizes[i]+1, dtype=np.uint64) * ACL_UNIT
        objEnd = objStart + objSizes[i] * ACL_UNIT
        rw = np.random.randint(0, 100)
        if rw < rwRatio:
            rw = 0
        else:
            rw = 1
        policy_spec[rw].append([objStart, objEnd])

    # print ("original read")
    # print (policy_spec[0])
    # print ("original write")
    # print (policy_spec[1])
    # if len(policy_spec[0]) > 100:
    #     print(policy_spec[0])
    #     sizes = list(map(lambda x: x[1]-x[0], policy_spec[0]))
    #     print(sizes)
    #     sizes = list(map(str, sorted(sizes)))
    #     print(sizes)
    #     print("\n".join(sizes[0::int(len(sizes)/10)]))

    #combine overlapped objects in the same type
    for rw in range(0, 2):
        policy_spec[rw].sort(key = lambda x: x[0])
        after_merge = []
        curMin = -1
        curMax = -1
        for i in range(len(policy_spec[rw])):
            objRange = policy_spec[rw][i]
            if objRange[0] > curMax: # consecutive ranges should be merged
                if i != 0:
                    after_merge.append([curMin, curMax])
                curMin = objRange[0]
                curMax = objRange[1]
            else:
                if objRange[1] > curMax:
                    curMax = objRange[1]
        if curMax != -1 and [curMin, curMax] not in after_merge:
            after_merge.append([curMin, curMax])
        policy_spec[rw] = after_merge

    # print ("merged read")
    # print (policy_spec[0])
    # print ("merged write")
    # print (policy_spec[1])

    # generate readable+writable rule based on overlap between the two types
    # also remove any duplicate rules covered by it
    i = 0
    j = 0
    remove_set = [set(), set()]
    ret = [[], [], []]
    while i < len(policy_spec[0]) and j < len(policy_spec[1]):
        if checkOverlap(policy_spec[0][i], policy_spec[1][j]):
            objStart = max(policy_spec[0][i][0], policy_spec[1][j][0])
            objEnd = min(policy_spec[0][i][1], policy_spec[1][j][1])
            if [objStart, objEnd] == policy_spec[0][i]:
                remove_set[0].add(i)
            if [objStart, objEnd] == policy_spec[1][j]:
                remove_set[1].add(j)
            ret[0].append([objStart, objEnd])
        if policy_spec[0][i][1] > policy_spec[1][j][1]:
            j += 1
        else:
            i += 1

    for rw in range(0, 2):
        for i in range(len(policy_spec[rw])):
            if i not in remove_set[rw]:
                ret[rw+1].append(policy_spec[rw][i])

    # print ("readWrite")
    # print (ret[0])
    # print ("read")
    # print (ret[1])
    # print ("write")
    # print (ret[2])

    # print ("number of readWrite ranges: %d" % len(ret[0]))
    # print ("number of read ranges: %d" % len(ret[1]))
    # print ("number of write ranges: %d" % len(ret[2]))
    return ret

def test_gen_ranges():
    a = 1.1
    m = 5
    maxObjSize = 10
    ACL_UNIT = 1
    addrSpace = [0, 20/ACL_UNIT]

    return gen_ranges(a, m, maxObjSize, ACL_UNIT, addrSpace, 50)

def main():
    a = 1.1
    m = 5
    maxObjSize = 1000000 # 4GB
    ACL_UNIT = 4096 # 1 page
    addrSpace = [0, 2**40/ACL_UNIT] # 1TB

    gen_ranges(a, m, maxObjSize, ACL_UNIT, addrSpace, 50)

if __name__ == "__main__":
    # main()
    myZipf = MyZipf(1.1, 1000000)
    myZipf.test()
