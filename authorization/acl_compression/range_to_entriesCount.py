import argparse
import operator

import numpy as np

import policy_spec

"""
boundary_masks*: the boundary is between the last f and the first 0. When
calculating the number of entries needed for a range, boundary_masks* is used
to determine when to count the cost for the next level. See
count_entries_boundary for detail.
costs*: For each level, we have cost for current level when there is next
level (costs*[level][1]) and cost when there is no next level
(costs*[level][0]). See count_entries_boundary for detail.

For example, when tech is baseline, we have 16 bits per level, and three
levels in total, so the boundary_masks1 has two boundaries. When tech is
tech#2 without tech#1, we still have three levels, it's just about changing
the way we accumulate the entries in each level. See count_entries for detail.
When tech is tech#1,#2, we only have two levels because the optimization on
page granularity, so we use boundary_masks2. When tech is tech#1,#2,#3, we
have 4 levels, but the cost is calculated separately for each level, and
sometimes the smallest level can have 0 cost because it can be covered by
larger level.
"""


# baseline, tech #2
boundary_masks_list1 = {
    "zipf": {
        "boundary_masks": [
            0xFFFFffffFFFF0000,
            0xFFFFffff00000000,
        ],
        "costs": [
            [1, 1],
            [1, 1],
        ],
    },
    "osdi_twem": {
        "boundary_masks": [
            0xFFFFffffFFFF0000,
            0xFFFFffff00000000,
        ],
        "costs": [
            [1, 1],
            [1, 1],
        ],
    },
    "idiada": {
        "boundary_masks": [
            0xFFFFffffFFFF0000,
            0xFFFFffff00000000,
        ],
        "costs": [
            [1, 1],
            [1, 1],
        ],
    },
    "arctur": {
        "boundary_masks": [
            0xFFFFffffFFFF0000,
            0xFFFFffff00000000,
        ],
        "costs": [
            [1, 1],
            [1, 1],
        ],
    },
}
resource_list1_tofino1 = {
    "zipf": [6500],
    "osdi_twem": [6500],
    "idiada": [6500],
    "arctur": [6500],
}
resource_list1_tofino2 = {
    "zipf": [16250],
    "osdi_twem": [16250],
    "idiada": [16250],
    "arctur": [16250],
}

# tech #1, tech#1,#2
boundary_masks_list2 = {
    "zipf": {
        "boundary_masks": [
            0xFFFFffff00000000,
        ],
        "costs": [
            [1, 1],
        ],
    },
    "osdi_twem": {
        "boundary_masks": [
            0xFFFFffffFF800000,
            0xFFFFf80000000000,
        ],
        "costs": [
            [1, 1],
            [1, 1],
        ],
    },
    "idiada": {
        "boundary_masks": [
            0xFFFFffff00000000,
        ],
        "costs": [
            [1, 1],
        ],
    },
    "arctur": {
        "boundary_masks": [
            0xFFFFffffE0000000,
        ],
        "costs": [
            [1, 1],
        ],
    },
}
resource_list2_1_tofino1 = {
    "zipf": [5850],
    "osdi_twem": [5850],
    "idiada": [5850],
    "arctur": [5850],
}
resource_list2_2_tofino1 = {
    "zipf": [5950],
    "osdi_twem": [5950],
    "idiada": [5950],
    "arctur": [5950],
}
resource_list2_1_tofino2 = {
    "zipf": [14625],
    "osdi_twem": [14625],
    "idiada": [14625],
    "arctur": [14625],
}
resource_list2_2_tofino2 = {
    "zipf": [14875],
    "osdi_twem": [14875],
    "idiada": [14875],
    "arctur": [14875],
}

# tech #1,#2,#3
boundary_masks_list3 = {
    "zipf": {
        "boundary_masks": [
            0xFFFFffffFFFFf000,
            0xFFFFffffFFF00000,
            0xFFFFffff00000000,
        ],
        "costs": [
            [1, 0],  # start and end are in the same page => no cost
            [1, 0],  # a single small range entry is enough or if not enough, no cost for this level, but only for the next level
            [1, 1],
        ],
    },
    "osdi_twem": {
        "boundary_masks": [
            0xFFFFffffFFFFfff8,
            0xFFFFffffFFFFf800,
            0xFFFFffff80000000,
        ],
        "costs": [
            [1, 0],
            [1, 1],  # for osdi twem only: medium table cannot cover small table, so there is still cost for small table when small table is not enough
            [1, 1],
        ],
    },
    "idiada": {
        "boundary_masks": [
            0xFFFFffffFFFFe000,
            0xFFFFffffFFF00000,
            0xFFFFffff00000000,
        ],
        "costs": [
            [1, 0],
            [1, 0],
            [1, 1],
        ],
    },
    "arctur": {
        "boundary_masks": [
            0xFFFFffffFFFFfe00,
            0xFFFFffffFFFE0000,
            0xFFFFffffE0000000,
        ],
        "costs": [
            [1, 0],
            [1, 0],
            [1, 1],
        ],
    },
}
resource_list3 = {
    # the following is used when every ternary table is assumed to occupy the
    # whole stage
    # "zipf": [100000, 4050, 2200, 2450],
    # "osdi_twem": [100000, 2700, 1475, 2200],
    # "idiada": [100000, 4050, 2225, 2450],
    # "arctur": [100000, 4050, 1475, 2200],

    # the new calculation is assuming ternary table can share the stage in
    # the granularity of 1/24 stage (a TCAM block), so we divide all numbers
    # above by 24
    # "zipf": [100000, 168, 91, 102],
    # "osdi_twem": [100000, 112, 61, 91],
    # "idiada": [100000, 168, 92, 100],
    # "arctur": [100000, 168, 61, 91],

    # the correct granularity is actually 1/12 stage
    "zipf": [100000, 337, 183, 204],
    "osdi_twem": [100000, 225, 122, 183],
    "idiada": [100000, 337, 185, 204],
    "arctur": [100000, 337, 122, 183],

}

# meaning of each entry in each tuple:
#     - name
#     - boundary_masks_list: including boundary_masks and costs
#     - init number of entries
#     - number of entries for each table
#     - number of stages (only used by tech with tech#3)
allStrategies = [
    # Tofino (12 stages)
    # baseline solution can have at most 6500 entries (across 8 stages)
    # the 12 here is not used (12 is only used by tech with tech#3)
    ("baseline", boundary_masks_list1, [0], resource_list1_tofino1, 12),

    # tech#1 can have at most 5850 entries (across 8 stages)
    # the 12 here is not used (12 is only used by tech with tech#3)
    ("tech#1",  boundary_masks_list2, [0], resource_list2_1_tofino1, 12),

    # # tech#2 can have at most 6500 entries (across 8 stages)
    # # the 12 here is not used (12 is only used by tech with tech#3)
    # ("tech#2",  boundary_masks_list1, [0], [6500], 12),

    # tech#1,#2 can have at most 5950 entries (across 8 stages)
    # the 12 here is not used (12 is only used by tech with tech#3)
    ("tech#1,#2",  boundary_masks_list2, [0], resource_list2_2_tofino1, 12),

    # ("tech #1, #3", boundary_masks_list3, counts3),  # seems not possible because #3 cannot do two addresses in one table => #3 needs #2

    # tech#1,#2,#3 will have four tables:
    #     - single-page table can be arbitrarily large (no TCAM is used),
    #       so 10^5
    #     - small-range table can have 4050 entries per 2 stages (one for
    #       startAddr, one for endAddr)
    #     - medium-range table can have 2200 entries per 2 stages
    #     - large-range table can have 2450 entries per 2 stages
    ("tech#1,#2,#3", boundary_masks_list3, [0, 0, 0, 0], resource_list3, 12),

    # Tofino2 (24 stages)
    ("baseline", boundary_masks_list1, [0], resource_list1_tofino2, 20),
    ("tech#1",  boundary_masks_list2, [0], resource_list2_1_tofino2, 20),
    # ("tech#2",  boundary_masks_list1, [0], [16250], 20),
    ("tech#1,#2",  boundary_masks_list2, [0], resource_list2_2_tofino2, 20),
    ("tech#1,#2,#3", boundary_masks_list3, [0, 0, 0, 0], resource_list3, 20),

    # # RMT (32 stages)
    # # ("baseline", boundary_masks_list1, [0], [22750], 32),
    # ("tech#1",  boundary_masks_list2, [0], [20475], 32),
    # # ("tech#2",  boundary_masks_list1, [0], [22750], 32),
    # ("tech#1,#2",  boundary_masks_list2, [0], [20825], 32),
    # # ("tech #1, #3", boundary_masks_list3, counts3),  # seems not possible because #3 cannot do two addresses in one table => #3 needs #2
    # # ("tech#1,#2,#3", boundary_masks_list3, [0, 0, 0, 0], [100000, 4050, 2200, 2450], 32),
]


def count_entries_boundary(start, end, boundary_masks, costs, level):
    """Return the number of entries for each level (a list)"""
    if start > end:
        return [0] * (len(boundary_masks)-level + 1)
    if level >= len(boundary_masks):
        # print ("%012x %012x" % (start, end))
        return [1]
    masked_start = (start & boundary_masks[level])
    masked_end = (end & boundary_masks[level])
    inverse_mask = ((~boundary_masks[level]) & 0xFFFFffffFFFFffff)
    # print ("%012x" % inverse_mask)
    if masked_start == masked_end:
        # print ("%012x %012x" % (start, end))
        return [costs[level][0]] + [0] * (len(boundary_masks)-level)
    else:
        thisLevelCost = 0
        nextStart = start
        nextEnd = end
        if start != masked_start and costs[level][1] != 0:
            thisLevelCost += costs[level][1]
            nextStart = masked_start + inverse_mask + 1
            # print ("%012x %012x" % (start, nextStart - 1))
        if end != masked_end + inverse_mask and costs[level][1] != 0:
            thisLevelCost += costs[level][1]
            nextEnd = masked_end - 1
            # print ("%012x %012x" % (nextEnd + 1, end))
        return [thisLevelCost] + count_entries_boundary(nextStart, nextEnd, boundary_masks, costs, level+1)

def transform_group_ranges(ranges):
    """Return the merged ranges (only for tech with tech #2)"""
    combinedRanges = ranges[0] + ranges[1] + ranges[2]
    boundaries = []
    for rType in ranges:
        for r in rType:
            boundaries += r
    boundaries.sort()

    combinedRanges.sort(key = lambda x: x[0])

    # print(combinedRanges)

    # merge all range to get valid
    curMin = -1
    curMax = -1
    j = 1
    prev = boundaries[0]
    ret = []
    for i in range(len(combinedRanges)):
        objRange = combinedRanges[i]
        if objRange[0] > curMax: # consecutive ranges should be merged
            if i != 0:
                while j < len(boundaries) and boundaries[j] <= curMax:
                    if prev != boundaries[j]:
                        ret.append([prev, boundaries[j]])
                        prev = boundaries[j]
                    j += 1
            curMin = objRange[0]
            curMax = objRange[1]
            prev = curMin
        else:
            if objRange[1] > curMax:
                curMax = objRange[1]
    while curMax != -1 and j < len(boundaries) and boundaries[j] <= curMax:
        if prev != boundaries[j]:
            ret.append([prev, boundaries[j]])
            prev = boundaries[j]
        j += 1

    # print(ret)
    return ret

def test_transform_group_ranges():
    ranges = policy_spec.test_gen_ranges()
    transform_group_ranges(ranges)

def count_entries(strategy, boundary_masks, costs, inputRanges):
    """Return the number of entries for each table (a list)
    One thing is about tech#3:
    For baseline, tech#1, tech#1,#2, there is only one table, so the return is
    a single-item list. That's why 'if "#3" not in name: cur = [sum(cur)]'.
    For tech with tech#3, we will return a list of values, each for one table.

    Another thing is about tech#2:
    For baseline, tech#1, we calculate the number of entries by calcuating the
    product (e.g., "x * (x+1) / 2".
    For tech with tech#2, we calculate the number of entries without
    multiplication, because the grouping technique.
    """
    (name, _, counts, _, stages) = strategy
    if "#2" in name:
        ranges = [transform_group_ranges(inputRanges)]
    else:
        ranges = inputRanges
    for rType in ranges:
        for r in rType:
            cur = count_entries_boundary(int(r[0]), int(r[1]-1), boundary_masks, costs, 0)
            # print ("%012x %012x" % (int(r[0]), int(r[1]-1)))
            # print (cur)
            if "#3" not in name:
                cur = [sum(cur)]
            if "#2" not in name:
                cur = map(lambda x: int(x * (x+1) / 2), cur)
            counts = list(map(operator.add, counts, cur))
    # print ("Strategy %s" % name)
    # print (counts)
    return counts

def violateConstraint(n, N):
    for i in range(len(N)):
        if n[i] > N[i]:
            return True
    return False

def select_boundary_masks_from_a(boundary_masks_list, resource_list, a):
    if a >= 1:
        selected = 'zipf'
    elif a == -1:
        selected = 'osdi_twem'
    elif a == -2:
        selected = 'idiada'
    elif a == -3:
        selected = 'arctur'
    else:
        print("Shouldn't happen")
        selected = ''
    return (
        boundary_masks_list[selected]['boundary_masks'],
        boundary_masks_list[selected]['costs'],
        resource_list[selected]
    )

def main(args):

    TRIALS = 1
    # (minM, maxM, incM) = (100, 1000000, 100) # the ranges when using linear inc
    (minM, maxM, incM) = (2, 8, 0.1) # the ranges when using logspace inc
    a = args.a
    rw = args.rw
    if a >= 1:
        maxObjSize = 100000000 # pages
        ACL_UNIT = 4096 # bytes => 4KB (1 page)
        sampler = policy_spec.ZipfSampler(a, maxObjSize)
    elif a == -1:
        ACL_UNIT = 8 # bytes
        sampler = policy_spec.OsdiTwemSampler(ACL_UNIT)
    elif a == -2:
        ACL_UNIT = 8192 # bytes
        sampler = policy_spec.IdiadaSampler(ACL_UNIT)
    elif a == -3:
        ACL_UNIT = 512 # bytes
        sampler = policy_spec.ArcturSampler(ACL_UNIT)
    else:
        print("Wrong argument on a: >1 to use Zipf, -1 to use osdi_twem,")
        print("    -2 to use idiada, -3 to use arctur")
        return

    addrSpace = [0, 2**48/ACL_UNIT] # whole address space

    try:
        with open("output/revision-granularity12-fixTofino2-afterMajRev-a%2f-rw%d.txt"%(a, rw), "w") as fo:
            # fo.write ("a\trw\ts\tm\n")
            fo.write ("%f\t%d\t" % (a, rw))
            for strategy in allStrategies:
                (name, boundary_masks_list, counts, resource_list, stages) = strategy
                boundary_masks, costs, resource = select_boundary_masks_from_a(
                    boundary_masks_list, resource_list, a)
                avgM = 0
                if "#3" in name:
                    orig = resource
                    newRes = [0,0,0]
                    newResInt = [0,0,0]
                    for i in range(2):
                        # test once to get ratio
                        # for m in range(minM, maxM, incM): # linear inc
                        found_optimal = False
                        for m in np.logspace(minM, maxM, num=int((maxM-minM)/incM+1), dtype='int'): # logspace inc
                            ranges = policy_spec.gen_ranges(sampler, m, ACL_UNIT, addrSpace, rw)
                            n = count_entries(strategy, boundary_masks, costs, ranges)
                            print(m, "/", 10**maxM, ":", n)
                            if violateConstraint(n, resource):
                                break
                            if sum(n) < m and sum(n) < 1000: # the current setup can accept any number of entries
                                found_optimal = True
                                break
                        if not found_optimal:
                            # allocate resource accordingly
                            p = (stages-4) / 2 * 12 / (float(n[1])/orig[1]+float(n[2])/orig[2]+float(n[3])/orig[3])
                            newRes = [n[i]*p/orig[i] for i in range(1, 4)]
                            minRes = [1, 1, 1]
                            newResInt = [max(minRes[i], int(newRes[i])) for i in range(len(newRes))]
                            # print(newResInt)

                            while sum(newResInt) > (stages-4)/2*12:
                                prob = []
                                for i in range(0, 3):
                                    if newResInt[i] > minRes[i]:
                                        prob.append(newResInt[i] - minRes[i])
                                    else:
                                        prob.append(0)
                                sumProb = sum(prob)
                                prob = [x / sumProb for x in prob]
                                selected = np.random.choice(range(0,3), p=prob)
                                # print(prob, selected)
                                # most = np.argmax(newResInt)
                                newResInt[selected] -= 1

                            prob = [x / sum(newResInt) for x in newResInt]
                            while sum(newResInt) < (stages-4)/2*12:
                                selected = np.random.choice(range(0,3), p=prob)
                                # least = np.argmax(list(map(operator.sub, newRes, newResInt)))
                                newResInt[selected] += 1

                            resource = [resource[0]] + list(map(operator.mul, newResInt, orig[1:]))
                            print (n, newRes, newResInt, resource)
                        else:
                            print ("found optimal",
                                newRes,
                                newResInt,
                                resource)
                for i in range(TRIALS):
                    found_optimal = 0
                    # for m in range(minM, maxM, incM): # linear inc
                    for m in np.logspace(minM, maxM, num=int((maxM-minM)/incM+1), dtype='int'): # logspace inc
                        ranges = policy_spec.gen_ranges(sampler, m, ACL_UNIT, addrSpace, rw)
                        n = count_entries(strategy, boundary_masks, costs, ranges)
                        if violateConstraint(n, resource):
                            # print (n)
                            # avgM += m - incM # linear inc
                            avgM += int(m / (10**incM)) # logspace inc
                            break
                        if sum(n) < m and sum(n) < 1000: # the current setup can accept any number of entries
                            found_optimal += 1
                            break
                if found_optimal < TRIALS:
                    avgM = float(avgM) / (TRIALS-found_optimal)
                else:
                    avgM = 10**maxM
                if "#3" in name:
                    fo.write ("%f\t%d\t%s/%s\t" % (avgM, found_optimal, str(n), str(resource)))
                else:
                    fo.write ("%f\t%d\t" % (avgM, found_optimal))
            fo.write("\n")
            fo.close()
    except IOError as e:
        print ("error opening file (%s)" % e)

def test_count_entries_boundary():
    r1 = 0x1111222200001000
    r2 = 0x11112223FFFFFFFF
    r1 = 0x1111222233330000
    r2 = 0x111122223333FFFF
    r1 = 0x1111222233300000
    r2 = 0x111122223333FFFF
    r1 = 0x1111222233300000
    r2 = 0x11112222333FFFFF
    r1 = 0x1111222233000000
    r2 = 0x1111222233FFFFFF
    r1 = 0x1111222233000000
    r2 = 0x111122223FFFEFFF
    r1 = 0x1111222233330000
    r2 = 0x111122230001FFFF
    r1 = 0x1111222233330000
    r2 = 0x111122230000EFFF
    r1 = 0x1111222233330000
    r2 = 0x111122240000FFFF

    print (count_entries_boundary(r1, r2, allStrategies[0][0], allStrategies[0][1], 0))
    print (count_entries_boundary(r1, r2, allStrategies[1][0], allStrategies[1][1], 0))
    print (count_entries_boundary(r1, r2, allStrategies[2][0], allStrategies[2][1], 0))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = 'Calculate ACL scalability')
    parser.add_argument('-a', dest='a', required=True, type=float, help='skewness')
    parser.add_argument('-r', dest='rw', required=True, type=int, help='read ratio, 40 means 40%')
    args = parser.parse_args()
    main(args)
    # test_transform_group_ranges()
