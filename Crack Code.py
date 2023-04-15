from multiprocessing import Pool
import string
import numpy as np
import _md5


class ExpectedResults:
    def __init__(self, expectedSalt, expectedHash):
        self.expectedSalt = expectedSalt
        self.expectedHash = expectedHash


# function to read and retrieve team 4 hash,salt
def read():
    # team 4's salt and hash to be used by the rest of the
    # program
    expected = ExpectedResults(None, None)

    # open file and retrieve info for team 4
    f = open("etc_shadow", "r", encoding='utf-8')
    lines = f.readlines()
    team = lines[4]

    # split by delimiter to get team salt and hash
    team = team.split('$')

    # get team4 salt
    expected.expectedSalt = team[2]
    # print("salt is: " + salt)

    # get team4 hash
    teamHash = team[3].split(':')
    expected.expectedHash = teamHash[0]

    # close file
    f.close()
    return expected
# end of read function


# Mainly a wrapper over recursive function
# getKCombinationsRecursive()
def getKCombinations(sets, k):
    combinationsList = []
    n = len(sets)
    return getKCombinationsRecursive(sets, "", n, k, combinationsList)


# The main recursive method
def getKCombinationsRecursive(sets, password, n, k, combinationsList):
    # Base case: k is 0,
    if (k == 0):
        combinationsList.append(password)
        return

    # get all combinations of k lowercase letters
    for i in range(n):
        # Next character of input added
        # ex) aaaaaa -> aaaaab -> aaaaac etc.
        newPassword = password + sets[i]

        # decrease k because a new character is added
        # make recursive call
        getKCombinationsRecursive(sets, newPassword, n, k - 1, combinationsList)
    return combinationsList


ascii64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
# JavaScript Functions
def to64(a, b):
    newString = ''
    b = b - 1
    while (b >= 0):
        newString += ascii64[a & 0x3f]
        a >>= 6
        b = b - 1
    return newString

def convert_triplet(str, idx0, idx1, idx2):
    v = (str[idx0] << 16) | (str[idx1] << 8) | (str[idx2])
    return to64(v, 4)

def convert_single(str, idx0):
    v = str[idx0]
    return to64(v, 2)


def checkHashMatch(passwordSet, mainSalt, mainHash):
    # get the pid
    magic = "$1$"
    salt = mainSalt
    teamHash = mainHash

    for password in passwordSet:
        print(password)
        # calculate Alternative Sum
        alternativeStr = (password + salt + password)
        alternativeSum = _md5.md5(alternativeStr.encode("latin1"))

        # calculate Intermediate Sum
        intermediateStr = password + magic + salt

        # add 6 bytes of alternativeStr
        temp = (alternativeSum.digest())[:6]
        intermediateStr += temp.decode("latin1")

        # high low stuff
        i = len(password)
        while (i != 0):
            if (i & 1):
                intermediateStr += "\0"
            else:
                intermediateStr += password[0]
            i = i >> 1
        # hashed intermediate_0
        intermediateSum = _md5.md5(intermediateStr.encode("latin1"))

        # ////////////////////////////////////////////////////////////////////////////////////////// #
        # hash guess 1000 times
        for i in range(1000):
            hashKey = ""
            if ((i % 2) == 0):
                hashKey += intermediateSum.digest().decode("latin1")
            if ((i % 2) != 0):
                hashKey += password
            if ((i % 3) != 0):
                hashKey += salt
            if ((i % 7) != 0):
                hashKey += password
            if ((i % 2) == 0):
                hashKey += password
            if ((i % 2) != 0):
                hashKey += intermediateSum.digest().decode("latin1")
            intermediateSum = _md5.md5(hashKey.encode("latin1"))
        # separating each byte of the hash
        final_sum = intermediateSum.digest()

        # ////////////////////////////////////////////////////////////////////////////////////////// #

        finalHash = ""
        finalHash += convert_triplet(final_sum, 0, 6, 12) + convert_triplet(final_sum, 1, 7, 13) + \
                  convert_triplet(final_sum, 2, 8, 14) + convert_triplet(final_sum, 3, 9, 15) + \
                  convert_triplet(final_sum, 4, 10, 5) + convert_single(final_sum, 11)

        if (finalHash == teamHash):
            print("FOUND IT", flush=True)


# Driver Code
if __name__ == "__main__":
    # read file and get hash, salt
    print("reading file...\n")
    results = read()
    print("done reading file\n")

    # get all combinations
    print("getting combinations...\n")
    set1 = list(string.ascii_lowercase)
    k = 6
    combinations = getKCombinations(set1, k)
    print("done getting combinations\n")

    # get list of combinations in chunks of 10
    print("splitting up combinations...\n")
    list_chunked = np.array_split(combinations, 30)
    print("finished splitting list of combinations\n")

    # run processes
    print("multiprocessing...\n")
    with Pool() as pool:
        # inputs
        input1 = [(list_chunked[0], results.expectedSalt, results.expectedHash)]
        input2 = [(list_chunked[1], results.expectedSalt, results.expectedHash)]
        input3 = [(list_chunked[2], results.expectedSalt, results.expectedHash)]
        input4 = [(list_chunked[3], results.expectedSalt, results.expectedHash)]
        input5 = [(list_chunked[4], results.expectedSalt, results.expectedHash)]
        input6 = [(list_chunked[5], results.expectedSalt, results.expectedHash)]
        input7 = [(list_chunked[6], results.expectedSalt, results.expectedHash)]
        input8 = [(list_chunked[7], results.expectedSalt, results.expectedHash)]
        input9 = [(list_chunked[8], results.expectedSalt, results.expectedHash)]
        input10 = [(list_chunked[9], results.expectedSalt, results.expectedHash)]
        input11 = [(list_chunked[10], results.expectedSalt, results.expectedHash)]
        input12 = [(list_chunked[11], results.expectedSalt, results.expectedHash)]
        input13 = [(list_chunked[12], results.expectedSalt, results.expectedHash)]
        input14 = [(list_chunked[13], results.expectedSalt, results.expectedHash)]
        input15 = [(list_chunked[14], results.expectedSalt, results.expectedHash)]
        input16 = [(list_chunked[15], results.expectedSalt, results.expectedHash)]
        input17 = [(list_chunked[16], results.expectedSalt, results.expectedHash)]
        input18 = [(list_chunked[17], results.expectedSalt, results.expectedHash)]
        input19 = [(list_chunked[18], results.expectedSalt, results.expectedHash)]
        input20 = [(list_chunked[19], results.expectedSalt, results.expectedHash)]
        input21 = [(list_chunked[20], results.expectedSalt, results.expectedHash)]
        input22 = [(list_chunked[21], results.expectedSalt, results.expectedHash)]
        input23 = [(list_chunked[23], results.expectedSalt, results.expectedHash)]
        input24 = [(list_chunked[24], results.expectedSalt, results.expectedHash)]
        input25 = [(list_chunked[25], results.expectedSalt, results.expectedHash)]
        input26 = [(list_chunked[26], results.expectedSalt, results.expectedHash)]
        input27 = [(list_chunked[27], results.expectedSalt, results.expectedHash)]
        input28 = [(list_chunked[28], results.expectedSalt, results.expectedHash)]
        input29 = [(list_chunked[29], results.expectedSalt, results.expectedHash)]
        # multiprocessing pool object
        for result in pool.starmap(checkHashMatch, input17, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input29, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input3, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input7, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input5, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input6, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input10, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input11, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input13, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input15, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input14, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input16, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input1, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input2, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input20, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input24, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input22, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input21, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input26, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input25, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input4, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input23, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input18, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input19, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input28, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input27, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input12, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input9, chunksize=100):
            print(f'Got result: {result}', flush=True)
        for result in pool.starmap(checkHashMatch, input8, chunksize=100):
            print(f'Got result: {result}', flush=True)
    print("\nfinished\n")
