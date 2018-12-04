class Solution:
    """
    @param A: an integer array
    @return: nothing
    """
    def sortIntegers2(self, A):
        # write your code here
        if len(A) <= 0:
            return []
        return Solution.subsort(1, A)
        
    def subsort(self, arr):
        if len(arr) <= 1:
            return arr
        if len(arr) == 2:
            if(arr[0] > arr[1]):
                return [arr[1], arr[0]]
            else:
                return arr
        else:
            size = len(arr)
            return Solution.merge(1, Solution.subsort(1, arr[:size//2]), Solution.subsort(1, arr[size//2:]))

    def merge(self, arr1, arr2):
        res = []
        if len(arr1) == 0:
            return arr2
        if len(arr2) == 0:
            return arr1
        i, j = 0, 0
        while i < len(arr1) and j < len(arr2):
            if arr1[i] < arr2[j]:
                res.append(arr1[i])
                i += 1
            else :
                res.append(arr2[j])
                j += 1
        if i == len(arr1):
            while j < len(arr2):
                res.append(arr2[j])
                j += 1
        if j == len(arr2):
            while i < len(arr1):
                res.append(arr1[i])
                i += 1
        return res

print(Solution.sortIntegers2(1, [3, 2, 1, 4, 5, 7, 6, 8]))
print(Solution.sortIntegers2(1, []))
print(Solution.sortIntegers2(1, [3, 2, 1, 4, 5, 7, 6]))
print(Solution.sortIntegers2(1, [3,2,1,4,5]))
